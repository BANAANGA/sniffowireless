"""Live application logs: an in-memory ring buffer fed by a logging handler, exposed to admins as a
snapshot (/api/logs) and as a Server-Sent Events stream (/api/logs/stream). The log level can be changed
at runtime."""
import asyncio
import collections
import json
import logging
import re
import threading
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .auth import require_admin

CAPACITY = 5000
LEVELS = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
# Never show secrets in the UI, even if they were logged (the first-run setup code, tokens).
REDACT = [(re.compile(r"(setup code:\s*)\S+", re.I), r"\1••••"), (re.compile(r"\bsniffowireless_[A-Za-z0-9_-]{20,}"), "sniffowireless_••••")]


class RingHandler(logging.Handler):
    def __init__(self, capacity=CAPACITY):
        super().__init__(level=logging.DEBUG)
        self.buf = collections.deque(maxlen=capacity)
        self.buf_lock = threading.Lock()  # not `self.lock`: logging.Handler holds that one around emit()
        self.seq = 0

    def emit(self, record):
        try:
            msg = record.getMessage()
            if record.exc_info:
                msg += "\n" + logging.Formatter().formatException(record.exc_info)
            for rx, repl in REDACT:
                msg = rx.sub(repl, msg)
            with self.buf_lock:
                self.seq += 1
                self.buf.append({"id": self.seq, "ts": record.created, "level": record.levelname,
                                 "logger": record.name, "msg": msg[:4000], "thread": record.threadName})
        except Exception:
            self.handleError(record)

    def since(self, after=0, limit=1000):
        with self.buf_lock:
            items = [r for r in self.buf if r["id"] > after]
        return items[-limit:]


HANDLER = RingHandler()

REMOTE_CAPACITY = 2000   # lines kept per remote sensor
REMOTE_BATCH = 200       # lines a sensor may send with one upload


class RemoteLogs:
    """The recent log lines of each remote sensor, which sends the new ones with every upload. Memory only, like the server's own buffer.
    Lines get this server's own increasing id (what the live stream resumes from); a sensor that restarts starts counting from 1 again,
    so its `epoch` tells a new run from a retried upload (a batch whose answer got lost is not added twice)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.by = {}

    def add(self, sid, epoch, lines):
        with self.lock:
            s = self.by.setdefault(sid, {"buf": collections.deque(maxlen=REMOTE_CAPACITY), "seq": 0, "epoch": None, "last": 0})
            if epoch != s["epoch"]:
                s["epoch"], s["last"] = epoch, 0
            for ln in lines[-REMOTE_BATCH:]:
                if ln["src_id"] and ln["src_id"] <= s["last"]:
                    continue
                msg = ln["msg"]
                for rx, repl in REDACT:  # the sensor redacts too; this server does not rely on it
                    msg = rx.sub(repl, msg)
                s["seq"] += 1
                s["last"] = max(s["last"], ln["src_id"])
                s["buf"].append({"id": s["seq"], "ts": ln["ts"], "level": ln["level"], "logger": ln["logger"], "msg": msg,
                                 "thread": ln["thread"]})

    def since(self, sid, after=0, limit=1000):
        with self.lock:
            s = self.by.get(sid)
            items = [r for r in s["buf"] if r["id"] > after] if s else []
        return items[-limit:]

    def count(self, sid):
        with self.lock:
            s = self.by.get(sid)
            return len(s["buf"]) if s else 0

    def drop(self, sid):
        with self.lock:
            self.by.pop(sid, None)


REMOTE = RemoteLogs()


def install(level):
    """Attach the ring buffer to the root logger (call once, after logging.basicConfig)."""
    root = logging.getLogger()
    if HANDLER not in root.handlers:
        root.addHandler(HANDLER)
    root.setLevel(level)
    for noisy in ("uvicorn.access",):  # request lines would flood the view (and the stream itself causes them)
        logging.getLogger(noisy).propagate = False


class LevelBody(BaseModel):
    level: str = Field(pattern="^(DEBUG|INFO|WARNING|ERROR)$")


def routes(ctx):
    r = APIRouter()

    def sensor_tabs():
        now = time.time()
        return [{"id": x["id"], "name": x["name"], "online": (x["last_seen"] or 0) > now - 90, "lines": REMOTE.count(x["id"])}
                for x in ctx.rows("SELECT id, name, last_seen FROM sensors WHERE id != 'local' ORDER BY name")]

    def source(sensor):
        """The buffer a request asks for: this server's own (empty `sensor`) or a remote sensor's."""
        if not sensor or sensor == "local":
            return HANDLER.since
        if not ctx.one("SELECT 1 FROM sensors WHERE id=?", (sensor,)):
            raise HTTPException(404, "No such sensor")
        return lambda after, limit: REMOTE.since(sensor, after, limit)

    @r.get("/api/logs")
    def snapshot(after: int = 0, limit: int = 1000, sensor: str = "", _=Depends(require_admin)):
        since = source(sensor)
        remote = bool(sensor and sensor != "local")
        return {"items": since(after, max(1, min(limit, CAPACITY))),
                "level": None if remote else logging.getLevelName(logging.getLogger().level),
                "capacity": REMOTE_CAPACITY if remote else CAPACITY, "sensors": sensor_tabs(), "sensor": sensor if remote else ""}

    @r.get("/api/logs/stream")
    async def stream(request: Request, after: int = 0, sensor: str = "", _=Depends(require_admin)):
        since = source(sensor)

        async def gen():
            last = after
            idle = 0.0
            yield "retry: 3000\n\n"
            while True:
                if await request.is_disconnected():
                    break
                items = since(last, 500)
                if items:
                    last = items[-1]["id"]
                    yield f"id: {last}\nevent: logs\ndata: {json.dumps(items)}\n\n"
                    idle = 0.0
                else:
                    idle += 0.5
                    if idle >= 15:  # keep proxies from closing an idle connection
                        yield f": keepalive {int(time.time())}\n\n"
                        idle = 0.0
                await asyncio.sleep(0.5)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    @r.put("/api/logs/level")
    def set_level(body: LevelBody, me=Depends(require_admin)):
        logging.getLogger().setLevel(LEVELS[body.level])
        logging.getLogger("sniffowireless").warning("Log level set to %s by %s", body.level, me.username)
        return {"level": body.level}

    return r
