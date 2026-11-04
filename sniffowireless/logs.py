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

    @r.get("/api/logs")
    def snapshot(after: int = 0, limit: int = 1000, _=Depends(require_admin)):
        return {"items": HANDLER.since(after, max(1, min(limit, CAPACITY))),
                "level": logging.getLevelName(logging.getLogger().level), "capacity": CAPACITY}

    @r.get("/api/logs/stream")
    async def stream(request: Request, after: int = 0, _=Depends(require_admin)):
        async def gen():
            last = after
            idle = 0.0
            yield "retry: 3000\n\n"
            while True:
                if await request.is_disconnected():
                    break
                items = HANDLER.since(last, 500)
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
