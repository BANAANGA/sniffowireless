"""Walk survey: walk around with a sensor, tap where you stand on the floor plan, and get heatmaps of the coverage.

The sensor you carry can be any of them: the phone with its USB adapter (the Android app as a remote sensor), a laptop running
sniffowireless, or a remote sensor on a trolley. While a survey is open, every access point that sensor hears is noted with its
signal. When you tap a spot on the floor plan (from any browser, the phone's own included), the readings of the last few seconds
become a survey point: per access point, the median signal. Keep still for those seconds, so a sensor that hops channels has been
round them all.

The page draws, from the points, how strong your networks are everywhere (the best access point, per band or one access point),
and where several of your access points are heard well at once (good for roaming, but on one channel they share the air).
"""
import json
import math
import statistics
import threading
import time
from collections import deque

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .auth import current_user, require_admin

SCHEMA = """
CREATE TABLE IF NOT EXISTS walk_sessions(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, sensor TEXT, created REAL, closed REAL);
CREATE TABLE IF NOT EXISTS walk_points(id INTEGER PRIMARY KEY AUTOINCREMENT, session INTEGER NOT NULL, ts REAL, x REAL, y REAL,
  readings TEXT);
CREATE INDEX IF NOT EXISTS idx_walk_points ON walk_points(session);
"""
WINDOW = 10          # seconds of readings a point is made of
KEEP = 60            # seconds of readings kept per access point while a survey is open
MAX_APS = 3000


class WalkCollector:
    """Store plugin: while a survey is open on a sensor, keeps every access point reading of that sensor for a minute."""

    def __init__(self, ctx):
        self.ctx = ctx
        ctx.store.conn.executescript(SCHEMA)
        self.lock = threading.Lock()
        self.open = {}      # sensor -> session id
        self.buf = {}       # sensor -> {bssid: deque[(ts, rssi)]}

    def observe(self, store, o, dev):
        if o.get("t") != "wifi_ap" or o.get("rssi") is None:
            return
        sensor = o.get("sensor") or "local"
        if sensor not in self.open:
            return
        with self.lock:
            b = self.buf.setdefault(sensor, {})
            q = b.get(o["mac"])
            if q is None:
                if len(b) >= MAX_APS:
                    return
                q = b[o["mac"]] = deque(maxlen=200)
            q.append((o["ts"], int(o["rssi"])))

    def readings(self, sensor, seconds=WINDOW, now=None):
        """Per access point, the median signal the sensor heard in the last `seconds`."""
        now = now or time.time()
        out = {}
        with self.lock:
            for mac, q in (self.buf.get(sensor) or {}).items():
                while q and q[0][0] < now - KEEP:
                    q.popleft()
                vals = [r for t, r in q if t >= now - seconds]
                if vals:
                    out[mac] = round(statistics.median(vals))
        return out

    def start(self, sensor, sid):
        with self.lock:
            self.open[sensor] = sid
            self.buf[sensor] = {}

    def stop(self, sid):
        with self.lock:
            for s, x in list(self.open.items()):
                if x == sid:
                    del self.open[s]
                    self.buf.pop(s, None)


def demo_readings(ctx, x, y):
    """The demo's sensors don't move: make up what a sensor at (x, y) would hear, from where the demo access points stand
    (log-distance path loss, a 20 m wide floor, walls by room)."""
    from .demo import APS, FIXED_ROOMS, SENSORS
    rooms = {room: (sx, sy) for _, _, room, sx, sy in SENSORS}
    out = {}
    for mac, ssid, ch, enc, base, vendor in APS:
        room = FIXED_ROOMS.get(mac)
        if room in rooms:
            ax, ay = rooms[room]
            d = max(0.5, math.hypot((x - ax) * 20, (y - ay) * 13))
            out[mac] = round(-32 - 30 * math.log10(d) - (6 if (x - ax) * (y - ay) < -0.02 else 0) - (4 if isinstance(ch, tuple) or ch > 14 else 0))
        else:   # the neighbours: about as loud everywhere
            out[mac] = base + int(((x * 7 + y * 3) % 1) * 4)
    return {k: v for k, v in out.items() if v >= -92}


class StartBody(BaseModel):
    name: str = Field("Survey", min_length=1, max_length=60)
    sensor: str = Field("local", max_length=64)


class PointBody(BaseModel):
    x: float = Field(ge=0, le=1)
    y: float = Field(ge=0, le=1)
    seconds: int = Field(WINDOW, ge=3, le=30)


def routes(ctx):
    r = APIRouter()
    col = ctx.walk

    def session(sid):
        s = ctx.one("SELECT * FROM walk_sessions WHERE id=?", (sid,))
        if not s:
            raise HTTPException(404, "No such survey")
        return s

    def ensure_demo():
        """The demo gets a survey to look at: a walk through the three rooms."""
        if not ctx.cfg.demo or ctx.one("SELECT id FROM walk_sessions LIMIT 1"):
            return
        with ctx.wdb() as w:
            cur = w.execute("INSERT INTO walk_sessions(name, sensor, created, closed) VALUES('Ground floor', 'local', ?, ?)", (time.time() - 3600,) * 2)
            sid = cur.lastrowid
            pts = [(0.06 + 0.11 * i, 0.08 + 0.14 * j) for i in range(9) for j in range(7)]
            w.executemany("INSERT INTO walk_points(session, ts, x, y, readings) VALUES(?, ?, ?, ?, ?)",
                          [(sid, time.time() - 3600 + k * 20, x, y, json.dumps(demo_readings(ctx, x, y))) for k, (x, y) in enumerate(pts)])

    @r.get("/api/walk")
    def surveys(_=Depends(current_user)):
        ensure_demo()
        rows = ctx.rows("SELECT s.*, (SELECT COUNT(*) FROM walk_points p WHERE p.session = s.id) points FROM walk_sessions s ORDER BY created DESC")
        sensors = [{"id": "local", "name": "This server"}] + [{"id": x["id"], "name": x["name"] or x["id"], "online": bool(x["last_seen"] and time.time() - x["last_seen"] < 120)}
                                                              for x in ctx.rows("SELECT id, name, last_seen FROM sensors WHERE id != 'local' ORDER BY name")]
        return {"surveys": rows, "sensors": sensors, "open": {str(v): k for k, v in col.open.items()}, "window": WINDOW,
                "floorplan": ctx.settings.get("floorplan")}

    @r.post("/api/walk")
    def start(body: StartBody, _=Depends(require_admin)):
        known = {"local"} | {x["id"] for x in ctx.rows("SELECT id FROM sensors")}
        if body.sensor not in known:
            raise HTTPException(404, "No such sensor")
        with ctx.wdb() as w:
            sid = w.execute("INSERT INTO walk_sessions(name, sensor, created) VALUES(?, ?, ?)", (body.name.strip(), body.sensor, time.time())).lastrowid
        col.start(body.sensor, sid)
        return {"id": sid}

    @r.get("/api/walk/{sid}")
    def survey(sid: int, _=Depends(current_user)):
        """The points with their readings, and what the access points in them are (network, band, channel, mine)."""
        s = session(sid)
        pts = []
        for p in ctx.rows("SELECT id, ts, x, y, readings FROM walk_points WHERE session=? ORDER BY id", (sid,)):
            p["readings"] = json.loads(p["readings"] or "{}")
            pts.append(p)
        macs = sorted({m for p in pts for m in p["readings"]})
        n = ctx.settings.get("networks")
        trusted = set(n["trusted_bssids"])
        aps = {}
        if macs:
            for a in ctx.rows(f"SELECT mac, ssid, band, channel FROM devices WHERE mac IN ({','.join('?' * len(macs))})", macs):
                a["mine"] = a["ssid"] in n["ssids"] and (not trusted or a["mac"] in trusted)
                aps[a["mac"]] = a
        return {**s, "open": col.open.get(s["sensor"]) == sid, "points": pts, "aps": aps}

    @r.get("/api/walk/{sid}/now")
    def now_heard(sid: int, seconds: int = WINDOW, _=Depends(require_admin)):
        """What a point here would hold right now: how many access points, and the strongest of mine."""
        s = session(sid)
        rd = demo_readings(ctx, 0.5, 0.5) if ctx.cfg.demo else col.readings(s["sensor"], max(3, min(seconds, 30)))
        n = ctx.settings.get("networks")
        mine = {a["mac"] for a in ctx.rows(f"SELECT mac FROM devices WHERE kind='ap' AND ssid IN ({','.join('?' * len(n['ssids']))})", n["ssids"])} if n["ssids"] else set()
        best = max((v for k, v in rd.items() if k in mine), default=None)
        return {"aps": len(rd), "best_mine": best, "open": col.open.get(s["sensor"]) == sid}

    @r.post("/api/walk/{sid}/point")
    def point(sid: int, body: PointBody, _=Depends(require_admin)):
        s = session(sid)
        if col.open.get(s["sensor"]) != sid:
            raise HTTPException(409, "This survey is closed")
        rd = demo_readings(ctx, body.x, body.y) if ctx.cfg.demo else col.readings(s["sensor"], body.seconds)
        if not rd:
            raise HTTPException(409, "The sensor heard no access point in the last seconds: wait a moment and tap again")
        with ctx.wdb() as w:
            pid = w.execute("INSERT INTO walk_points(session, ts, x, y, readings) VALUES(?, ?, ?, ?, ?)",
                            (sid, time.time(), body.x, body.y, json.dumps(rd))).lastrowid
        return {"id": pid, "aps": len(rd)}

    @r.post("/api/walk/{sid}/resume")
    def resume(sid: int, _=Depends(require_admin)):
        """Go on with a survey (after a restart, or another day): its sensor collects again."""
        s = session(sid)
        col.start(s["sensor"], sid)
        with ctx.wdb() as w:
            w.execute("UPDATE walk_sessions SET closed=NULL WHERE id=?", (sid,))
        return {"ok": True}

    @r.delete("/api/walk/{sid}/point/{pid}")
    def undo(sid: int, pid: int, _=Depends(require_admin)):
        with ctx.wdb() as w:
            w.execute("DELETE FROM walk_points WHERE id=? AND session=?", (pid, sid))
        return {"ok": True}

    @r.post("/api/walk/{sid}/stop")
    def stop(sid: int, _=Depends(require_admin)):
        session(sid)
        col.stop(sid)
        with ctx.wdb() as w:
            w.execute("UPDATE walk_sessions SET closed=? WHERE id=? AND closed IS NULL", (time.time(), sid))
        return {"ok": True}

    @r.delete("/api/walk/{sid}")
    def delete(sid: int, _=Depends(require_admin)):
        col.stop(sid)
        with ctx.wdb() as w:
            w.execute("DELETE FROM walk_points WHERE session=?", (sid,))
            w.execute("DELETE FROM walk_sessions WHERE id=?", (sid,))
        return {"ok": True}

    return r
