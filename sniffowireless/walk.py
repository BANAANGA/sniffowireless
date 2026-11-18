"""Walk survey: walk around with a sensor, tap where you stand on the floor plan, and get heatmaps of the coverage.

The sensor you carry can be any of them: the phone with its USB adapter (the Android app as a remote sensor), a laptop running
sniffowireless, or a remote sensor on a trolley. While a survey is open, every access point that sensor hears is noted with its
signal. When you tap a spot on the floor plan (from any browser, the phone's own included), the readings of the last few seconds
become a survey point: per access point, the median signal. Keep still for those seconds, so a sensor that hops channels has been
round them all.

The page draws, from the points, how strong your networks are everywhere (the best access point, per band or one access point),
how strong the second-best one is (what roaming designs aim for), where several of your access points are heard well at once, and
how many other access points share the channel of the strongest one (co-channel interference).

Release 34.2 adds the analysis of a survey: the dead spots (points where none of yours is heard at -75 dBm or better), a suggestion
where one extra access point would cover most of the weak area (a log-distance path-loss model, fitted to the survey itself), and
the comparison of two surveys of the same floor (before / after moving an access point or changing channels).
"""
import json
import math
import statistics
import threading
import time
from collections import deque

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .auth import current_user, require_admin
from .sensors import floorplan_file

SCHEMA = """
CREATE TABLE IF NOT EXISTS walk_sessions(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, sensor TEXT, created REAL, closed REAL);
CREATE TABLE IF NOT EXISTS walk_points(id INTEGER PRIMARY KEY AUTOINCREMENT, session INTEGER NOT NULL, ts REAL, x REAL, y REAL,
  readings TEXT);
CREATE INDEX IF NOT EXISTS idx_walk_points ON walk_points(session);
"""
GOOD, WEAK = -67, -75   # the usual targets: calls and video, and where it gets unusable
GRID = 40               # cells across the floor for the analysis
REACH = 0.18            # how far (a share of the floor's long side) a point says something about its surroundings
DEFAULT_WIDTH_M = 20
MODEL = (-40.0, 3.0)    # rssi at 1 m, path-loss exponent: the fallback when the survey doesn't fit a model
WINDOW = 10          # seconds of readings a point is made of
KEEP = 60            # seconds of readings kept per access point while a survey is open
MAX_APS = 3000


class WalkCollector:
    """Store plugin: while a survey is open on a sensor, keeps every access point reading of that sensor for a minute."""

    def __init__(self, ctx):
        self.ctx = ctx
        ctx.store.conn.executescript(SCHEMA)
        if "width_m" not in {r[1] for r in ctx.store.conn.execute("PRAGMA table_info(walk_sessions)")}:
            ctx.store.conn.execute("ALTER TABLE walk_sessions ADD COLUMN width_m REAL")
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


def demo_readings(ctx, x, y, without=()):
    """The demo's sensors don't move: make up what a sensor at (x, y) would hear, from where the demo access points stand
    (log-distance path loss, a 20 m wide floor, walls by room). `without`: access points that were off."""
    from .demo import APS, FIXED_ROOMS, SENSORS
    rooms = {room: (sx, sy) for _, _, room, sx, sy in SENSORS}
    out = {}
    for mac, ssid, ch, enc, base, vendor in APS:
        room = FIXED_ROOMS.get(mac)
        if mac in without:
            continue
        if room in rooms:
            ax, ay = rooms[room]
            d = max(0.5, math.hypot((x - ax) * 20, (y - ay) * 13))
            out[mac] = round(-32 - 30 * math.log10(d) - (6 if (x - ax) * (y - ay) < -0.02 else 0) - (4 if isinstance(ch, tuple) or ch > 14 else 0))
        else:   # the neighbours: about as loud everywhere
            out[mac] = base + int(((x * 7 + y * 3) % 1) * 4)
    return {k: v for k, v in out.items() if v >= -92}


# ---------------------------------------------------------------- analysis

def best(readings, macs, rank=0):
    """The strongest (rank 0) or second-strongest (rank 1) reading of these access points, or None."""
    vals = sorted((v for m, v in readings.items() if m in macs), reverse=True)
    return vals[rank] if len(vals) > rank else None


def ratio_of(fp):
    fp = fp or {}
    return fp["height"] / fp["width"] if fp.get("width") and fp.get("height") else 0.64


def grid(points, ratio, n=GRID):
    """The cells of the floor (centre x, y as shares of width and height) with the interpolated value of the points
    (inverse-distance weighting, as the page draws it), leaving out cells too far from any point. points: [(x, y, v)]."""
    pts = [(x, y * ratio, v) for x, y, v in points if v is not None]
    if not pts:
        return []
    rows = max(1, round(n * ratio))
    reach = REACH * max(1, ratio)
    out = []
    for j in range(rows):
        for i in range(n):
            cx, cy = (i + 0.5) / n, (j + 0.5) / rows
            num = den = 0.0
            near = math.inf
            for x, y, v in pts:
                d2 = (x - cx) ** 2 + (y - cy * ratio) ** 2
                near = min(near, d2)
                w = 1 / max(d2, 1e-6) ** 1.5
                num += w * v
                den += w
            if math.sqrt(near) <= reach:
                out.append((cx, cy, num / den))
    return out


def fit_model(points, mine, ratio, width_m):
    """Fit rssi = A - 10 n log10(d) to the survey: each of my access points is taken to stand near where it was heard
    best (the strongest point, pulled a little towards the next two), and its other readings give the fall-off with the
    distance. Falls back to MODEL when there is too little to go by, and clamps to what indoor Wi-Fi does."""
    xs, ys = [], []
    for mac in mine:
        heard = sorted(((p["readings"][mac], p["x"], p["y"]) for p in points if mac in p["readings"]), reverse=True)
        if len(heard) < 4:
            continue
        top = heard[:3]
        wsum = sum(10 ** (v / 20) for v, _, _ in top)
        ax = sum(10 ** (v / 20) * x for v, x, _ in top) / wsum
        ay = sum(10 ** (v / 20) * y for v, _, y in top) / wsum
        for v, x, y in heard:
            d = math.hypot((x - ax) * width_m, (y - ay) * width_m * ratio)
            if d >= 1.5:
                xs.append(math.log10(d))
                ys.append(v)
    if len(xs) < 8 or max(xs) - min(xs) < 0.3:
        return MODEL
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    slope = sum((a - mx) * (b - my) for a, b in zip(xs, ys)) / sum((a - mx) ** 2 for a in xs)
    n = min(5.0, max(2.0, -slope / 10))
    a = min(-25.0, max(-55.0, my + 10 * n * mx))
    return round(a, 1), round(n, 2)


def nearest_room(ctx, x, y):
    best_room, best_d = None, math.inf
    for s in ctx.rows("SELECT room, x, y FROM sensors WHERE room IS NOT NULL AND x IS NOT NULL"):
        d = math.hypot(s["x"] - x, s["y"] - y)
        if d < best_d:
            best_room, best_d = s["room"], d
    return best_room


def analyse(ctx, s, points, aps):
    """Dead spots, coverage, and where one extra access point would help most."""
    ratio = ratio_of(ctx.settings.get("floorplan"))
    width_m = s.get("width_m") or DEFAULT_WIDTH_M
    mine = {m for m, a in aps.items() if a.get("mine")}
    vals = [(p["x"], p["y"], best(p["readings"], mine)) for p in points]
    dead = [{"x": x, "y": y, "best": v, "room": nearest_room(ctx, x, y)} for x, y, v in vals if v is None or v < WEAK]
    cells = grid(vals, ratio)
    out = {"dead": dead, "points_good": sum(1 for *_, v in vals if v is not None and v >= GOOD), "points": len(vals),
           "area_good": round(100 * sum(1 for *_, v in cells if v >= GOOD) / len(cells)) if cells else None, "suggest": None}
    weak = [(x, y, v) for x, y, v in cells if v < GOOD]
    if not mine or not weak or len(points) < 4:
        return out
    a, n = fit_model(points, mine, ratio, width_m)
    best_pick = None
    for cx, cy, _ in cells[::2]:   # candidates: every other cell of the surveyed area
        fixed, gain = 0, 0.0
        for x, y, v in weak:
            d = max(1.0, math.hypot((x - cx) * width_m, (y - cy) * width_m * ratio))
            new = a - 10 * n * math.log10(d)
            if new >= GOOD:
                fixed += 1
            gain += max(0.0, new - v)
        if best_pick is None or (fixed, gain) > best_pick[:2]:
            best_pick = (fixed, gain, cx, cy)
    fixed, _, cx, cy = best_pick
    if fixed:
        after = sum(1 for *_, v in cells if v >= GOOD) + fixed
        out["suggest"] = {"x": round(cx, 3), "y": round(cy, 3), "room": nearest_room(ctx, cx, cy), "fixes": round(100 * fixed / len(weak)),
                          "area_after": round(100 * after / len(cells)), "model": {"a": a, "n": n, "fitted": (a, n) != MODEL}}
    return out


def compare(ctx, before, after, mine):
    """The change in the strongest of my access points between two surveys, cell by cell where both say something."""
    ratio = ratio_of(ctx.settings.get("floorplan"))
    key = lambda x, y: (round(x, 4), round(y, 4))   # noqa: E731
    ga = {key(x, y): v for x, y, v in grid([(p["x"], p["y"], best(p["readings"], mine)) for p in before], ratio)}
    both = [(x, y, ga[key(x, y)], v) for x, y, v in grid([(p["x"], p["y"], best(p["readings"], mine)) for p in after], ratio) if key(x, y) in ga]
    n = len(both) or 1
    return {"cells": [{"x": x, "y": y, "d": round(b - a, 1)} for x, y, a, b in both], "n": GRID, "rows": max(1, round(GRID * ratio)),
            "better": round(100 * sum(1 for *_, a, b in both if b - a >= 3) / n), "worse": round(100 * sum(1 for *_, a, b in both if b - a <= -3) / n),
            "good_before": round(100 * sum(1 for *_, a, b in both if a >= GOOD) / n), "good_after": round(100 * sum(1 for *_, a, b in both if b >= GOOD) / n),
            "median": round(statistics.median([b - a for *_, a, b in both]), 1) if both else None}


class StartBody(BaseModel):
    name: str = Field("Survey", min_length=1, max_length=60)
    sensor: str = Field("local", max_length=64)
    width_m: float = Field(DEFAULT_WIDTH_M, ge=3, le=500)


class EditBody(BaseModel):
    name: str = Field(None, min_length=1, max_length=60)
    width_m: float = Field(None, ge=3, le=500)


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
        """The demo gets two surveys to look at: a walk through the three rooms, and the same walk a week before, when the
        5 GHz access point in the office wasn't there yet (to compare)."""
        if not ctx.cfg.demo or ctx.one("SELECT id FROM walk_sessions LIMIT 1"):
            return
        pts = [(0.06 + 0.11 * i, 0.08 + 0.14 * j) for i in range(9) for j in range(7)]
        with ctx.wdb() as w:
            for name, ago, without in (("Ground floor, before the office AP", 7 * 86400, ("24:a4:3c:10:00:02",)), ("Ground floor", 3600, ())):
                sid = w.execute("INSERT INTO walk_sessions(name, sensor, created, closed, width_m) VALUES(?, 'local', ?, ?, 20)",
                                (name, time.time() - ago, time.time() - ago + 1300)).lastrowid
                w.executemany("INSERT INTO walk_points(session, ts, x, y, readings) VALUES(?, ?, ?, ?, ?)",
                              [(sid, time.time() - ago + k * 20, x, y, json.dumps(demo_readings(ctx, x, y, without))) for k, (x, y) in enumerate(pts)])

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
            sid = w.execute("INSERT INTO walk_sessions(name, sensor, created, width_m) VALUES(?, ?, ?, ?)",
                            (body.name.strip(), body.sensor, time.time(), body.width_m)).lastrowid
        col.start(body.sensor, sid)
        return {"id": sid}

    def load(sid):
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
        return s, pts, aps

    @r.get("/api/walk/{sid}")
    def survey(sid: int, _=Depends(current_user)):
        """The points with their readings, what the access points in them are (network, band, channel, mine), and the
        analysis: dead spots, coverage, where an extra access point would help."""
        s, pts, aps = load(sid)
        return {**s, "width_m": s.get("width_m") or DEFAULT_WIDTH_M, "open": col.open.get(s["sensor"]) == sid, "points": pts, "aps": aps,
                "analysis": analyse(ctx, s, pts, aps), "good": GOOD, "weak": WEAK}

    @r.get("/api/walk/{sid}/compare/{other}")
    def compare_with(sid: int, other: int, _=Depends(current_user)):
        """How the strongest of my access points changed from survey `other` (before) to `sid` (after)."""
        _s, after, aps_a = load(sid)
        _o, before, aps_b = load(other)
        mine = {m for m, a in {**aps_b, **aps_a}.items() if a["mine"]}
        return compare(ctx, before, after, mine)

    @r.put("/api/walk/{sid}")
    def edit(sid: int, body: EditBody, _=Depends(require_admin)):
        session(sid)
        with ctx.wdb() as w:
            if body.name is not None:
                w.execute("UPDATE walk_sessions SET name=? WHERE id=?", (body.name.strip(), sid))
            if body.width_m is not None:
                w.execute("UPDATE walk_sessions SET width_m=? WHERE id=?", (body.width_m, sid))
        return {"ok": True}

    @r.get("/api/walk/{sid}/now")
    def now_heard(sid: int, seconds: int = WINDOW, _=Depends(require_admin)):
        """What a point here would hold right now: how many access points, and the strongest of mine."""
        s = session(sid)
        rd = demo_readings(ctx, 0.5, 0.5) if ctx.cfg.demo else col.readings(s["sensor"], max(3, min(seconds, 30)))
        n = ctx.settings.get("networks")
        mine = {a["mac"] for a in ctx.rows(f"SELECT mac FROM devices WHERE kind='ap' AND ssid IN ({','.join('?' * len(n['ssids']))})", n["ssids"])} if n["ssids"] else set()
        return {"aps": len(rd), "best_mine": best(rd, mine), "open": col.open.get(s["sensor"]) == sid}

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

    # ---- the sensor's own side (release 34.2): the Android app carried around walks its own survey with its sensor token. A
    # token can only see, start, add to and close surveys of its own sensor, and read the floor plan they are drawn on.

    def own_sensor(request: Request):
        u = request.state.user
        if not u or getattr(u, "scope", None) != "sensor" or not u.sensor_id:
            raise HTTPException(401, "sensor token required")
        return u.sensor_id

    def own(sid, sensor):
        s = session(sid)
        if s["sensor"] != sensor:
            raise HTTPException(404, "No such survey")
        return s

    @r.get("/api/ingest/walk")
    def sensor_state(survey: int = 0, sensor: str = Depends(own_sensor)):
        """This sensor's surveys, the open one (or `survey`) with its points coloured by the strongest of my access points, the
        analysis, and what a point here would hold now."""
        mine_list = ctx.rows("SELECT s.id, s.name, s.created, s.closed, (SELECT COUNT(*) FROM walk_points p WHERE p.session = s.id) points "
                             "FROM walk_sessions s WHERE s.sensor=? ORDER BY created DESC LIMIT 50", (sensor,))
        sid = survey or col.open.get(sensor) or 0
        out = {"surveys": mine_list, "open": col.open.get(sensor), "window": WINDOW, "good": GOOD, "weak": WEAK, "survey": None,
               "floorplan": {k: (ctx.settings.get("floorplan") or {}).get(k) for k in ("width", "height", "updated")}}
        out["floorplan"]["image"] = (floorplan_file(ctx.settings.get("floorplan")) or "").rsplit(".", 1)[-1] or None
        if sid:
            s, pts, aps = load(sid)
            if s["sensor"] != sensor:
                raise HTTPException(404, "No such survey")
            mine = {m for m, a in aps.items() if a["mine"]}
            out["survey"] = {"id": sid, "name": s["name"], "width_m": s.get("width_m") or DEFAULT_WIDTH_M, "open": col.open.get(sensor) == sid,
                             "points": [{"id": p["id"], "x": p["x"], "y": p["y"], "aps": len(p["readings"]), "best": best(p["readings"], mine)} for p in pts],
                             "analysis": analyse(ctx, s, pts, aps)}
            if out["survey"]["open"]:
                out["now"] = now_heard(sid)
        return out

    @r.get("/api/ingest/walk/floorplan")
    def sensor_floorplan(sensor: str = Depends(own_sensor)):
        import os

        from .sensors import IMAGE_TYPES
        name = floorplan_file(ctx.settings.get("floorplan"))
        path = os.path.join(ctx.cfg.data_dir, name) if name else None
        if not path or not os.path.exists(path):
            raise HTTPException(404, "No floor plan")
        return FileResponse(path, media_type=IMAGE_TYPES[name.rsplit(".", 1)[-1]], headers={"Cache-Control": "no-cache"})

    @r.post("/api/ingest/walk")
    def sensor_start(body: EditBody, sensor: str = Depends(own_sensor)):
        """Start a survey with this sensor (the one open on it is closed)."""
        for sid in [v for k, v in col.open.items() if k == sensor]:
            stop(sid)
        with ctx.wdb() as w:
            sid = w.execute("INSERT INTO walk_sessions(name, sensor, created, width_m) VALUES(?, ?, ?, ?)",
                            ((body.name or f"Survey {time.strftime('%d %b %H:%M')}").strip(), sensor, time.time(), body.width_m or DEFAULT_WIDTH_M)).lastrowid
        col.start(sensor, sid)
        return {"id": sid}

    @r.post("/api/ingest/walk/{sid}/point")
    def sensor_point(sid: int, body: PointBody, sensor: str = Depends(own_sensor)):
        own(sid, sensor)
        return point(sid, body)

    @r.delete("/api/ingest/walk/{sid}/point/{pid}")
    def sensor_undo(sid: int, pid: int, sensor: str = Depends(own_sensor)):
        own(sid, sensor)
        return undo(sid, pid)

    @r.post("/api/ingest/walk/{sid}/stop")
    def sensor_stop(sid: int, sensor: str = Depends(own_sensor)):
        own(sid, sensor)
        return stop(sid)

    @r.post("/api/ingest/walk/{sid}/resume")
    def sensor_resume(sid: int, sensor: str = Depends(own_sensor)):
        own(sid, sensor)
        return resume(sid)

    @r.delete("/api/walk/{sid}")
    def delete(sid: int, _=Depends(require_admin)):
        col.stop(sid)
        with ctx.wdb() as w:
            w.execute("DELETE FROM walk_points WHERE session=?", (sid,))
            w.execute("DELETE FROM walk_sessions WHERE id=?", (sid,))
        return {"ok": True}

    return r
