"""Distributed sensors: remote capture nodes forwarding to a central server, room-level location
from the strongest sensor, position estimates on a floor plan, and the map API."""
import gzip
import json
import logging
import math
import os
import re
import threading
import time
import urllib.request
from collections import deque
from contextlib import closing
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

from . import status
from .auth import current_user, require_admin

log = logging.getLogger("yolo.sensors")

SCHEMA = """
CREATE TABLE IF NOT EXISTS sensors(
  id TEXT PRIMARY KEY, name TEXT, room TEXT, x REAL, y REAL, token_id INTEGER, created REAL, last_seen REAL,
  info TEXT);
"""
ALLOWED_OBS = {"wifi_ap", "wifi_client", "bt", "bt_conn", "event", "chan", "lan", "lan_traffic", "dhcp_server"}
SIGHTING_WINDOW = 120     # use sightings from the last N seconds for location
ROOM_HYSTERESIS_DB = 4    # stay in the current room unless another sensor is this much stronger


# ------------------------------------------------------------ sensor mode
class Forwarder:
    """Stands in for the Store on a remote sensor: batches observations and POSTs them to the server."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.buf = deque(maxlen=300_000)
        self.dropped = 0
        self.sent = 0
        if not cfg.server_url or not cfg.sensor_token:
            raise SystemExit("YOLO_MODE=sensor needs SERVER_URL and SENSOR_TOKEN")

    def put(self, obs):
        if len(self.buf) == self.buf.maxlen:
            self.dropped += 1
        self.buf.append(obs)

    def run(self, stop):
        backoff = 2
        while not stop.wait(2 if backoff == 2 else backoff):
            batch = []
            while self.buf and len(batch) < 20_000:
                batch.append(self.buf.popleft())
            body = gzip.compress(json.dumps({"sent_at": time.time(), "obs": batch, "status": status.snapshot(),
                                             "dropped": self.dropped}, default=str).encode())
            req = urllib.request.Request(f"{self.cfg.server_url}/api/ingest", data=body, method="POST", headers={
                "Authorization": f"Bearer {self.cfg.sensor_token}", "Content-Type": "application/json",
                "Content-Encoding": "gzip", "User-Agent": "yolo-sensor"})
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    r.read()
                self.sent += len(batch)
                backoff = 2
            except Exception as e:
                self.buf.extendleft(reversed(batch))  # keep for the next attempt
                backoff = min(60, backoff * 2)
                log.warning("Forwarding %d observations to %s failed: %s (retry in %ds)", len(batch),
                            self.cfg.server_url, e, backoff)


# -------------------------------------------------------------- location
class LocationTracker:
    """Store plugin: assigns each present device to the room of its strongest sensor and estimates a
    position on the floor plan as the signal-weighted centroid of the sensors that hear it."""

    def __init__(self, ctx):
        self.ctx = ctx
        ctx.store.conn.executescript(SCHEMA)
        ctx.store.conn.execute("INSERT OR IGNORE INTO sensors(id, name, created) VALUES('local', 'This server', ?)",
                               (time.time(),))
        self.last_run = 0
        self.reload()

    def reload(self):
        self.sensors = {r["id"]: r for r in self.ctx.rows("SELECT id, name, room, x, y FROM sensors")}

    def sweep(self, store, now):
        if now - self.last_run < 10:
            return
        self.last_run = now
        per = {}
        for (mac, sensor), (ts, rssi) in store.sightings.items():
            if now - ts <= SIGHTING_WINDOW and sensor in self.sensors:
                per.setdefault(mac, []).append((rssi, sensor))
        multi = len({s for v in per.values() for _, s in v}) > 1
        for mac, lst in per.items():
            dev = store.devices.get(mac)
            if not dev or mac not in store.presence:
                continue
            lst.sort(reverse=True)
            best_rssi, best = lst[0]
            room = self.sensors[best]["room"] or (self.sensors[best]["name"] if multi else None)
            cur = dev.get("room")
            if cur and cur != room:
                cur_rssi = max((r for r, s in lst if (self.sensors[s]["room"] or self.sensors[s]["name"]) == cur),
                               default=None)
                if cur_rssi is not None and best_rssi - cur_rssi < ROOM_HYSTERESIS_DB:
                    room = cur
            if room and room != cur:
                dev["room"] = room
                store.dirty.add(mac)
                if cur:
                    store._event(now, mac, "moved", None, f"{cur} → {room}", dev=dev)
            placed = [(r, self.sensors[s]) for r, s in lst[:3] if self.sensors[s]["x"] is not None]
            if placed:
                ws = [10 ** (r / 10) for r, _ in placed]  # received power: nearer sensors weigh much more
                tot = sum(ws)
                x = sum(w * s["x"] for w, (_, s) in zip(ws, placed)) / tot
                y = sum(w * s["y"] for w, (_, s) in zip(ws, placed)) / tot
                if len(placed) == 1:  # one sensor: place the device in a ring around it by signal strength
                    ang = math.radians(int(mac.replace(":", "")[-4:], 16) % 360)
                    dist = min(0.12, max(0.02, (-40 - best_rssi) / 400))
                    x += dist * math.cos(ang)
                    y += dist * math.sin(ang)
                h = int(mac.replace(":", "")[-6:], 16)  # stable per-device offset so co-located dots don't overlap
                x += ((h & 0xFF) / 255 - 0.5) * 0.06
                y += (((h >> 8) & 0xFF) / 255 - 0.5) * 0.06
                dev["pos_x"], dev["pos_y"] = round(min(1, max(0, x)), 4), round(min(1, max(0, y)), 4)
                store.dirty.add(mac)


# ------------------------------------------------------------------ routes
class SensorIn(BaseModel):
    name: str
    room: Optional[str] = None


class SensorUpdate(BaseModel):
    name: Optional[str] = None
    room: Optional[str] = None
    x: Optional[float] = None
    y: Optional[float] = None
    clear_position: bool = False


def routes(ctx):
    r = APIRouter()
    data_dir = ctx.cfg.data_dir

    @r.post("/api/ingest")
    async def ingest(request: Request):
        u = request.state.user
        if not u or getattr(u, "scope", None) != "sensor" or not u.sensor_id:
            raise HTTPException(401, "sensor token required")
        raw = await request.body()
        if request.headers.get("content-encoding") == "gzip":
            raw = gzip.decompress(raw)
        body = json.loads(raw)
        sid = u.sensor_id
        offset = time.time() - float(body.get("sent_at") or time.time())
        adjust = offset if abs(offset) > 2 else 0  # crude clock sync for sensors without NTP
        n = 0
        for o in body.get("obs") or []:
            if not isinstance(o, dict) or o.get("t") not in ALLOWED_OBS or not isinstance(o.get("mac"), str):
                continue
            o["sensor"] = sid
            o["ts"] = float(o.get("ts") or time.time()) + adjust
            if o["t"] == "bt_conn":
                o["peer"] = f"{sid}:{o.get('peer') or 'hci'}"
            ctx.store.put(o)
            n += 1
        for s in body.get("status") or []:
            status.update(f"{sid}/{s.get('name')}", **{k: v for k, v in s.items() if k != "name"}, remote=sid)
        ctx.execute("UPDATE sensors SET last_seen=?, info=? WHERE id=?",
                    (time.time(), json.dumps({"dropped": body.get("dropped"), "clock_offset": round(offset, 1),
                                              "status": body.get("status")}), sid))
        return {"accepted": n}

    @r.get("/api/sensors")
    def sensors(_=Depends(current_user)):
        rows = ctx.rows("SELECT id, name, room, x, y, created, last_seen, info FROM sensors ORDER BY id != 'local', name")
        now = time.time()
        for s in rows:
            ctx.jsonf(s, "info")
            s["online"] = s["id"] == "local" or (s["last_seen"] or 0) > now - 60
        return rows

    @r.post("/api/sensors")
    def add_sensor(body: SensorIn, request: Request, _=Depends(require_admin)):
        sid = re.sub(r"[^a-z0-9-]+", "-", body.name.strip().lower()).strip("-")[:32] or "sensor"
        base, i = sid, 2
        while ctx.one("SELECT id FROM sensors WHERE id=?", (sid,)):
            sid, i = f"{base}-{i}", i + 1
        tid, token = ctx.auth.create_token(f"sensor {sid}", "sensor", sid)
        ctx.execute("INSERT INTO sensors(id, name, room, token_id, created) VALUES(?,?,?,?,?)",
                    (sid, body.name.strip(), body.room, tid, time.time()))
        ctx.location.reload()
        server = str(request.base_url).rstrip("/")
        return {"id": sid, "token": token, "server_url": server}

    @r.put("/api/sensors/{sid}")
    def update_sensor(sid: str, body: SensorUpdate, _=Depends(require_admin)):
        s = ctx.one("SELECT * FROM sensors WHERE id=?", (sid,))
        if not s:
            raise HTTPException(404)
        for f in ("name", "room", "x", "y"):
            v = getattr(body, f)
            if v is not None:
                s[f] = (v.strip() or None) if isinstance(v, str) else min(1.0, max(0.0, v))
        if body.clear_position:
            s["x"] = s["y"] = None
        ctx.execute("UPDATE sensors SET name=?, room=?, x=?, y=? WHERE id=?", (s["name"], s["room"], s["x"], s["y"], sid))
        ctx.location.reload()
        return {"ok": True}

    @r.delete("/api/sensors/{sid}")
    def delete_sensor(sid: str, _=Depends(require_admin)):
        if sid == "local":
            raise HTTPException(400, "The built-in sensor can't be removed")
        s = ctx.one("SELECT token_id FROM sensors WHERE id=?", (sid,))
        if s and s["token_id"]:
            ctx.execute("DELETE FROM api_tokens WHERE id=?", (s["token_id"],))
        ctx.execute("DELETE FROM sensors WHERE id=?", (sid,))
        ctx.location.reload()
        return {"ok": True}

    @r.post("/api/floorplan")
    async def upload_floorplan(request: Request, width: int = 0, height: int = 0, _=Depends(require_admin)):
        ctype = request.headers.get("content-type", "")
        ext = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp", "image/svg+xml": "svg"}.get(ctype)
        if not ext:
            raise HTTPException(415, "Upload a PNG, JPEG, WebP or SVG image")
        data = await request.body()
        if len(data) > 8 * 1024 * 1024:
            raise HTTPException(413, "Image larger than 8 MB")
        for old in os.listdir(data_dir):
            if old.startswith("floorplan."):
                os.remove(os.path.join(data_dir, old))
        name = f"floorplan.{ext}"
        with open(os.path.join(data_dir, name), "wb") as fh:
            fh.write(data)
        ctx.settings.set("floorplan", {"image": name, "width": width or None, "height": height or None,
                                       "updated": time.time()})
        return {"ok": True}

    @r.delete("/api/floorplan")
    def delete_floorplan(_=Depends(require_admin)):
        fp = ctx.settings.get("floorplan")
        if fp.get("image"):
            try:
                os.remove(os.path.join(data_dir, fp["image"]))
            except OSError:
                pass
        ctx.settings.set("floorplan", {"image": None, "width": None, "height": None})
        return {"ok": True}

    @r.get("/api/floorplan/image")
    def floorplan_image(_=Depends(current_user)):
        fp = ctx.settings.get("floorplan")
        path = os.path.join(data_dir, fp["image"]) if fp.get("image") else None
        if not path or not os.path.exists(path):
            raise HTTPException(404)
        return FileResponse(path, headers={"Cache-Control": "no-cache"})

    @r.get("/api/map")
    def map_data(active: int = 300, _=Depends(current_user)):
        now = time.time()
        devs = ctx.rows("SELECT d.mac, d.kind, d.name, d.ssid, d.vendor, d.dev_type, d.room, d.pos_x, d.pos_y, "
                        "d.last_rssi, d.randomized, d.ident, m.label, m.watch FROM devices d LEFT JOIN device_meta m "
                        "ON m.mac=d.mac WHERE d.last_seen >= ?", (now - active,))
        for d in devs:
            ctx.jsonf(d, "ident")
            d["label_text"] = d["label"] or d["name"] or (d["ident"] or {}).get("label") or d["ssid"] or d["mac"]
            d.pop("ident", None)
        rooms = {}
        for d in devs:
            if d["room"]:
                rooms.setdefault(d["room"], {"devices": 0, "people": 0})
                rooms[d["room"]]["devices"] += 1
                rooms[d["room"]]["people"] += d["dev_type"] == "phone"
        return {"floorplan": ctx.settings.get("floorplan"), "sensors": sensors(None), "devices": devs, "rooms": rooms}

    return r
