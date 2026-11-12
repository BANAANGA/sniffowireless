"""Live signal strength of chosen devices, per sensor, for the comparison graph on the Sensors page.

The page names up to MAX_DEVICES devices and asks every few seconds for the readings since its last request. While it keeps
asking, the store records every signal reading of those devices (not just the per-minute averages it stores anyway); it stops
a minute after the last request. Nothing of this is written to the database.
"""
import time

from fastapi import APIRouter, Depends, Query

from .auth import current_user
from .sanitize import clean_mac
from .store import FOLLOW_KEEP

MAX_DEVICES = 8


def routes(ctx):
    r = APIRouter()

    @r.get("/api/signal/live")
    def live(mac: list[str] = Query(default=[], max_length=MAX_DEVICES * 4), after: float = 0, _=Depends(current_user)):
        macs = list(dict.fromkeys(m for m in (clean_mac(x) for x in mac[:MAX_DEVICES * 4]) if m))[:MAX_DEVICES]
        now = time.time()
        points = ctx.store.follow_signal(macs, after, now) if macs else {}
        q = ",".join("?" * len(macs))
        devices, latest = {}, []
        if macs:
            for d in ctx.rows(f"SELECT d.mac, d.kind, d.name, d.vendor, d.ssid, m.label, json_extract(d.ident, '$.label') ident "
                              f"FROM devices d LEFT JOIN device_meta m ON m.mac = d.mac WHERE d.mac IN ({q})", macs):
                devices[d["mac"]] = {k: v for k, v in d.items() if v is not None}
            latest = ctx.rows(f"SELECT mac, sensor, ROUND(rssi, 1) rssi, last_seen FROM sightings WHERE mac IN ({q})", macs)
        names = {s["id"]: s["name"] or s["id"] for s in ctx.rows("SELECT id, name FROM sensors")}
        return {"now": now, "keep": FOLLOW_KEEP,
                "macs": macs, "devices": devices, "latest": latest, "sensors": names,
                "points": {m: [[round(t, 3), s, rssi] for t, s, rssi in pts] for m, pts in points.items()}}

    return r
