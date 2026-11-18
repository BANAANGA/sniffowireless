"""Hidden nodes: clients that cannot hear each other, so they send at the same time and their frames collide at the access point.

Every client listens before it sends; two clients on opposite sides of the access point (or with a wall between them) don't hear
each other, both think the air is free, and the access point gets both frames at once and neither. The classic sign, and what the
link counts show (linkstats.py):

* what the client sends gets lost often (many retries up), although its signal and rate are good: it is not the distance
* what the access point sends to it gets through (few retries down): the access point is heard by everyone, so nobody sends
  into its frames
* other clients send on the same channel at the same time, and they are far from this one: on the other side of the floor plan,
  or heard well only by other sensors

The usual fixes: RTS/CTS for these clients (an RTS threshold on the access point, or on the client), the access point more central,
or a second access point so the far clients use another channel.
"""
import math
import time

from fastapi import APIRouter, Depends

from .auth import current_user

MIN_UP = 200          # frames sent in the period: fewer says too little
RETRY_UP = 0.15       # retries up from here count
RETRY_POSSIBLE = 0.25 # without any sign the others are far, only this much counts
GOOD_MCS, GOOD_RSSI = 5, -67
FAR = 0.4             # a share of the floor plan's width: about 8 m on a 20 m floor, usually with walls between
HEARD_WELL = -75


def _where(ctx, macs):
    """Per client, where it is: its own position on the map, or the position of the sensor of its room; and the sensors that hear
    it well."""
    if not macs:
        return {}, {}
    ph = ",".join("?" * len(macs))
    rooms = {r["room"]: (r["x"], r["y"]) for r in ctx.rows("SELECT room, x, y FROM sensors WHERE room IS NOT NULL AND x IS NOT NULL")}
    pos = {}
    for d in ctx.rows(f"SELECT mac, room, pos_x, pos_y FROM devices WHERE mac IN ({ph})", macs):
        if d["pos_x"] is not None and d["pos_y"] is not None:
            pos[d["mac"]] = (d["pos_x"], d["pos_y"], None)
        elif d["room"] in rooms:
            pos[d["mac"]] = (*rooms[d["room"]], d["room"])
    heard = {}
    for s in ctx.rows(f"SELECT mac, sensor, rssi FROM sightings WHERE mac IN ({ph}) AND rssi >= ?", [*macs, HEARD_WELL]):
        heard.setdefault(s["mac"], set()).add(s["sensor"])
    return pos, heard


def apart(a, b, pos, heard):
    """Why a and b probably don't hear each other, or None."""
    if a in pos and b in pos:
        (ax, ay, ar), (bx, by, br) = pos[a], pos[b]
        if math.hypot(ax - bx, ay - by) >= FAR:
            return f"on the other side ({br})" if br and br != ar else "on the other side of the floor plan"
    ha, hb = heard.get(a), heard.get(b)
    if ha and hb and not ha & hb:
        return "heard well by other sensors only"
    return None


def analyze(ctx, since):
    from . import linkstats
    link = linkstats.clients(ctx, since)
    bss = {x["bssid"] for x in link if x["bssid"]}
    aps = {r["mac"]: r for r in ctx.rows(f"SELECT mac, ssid, band, channel FROM devices WHERE mac IN ({','.join('?' * len(bss))})", list(bss))} if bss else {}
    senders = {}   # (band, channel) -> clients that send enough
    for x in link:
        ap = aps.get(x["bssid"])
        if ap and x["up"] and x["up"]["frames"] >= MIN_UP:
            senders.setdefault((ap["band"], ap["channel"]), []).append(x)
    pos, heard = _where(ctx, [x["mac"] for v in senders.values() for x in v])
    out = []
    for (band, ch), group in senders.items():
        for x in group:
            up, down = x["up"], x["down"]
            r_up = up["retry_rate"] or 0
            r_down = (down or {}).get("retry_rate")
            good = (up["mcs_median"] is not None and up["mcs_median"] >= GOOD_MCS) or (up["rssi"] is not None and up["rssi"] >= GOOD_RSSI)
            if r_up < RETRY_UP or not good or (r_down is not None and r_down > r_up * 0.6):
                continue
            others = [y for y in group if y["mac"] != x["mac"]]
            if not others:
                continue
            far = [{"mac": y["mac"], "name": y["name"], "why": w, "same_ap": y["bssid"] == x["bssid"]} for y in others if (w := apart(x["mac"], y["mac"], pos, heard))]
            if not far and r_up < RETRY_POSSIBLE:
                continue
            ap = aps[x["bssid"]]
            out.append({"mac": x["mac"], "name": x["name"], "bssid": x["bssid"], "ssid": ap["ssid"], "band": band, "channel": ch,
                        "retry_up": r_up, "retry_down": r_down, "mcs": up["mcs_median"], "rssi": up["rssi"], "frames": up["frames"],
                        "level": "likely" if far else "possible", "far": far[:5], "others": len(others)})
    out.sort(key=lambda c: (c["level"] != "likely", -c["retry_up"]))
    return {"clients": out, "retry_up": RETRY_UP, "min_up": MIN_UP}


def routes(ctx):
    r = APIRouter()

    @r.get("/api/channels/hidden-nodes")
    def hidden(hours: float = 24, _=Depends(current_user)):
        """Clients whose frames collide with those of clients they cannot hear."""
        return analyze(ctx, time.time() - max(1, min(hours, 24 * 30)) * 3600)

    return r
