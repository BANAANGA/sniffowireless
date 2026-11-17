"""BSS colour collisions and channel widths, from what access points announce in their beacons.

Wi-Fi 6 access points give their network a colour (1-63). A radio that hears a frame of another colour on its channel may
ignore it when it is weak enough and transmit anyway (spatial reuse), so neighbouring networks on one channel share it better.
Two networks with the same colour on the same channel lose that: each takes the other's frames for its own. Access points are
meant to notice and change colour, but many do not.

Widths: 40 MHz on 2.4 GHz takes two of the three channels that do not overlap there. On 5 GHz a wide channel is only faster when
it is free: 160 MHz shared with other networks is often slower than 80 MHz on its own.
"""
import json
import time

from fastapi import APIRouter, Depends

from .auth import current_user

CCA = -82
BLOCKS_160 = [(36, 64), (100, 128), (149, 177)]
BLOCKS_80 = [(36, 48), (52, 64), (100, 112), (116, 128), (132, 144), (149, 161), (165, 177)]


def block(ch, blocks):
    return next((b for b in blocks if b[0] <= ch <= b[1]), None)


def radio_key(a):
    return a["band"], a["channel"], a["mac"][3:16]


def analyze(ctx, since):
    n = ctx.settings.get("networks")
    my_ssids, trusted = set(n["ssids"]), set(n["trusted_bssids"])
    aps = []
    for r in ctx.rows("SELECT mac, ssid, channel, band, last_rssi, extra FROM devices WHERE kind='ap' AND channel IS NOT NULL "
                      "AND band IN ('2.4', '5', '6') AND last_seen >= ?", (since,)):
        try:
            info = json.loads(r["extra"] or "{}").get("ap") or {}
        except ValueError:
            info = {}
        aps.append({"mac": r["mac"], "ssid": r["ssid"], "channel": r["channel"], "band": r["band"], "rssi": r["last_rssi"],
                    "colour": info.get("bss_color"), "width": info.get("width"),
                    "mine": r["ssid"] in my_ssids and (not trusted or r["mac"] in trusted),
                    "near": r["last_rssi"] is None or r["last_rssi"] >= CCA})
    collisions = []
    groups = {}
    for a in aps:
        if a["colour"] and a["near"]:
            groups.setdefault((a["band"], a["channel"], a["colour"]), []).append(a)
    for (band, ch, colour), g in groups.items():
        if len({radio_key(a) for a in g}) >= 2:   # the BSSIDs of one radio share its colour: that is no collision
            collisions.append({"band": band, "channel": ch, "colour": colour, "mine": any(a["mine"] for a in g),
                               "aps": [{k: a[k] for k in ("mac", "ssid", "rssi", "mine")} for a in sorted(g, key=lambda a: -(a["rssi"] or -200))]})
    collisions.sort(key=lambda c: (not c["mine"], c["band"], c["channel"]))
    warnings = []
    for a in aps:
        if not a["width"]:
            continue
        if a["band"] == "2.4" and a["width"] >= 40:
            warnings.append({"level": "warn" if a["mine"] else "info", "mac": a["mac"], "ssid": a["ssid"], "band": a["band"], "channel": a["channel"],
                             "text": "uses 40 MHz on 2.4 GHz: that takes two of the three channels that do not overlap there, and most clients "
                                     "fall back to 20 MHz anyway when anything else is around."})
        elif a["band"] == "5" and a["width"] >= 80:
            blocks = BLOCKS_160 if a["width"] >= 160 else BLOCKS_80
            b = block(a["channel"], blocks)
            others = {radio_key(o) for o in aps if o is not a and o["band"] == "5" and o["near"] and b and block(o["channel"], blocks) == b
                      and radio_key(o)[2] != radio_key(a)[2]}
            if (a["width"] >= 160 and len(others) >= 2) or (a["width"] == 80 and len(others) >= 4):
                warnings.append({"level": "warn" if a["mine"] else "info", "mac": a["mac"], "ssid": a["ssid"], "band": a["band"], "channel": a["channel"],
                                 "text": f"uses {a['width']} MHz while {len(others)} other networks are heard in the same {a['width']} MHz "
                                         f"(channels {b[0]}–{b[1]}): a narrower channel to itself is often faster."})
    warnings.sort(key=lambda w: (w["level"] != "warn", w["band"], w["channel"]))
    widths = {}
    for a in aps:
        if a["near"]:
            w = widths.setdefault(a["band"], {})
            k = str(a["width"] or 20)
            w[k] = w.get(k, 0) + 1
    return {"collisions": collisions, "warnings": warnings, "widths": widths, "cca": CCA,
            "mine": [{k: a[k] for k in ("mac", "ssid", "band", "channel", "colour", "width", "rssi")} for a in aps if a["mine"]],
            "wifi6": sum(1 for a in aps if a["colour"] and a["near"]), "near": sum(1 for a in aps if a["near"])}


def routes(ctx):
    r = APIRouter()

    @r.get("/api/channels/colours")
    def colours(hours: float = 1, _=Depends(current_user)):
        """BSS colour collisions and channel widths of the access points heard in the last `hours`."""
        return analyze(ctx, time.time() - hours * 3600)

    return r
