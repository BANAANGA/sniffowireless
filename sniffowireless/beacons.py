"""Beacon overhead: how much of each channel's airtime goes to beacons alone.

Every access point sends a beacon for every SSID it offers, about ten times a second (every 100 TU of 1.024 ms), at its lowest
basic rate so every client can decode it. On 2.4 GHz that is often still 1 Mb/s, where a 300-byte beacon takes about 2.6 ms.
Many SSIDs on many access points sharing a channel then leave less airtime for traffic. A typical consultant's rule of thumb:
under 10 % is fine, above 20 % is a problem.

Power save (release 34.2): clients that sleep wake up for every DTIM beacon (every so many beacons, as each access point's TIM
element says), when the access point sends the multicast and broadcast it held back. A short DTIM interval costs sleeping phones
and battery sensors energy; a long one delays multicast (mDNS, casting and AirPlay discovery, ARP) by up to that long.

Per access point the beacon interval, the lowest basic rate and the size of its beacon come from its beacons (wifiattrs); where
an older sensor did not report them, 100 TU, 1 Mb/s (2.4 GHz) or 6 Mb/s (5 / 6 GHz) and 300 bytes are assumed. Only access points
heard at -82 dBm or stronger count: that is the level at which a radio's clear-channel assessment detects a Wi-Fi preamble and
defers to it, so weaker ones barely take airtime here. The time is the frame on the air (preamble and payload); the gap and
backoff around it are left out, so the real overhead is a little higher.
"""
import json
import math
import time

from fastapi import APIRouter, Depends

from .auth import current_user

CCA_DBM = -82                 # preamble detection threshold: weaker beacons are not deferred to
DEFAULT_TU, DEFAULT_LEN = 100, 300
DEFAULT_RATE = {"2.4": 1.0, "5": 6.0, "6": 6.0}
HIGH, BAD = 0.10, 0.20        # share of the airtime
DTIM_SHORT_MS, DTIM_LONG_MS, DTIM_VERY_LONG_MS = 110, 650, 1000
MANY_SSIDS = 4                # SSIDs on one radio worth a remark


def frame_us(length, rate, band):
    """Time on the air of a `length`-byte frame (FCS included) sent at `rate` Mb/s."""
    if rate in (1.0, 2.0, 5.5, 11.0):   # DSSS / CCK, long preamble (beacons use it so that every 802.11b client hears them)
        return 192 + length * 8 / rate
    symbols = math.ceil((16 + 8 * length + 6) / (4 * rate))   # OFDM: service + data + tail bits in 4 µs symbols
    return 20 + 4 * symbols + (6 if band == "2.4" else 0)     # preamble + SIGNAL, and the 2.4 GHz signal extension


def airtime(length, rate, tu, band):
    """Share of the airtime one BSSID's beacons take."""
    return frame_us(length, rate, band) / (tu * 1024)


def radio_key(a):
    """BSSIDs one radio offers its SSIDs under differ in the last digit (and often in the locally administered bit of the first
    byte): a guess at which BSSIDs are one radio."""
    return a["band"], a["channel"], a["mac"][3:16]


def overhead(ctx, since):
    n = ctx.settings.get("networks")
    my_ssids, trusted = set(n["ssids"]), set(n["trusted_bssids"])
    rows = ctx.rows("SELECT mac, ssid, channel, band, last_rssi, extra FROM devices WHERE kind='ap' AND channel IS NOT NULL "
                    "AND band IN ('2.4', '5', '6') AND last_seen >= ?", (since,))
    aps = []
    for r in rows:
        try:
            extra = json.loads(r["extra"] or "{}")
        except ValueError:
            extra = {}
        info = extra.get("ap") or {}
        rate, tu, size = info.get("basic_rate"), info.get("beacon_tu"), info.get("beacon_len")
        a = {"mac": r["mac"], "ssid": r["ssid"], "hidden": bool(extra.get("hidden")), "band": r["band"], "channel": r["channel"],
             "rssi": r["last_rssi"], "rate": rate or DEFAULT_RATE[r["band"]], "interval": tu if isinstance(tu, int) and 10 <= tu <= 10000 else DEFAULT_TU,
             "length": size if isinstance(size, int) and 40 <= size <= 2400 else DEFAULT_LEN, "known": bool(rate and size),
             "dtim": info.get("dtim") if isinstance(info.get("dtim"), int) and 1 <= info.get("dtim") <= 255 else None,
             "mine": r["ssid"] in my_ssids and (not trusted or r["mac"] in trusted)}
        a["counts"] = a["rssi"] is None or a["rssi"] >= CCA_DBM
        a["airtime"] = round(airtime(a["length"], a["rate"], a["interval"], a["band"]), 5)
        aps.append(a)
    channels = {}
    for a in aps:
        c = channels.setdefault((a["band"], a["channel"]), {"band": a["band"], "channel": a["channel"], "aps": 0, "weak": 0, "ssids": set(),
                                                             "radios": set(), "beacons_per_s": 0.0, "airtime": 0.0, "mine": 0.0})
        if not a["counts"]:
            c["weak"] += 1
            continue
        c["aps"] += 1
        c["ssids"].add(a["ssid"] or f"(hidden {a['mac']})")
        c["radios"].add(radio_key(a))
        c["beacons_per_s"] += 1 / (a["interval"] * 1.024e-3)
        c["airtime"] += a["airtime"]
        if a["mine"]:
            c["mine"] += a["airtime"]
    out = []
    for c in channels.values():
        c.update(ssids=len(c["ssids"]), radios=len(c["radios"]), beacons_per_s=round(c["beacons_per_s"], 1), airtime=round(min(1.0, c["airtime"]), 4),
                 mine=round(c["mine"], 4))
        c["level"] = "bad" if c["airtime"] >= BAD else "high" if c["airtime"] >= HIGH else "ok"
        out.append(c)
    out.sort(key=lambda c: (-c["airtime"], c["band"], c["channel"]))
    return {"channels": out, "aps": sorted(aps, key=lambda a: -a["airtime"]), "advice": advice(aps, out), "power": power_save(aps), "cca": CCA_DBM,
            "thresholds": {"high": HIGH, "bad": BAD}}


def pct(x):
    return f"{x * 100:.1f} %" if x < 0.1 else f"{x * 100:.0f} %"


def advice(aps, channels):
    out = []
    for c in channels:
        if c["level"] != "ok":
            out.append({"level": c["level"], "band": c["band"], "channel": c["channel"],
                        "text": f"Beacons alone take {pct(c['airtime'])} of channel {c['channel']} ({c['band']} GHz): {c['aps']} BSSIDs, "
                                f"{c['ssids']} SSIDs on about {c['radios']} radios." + (f" Yours: {pct(c['mine'])}." if c["mine"] else "")})
    mine = [a for a in aps if a["mine"] and a["counts"]]
    for a in mine:
        if a["band"] == "2.4" and a["rate"] < 6:
            better = airtime(a["length"], 12.0, a["interval"], a["band"])
            out.append({"level": "high" if a["rate"] <= 2 else "info", "band": a["band"], "channel": a["channel"], "mac": a["mac"],
                        "text": f"{a['ssid'] or 'A hidden network'} ({a['mac']}) on channel {a['channel']} sends its beacons at {a['rate']:g} Mb/s"
                                + ("" if a["known"] else " (assumed: the sensor did not report it)")
                                + f". With 12 Mb/s as its lowest basic rate they would take {pct(better)} instead of {pct(a['airtime'])} of the channel."
                                " Only clients that can do nothing but 802.11b (from before about 2005) would no longer join."})
        if a["interval"] < 100:
            out.append({"level": "info", "band": a["band"], "channel": a["channel"], "mac": a["mac"],
                        "text": f"{a['ssid'] or 'A hidden network'} ({a['mac']}) sends a beacon every {a['interval']} TU instead of the usual 100,"
                                f" {100 / a['interval']:.1f}× the beacon airtime."})
    radios = {}
    for a in mine:
        radios.setdefault(radio_key(a), []).append(a)
    for (band, channel, _), group in radios.items():
        if len(group) >= MANY_SSIDS:
            total = sum(a["airtime"] for a in group)
            out.append({"level": "info", "band": band, "channel": channel,
                        "text": f"One of your radios on channel {channel} ({band} GHz) seems to offer {len(group)} SSIDs "
                                f"({', '.join(sorted(a['ssid'] or 'hidden' for a in group))}). Their beacons take {pct(total)};"
                                f" each SSID you drop or merge saves about {pct(total / len(group))}."})
    order = {"bad": 0, "high": 1, "info": 2}
    out.sort(key=lambda x: order[x["level"]])
    return out


def power_save(aps):
    """Per network of mine: how often its access points send the multicast held back for sleeping clients (beacon interval x
    DTIM period), and what that means for battery and for multicast."""
    by = {}
    for a in aps:
        if a["mine"] and a["dtim"]:
            by.setdefault(a["ssid"] or "(hidden)", []).append(a)
    out = []
    for ssid, group in sorted(by.items()):
        ms = sorted({round(a["interval"] * 1.024 * a["dtim"]) for a in group})
        worst = max(ms)
        if worst >= DTIM_VERY_LONG_MS:
            level, text = "high", (f"Multicast and broadcast wait up to {worst / 1000:.1f} s for sleeping clients: casting and AirPlay discovery, "
                                   "smart-home apps and calls can stall. A DTIM period of 1–3 (100–300 ms) is usual.")
        elif worst >= DTIM_LONG_MS:
            level, text = "info", (f"Multicast waits up to {worst} ms for sleeping clients: fine for battery, slow for discovery (casting, "
                                   "printers). 1–3 is usual unless the network is mostly battery sensors.")
        elif worst <= DTIM_SHORT_MS:
            level, text = "info", ("Sleeping clients wake up for every beacon (DTIM 1): the lowest delay for multicast, but phones and battery "
                                   "sensors use more energy. DTIM 2–3 roughly halves that wake-up energy for a few hundred ms of delay.")
        else:
            level, text = "ok", f"Multicast is sent every {worst} ms: a good balance of battery and delay."
        if len(ms) > 1:
            text += f" The access points of this network differ ({', '.join(f'{m} ms' for m in ms)}): clients behave differently after roaming."
            level = "info" if level == "ok" else level
        out.append({"ssid": ssid, "level": level, "text": text, "ms": ms,
                    "aps": [{"mac": a["mac"], "band": a["band"], "channel": a["channel"], "interval": a["interval"], "dtim": a["dtim"]} for a in group]})
    return out


def routes(ctx):
    r = APIRouter()

    @r.get("/api/channels/beacons")
    def beacons(hours: float = 1, _=Depends(current_user)):
        """Beacon airtime per channel, from the access points heard in the last `hours`."""
        return overhead(ctx, time.time() - hours * 3600)

    return r
