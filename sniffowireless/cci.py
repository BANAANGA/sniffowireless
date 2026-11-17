"""Co-channel interference between your own access points, and a channel plan for all of them together.

Two access points on the same channel share its airtime wherever a radio hears both above the level at which it defers to a
Wi-Fi preamble (-82 dBm): a client there waits for either one. sniffowireless cannot hear what an access point hears, but it does
know how loud every sensor hears every access point. Where one sensor hears two of your access points both at -82 dBm or
stronger, they overlap there, by the weaker of the two signals. With sensors in several places that gives a map of which of your
access points meet where.

From the overlaps (and the neighbours' access points and the measured airtime per channel) a channel plan is worked out for all your
radios at once: 1/6/11 on 2.4 GHz, the non-DFS channels on 5 GHz (a radio on a DFS channel may keep it), the preferred scanning
channels on 6 GHz. Channel widths are not known from what is heard, so on 5 and 6 GHz radios in the same 80 MHz block count as half a
conflict.
"""
import time

from fastapi import APIRouter, Depends

from .auth import current_user

CCA = -82
MOVE_COST = 0.25      # a change of channel is not free (clients reconnect): small gains are not worth one
WINDOW = 24 * 3600
CANDIDATES = {"2.4": [1, 6, 11], "5": [36, 40, 44, 48, 149, 153, 157, 161], "6": list(range(5, 230, 16))}
BLOCKS_5 = [(36, 48), (52, 64), (100, 112), (116, 128), (132, 144), (149, 161)]


def conflict(band, a, b):
    """How much two radios on channels a and b share the air (1 = the same channel)."""
    if a == b:
        return 1.0
    if band == "2.4":
        return {1: 0.8, 2: 0.5, 3: 0.2, 4: 0.05}.get(abs(a - b), 0.0)
    if band == "5":
        return 0.5 if any(lo <= a <= hi and lo <= b <= hi for lo, hi in BLOCKS_5) else 0.0
    if band == "6":
        return 0.5 if (a - 1) // 16 == (b - 1) // 16 else 0.0
    return 0.0


def weight(dbm):
    """How much an overlap at this signal matters: from 0 at -95 dBm to 1 at -50 dBm."""
    return 0.0 if dbm is None else min(1.0, max(0.0, (dbm + 95) / 45))


def radio_key(a):
    return a["band"], a["channel"], a["mac"][3:16]


def analyze(ctx, since=None, now=None):
    now = now or time.time()
    since = since or now - WINDOW
    n = ctx.settings.get("networks")
    my_ssids, trusted = set(n["ssids"]), set(n["trusted_bssids"])
    aps = ctx.rows("SELECT mac, ssid, channel, band FROM devices WHERE kind='ap' AND channel IS NOT NULL AND band IN ('2.4', '5', '6') "
                   "AND last_seen >= ?", (since,))
    heard = {}
    for r in ctx.rows("SELECT mac, sensor, rssi FROM sightings WHERE last_seen >= ? AND mac IN (SELECT mac FROM devices WHERE kind='ap')", (since,)):
        heard.setdefault(r["mac"], {})[r["sensor"]] = round(r["rssi"])
    names = {"local": "This server"}
    names.update({r["id"]: r["name"] or r["id"] for r in ctx.rows("SELECT id, name FROM sensors")})
    mine = [a for a in aps if a["ssid"] in my_ssids and (not trusted or a["mac"] in trusted)]
    others = [a for a in aps if a not in mine]
    radios = {}
    for a in mine:   # the BSSIDs of one radio (one per SSID) count once, at the loudest
        r = radios.setdefault(radio_key(a), {"band": a["band"], "channel": a["channel"], "bssids": [], "ssids": [], "heard": {}})
        r["bssids"].append(a["mac"])
        if a["ssid"] not in r["ssids"]:
            r["ssids"].append(a["ssid"])
        for s, v in heard.get(a["mac"], {}).items():
            r["heard"][s] = max(r["heard"].get(s, -200), v)
    radios = sorted(radios.values(), key=lambda r: (r["band"] != "2.4", r["band"], r["channel"], r["bssids"][0]))
    for i, r in enumerate(radios):
        r["id"] = i
        r["bssids"].sort()
        r["label"] = f"{', '.join(r['ssids'])} · {r['bssids'][0]}"
    pairs = []
    for i, a in enumerate(radios):
        for b in radios[i + 1:]:
            if a["band"] != b["band"]:
                continue
            best = None
            for s in set(a["heard"]) & set(b["heard"]):
                v = min(a["heard"][s], b["heard"][s])
                if v >= CCA and (best is None or v > best[0]):
                    best = (v, s)
            if best:
                c = conflict(a["band"], a["channel"], b["channel"])
                pairs.append({"a": a["id"], "b": b["id"], "band": a["band"], "overlap": best[0], "sensor": best[1], "sensor_name": names.get(best[1], best[1]),
                              "conflict": c, "same_channel": a["channel"] == b["channel"]})
    spots = []
    for s in sorted({s for r in radios for s in r["heard"]} | {s for a in others for s in heard.get(a["mac"], {})}):
        for band in ("2.4", "5", "6"):
            chans = {}
            for r in radios:
                if r["band"] == band and r["heard"].get(s, -200) >= CCA:
                    chans.setdefault(r["channel"], {"mine": [], "others": 0})["mine"].append(r["id"])
            for a in others:
                if a["band"] == band and heard.get(a["mac"], {}).get(s, -200) >= CCA:
                    chans.setdefault(a["channel"], {"mine": [], "others": 0})["others"] += 1
            for ch, v in sorted(chans.items()):
                if len(v["mine"]) >= 2 or (v["mine"] and v["others"]):
                    spots.append({"sensor": s, "sensor_name": names.get(s, s), "band": band, "channel": ch, "mine": v["mine"], "others": v["others"]})
    util = {}
    try:
        from .survey import utilization
        util = {(x["band"], x["channel"]): x["utilization"] or 0 for x in utilization(ctx, now - 3600)}
    except Exception:
        pass
    return {"radios": [{k: r[k] for k in ("id", "label", "band", "channel", "bssids", "ssids", "heard")} for r in radios],
            "pairs": pairs, "spots": spots, "sensors": names, "cca": CCA, "plan": plan(radios, pairs, others, heard, util)}


def plan(radios, pairs, others, heard, util):
    """A channel per radio that keeps your own radios that overlap, and the neighbours they hear, apart. Changes that gain little
    are not suggested."""
    out = {}
    w = {}
    for p in pairs:
        w[(p["a"], p["b"])] = w[(p["b"], p["a"])] = weight(p["overlap"])
    for band in ("2.4", "5", "6"):
        rs = [r for r in radios if r["band"] == band]
        if not rs:
            continue

        def options(r):
            c = list(CANDIDATES[band])
            if r["channel"] not in c:   # a DFS channel (or one outside the list) may stay where it is
                c.append(r["channel"])
            return c

        def neighbours(r, ch):
            cost = 0.0
            for a in others:
                if a["band"] != band:
                    continue
                v = max((heard.get(a["mac"], {}).get(s, -200) for s in r["heard"]), default=-200)
                if v >= CCA:
                    cost += weight(v) * conflict(band, ch, a["channel"]) * 0.5
            return cost + util.get((band, ch), 0) * 2

        def cost(r, ch, assign):
            return sum(w.get((r["id"], o["id"]), 0) * conflict(band, ch, assign[o["id"]]) for o in rs if o is not r) + neighbours(r, ch) \
                + (MOVE_COST if ch != r["channel"] else 0)

        def total(assign):
            return sum(cost(r, assign[r["id"]], assign) for r in rs) / 1.0

        current = {r["id"]: r["channel"] for r in rs}
        assign = dict(current)
        order = sorted(rs, key=lambda r: -sum(w.get((r["id"], o["id"]), 0) for o in rs))
        for _ in range(4):   # improve one radio at a time until nothing gets better
            changed = False
            for r in order:
                best = min(options(r), key=lambda ch: (round(cost(r, ch, assign), 3), ch != assign[r["id"]], ch))
                if cost(r, best, assign) < cost(r, assign[r["id"]], assign) - 0.05:
                    assign[r["id"]] = best
                    changed = True
            if not changed:
                break
        before, after = total(current), total(assign)
        worth = before - after >= 0.5
        out[band] = {"before": round(before, 2), "after": round(after if worth else before, 2), "change": worth,
                     "radios": [{"id": r["id"], "current": r["channel"], "suggested": assign[r["id"]] if worth else r["channel"],
                                 "cost_now": round(cost(r, r["channel"], current), 2),
                                 "cost_then": round(cost(r, assign[r["id"]], assign), 2) if worth else round(cost(r, r["channel"], current), 2)}
                                for r in rs]}
    return out


def routes(ctx):
    r = APIRouter()

    @r.get("/api/channels/cci")
    def cci(hours: float = 24, _=Depends(current_user)):
        """Where your access points overlap, which channels they share there, and a channel plan for all of them."""
        now = time.time()
        return analyze(ctx, now - hours * 3600, now)

    return r
