"""Channel survey: per-channel airtime / retry / noise statistics measured while the sensor dwells on
each channel, plus a channel recommendation per band."""
import time

from fastapi import APIRouter, Depends

from .auth import current_user
from .config import band_of, ch_to_freq, freq_to_channel

SCHEMA = """
CREATE TABLE IF NOT EXISTS channel_stats(
  minute INTEGER NOT NULL, sensor TEXT NOT NULL, freq INTEGER NOT NULL, dwell_ms INTEGER DEFAULT 0,
  frames INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0, airtime_us INTEGER DEFAULT 0, retries INTEGER DEFAULT 0,
  noise_sum INTEGER DEFAULT 0, noise_cnt INTEGER DEFAULT 0, PRIMARY KEY(minute, sensor, freq)) WITHOUT ROWID;
"""
HT_RATES = [6.5, 13, 19.5, 26, 39, 52, 58.5, 65]
NON_DFS_5 = [36, 40, 44, 48, 149, 153, 157, 161, 165]
BLOCKS_80 = [(36, 48), (52, 64), (100, 112), (116, 128), (132, 144), (149, 161)]
PSC_6 = list(range(5, 230, 16))


def frame_airtime_us(length, rate_mbps):
    """Rough on-air time of one frame: preamble + payload at the reported PHY rate."""
    return 20 + (length * 8) / max(rate_mbps or 24.0, 1.0)


def rate_from_radiotap(rt):
    rate = getattr(rt, "Rate", None)
    if rate:
        return rate / 2.0
    idx = getattr(rt, "MCS_index", None)
    if idx is not None:
        return HT_RATES[idx % 8] * (idx // 8 + 1)
    return None


class SurveyCollector:
    """Store plugin: aggregates 'chan' observations into per-minute channel_stats rows."""

    def __init__(self, ctx):
        self.ctx = ctx
        ctx.store.conn.executescript(SCHEMA)
        self.pending = {}

    def observe(self, store, o, dev):
        if o["t"] != "chan":
            return
        k = (int(o["ts"] // 60) * 60, o.get("sensor") or "local", int(o["freq"]))
        b = self.pending.setdefault(k, [0, 0, 0, 0, 0, 0, 0])
        for i, f in enumerate(("dwell_ms", "frames", "bytes", "airtime_us", "retries", "noise_sum", "noise_cnt")):
            b[i] += int(o.get(f) or 0)

    def flush(self, store, c):
        c.executemany("INSERT INTO channel_stats VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(minute, sensor, freq) DO UPDATE "
                      "SET dwell_ms=dwell_ms+excluded.dwell_ms, frames=frames+excluded.frames, bytes=bytes+excluded.bytes, "
                      "airtime_us=airtime_us+excluded.airtime_us, retries=retries+excluded.retries, "
                      "noise_sum=noise_sum+excluded.noise_sum, noise_cnt=noise_cnt+excluded.noise_cnt",
                      [(*k, *v) for k, v in self.pending.items()])
        self.pending.clear()

    def prune(self, store, c, cutoff):
        c.execute("DELETE FROM channel_stats WHERE minute < ?", (cutoff,))


def _weight(rssi):
    """How much a neighbouring AP matters: strong signals interfere more."""
    if rssi is None:
        return 0.3
    return min(1.0, max(0.05, (rssi + 95) / 45))


def recommend(aps, util, my_bssids=()):
    """Score candidate channels per band (lower = better). aps: dicts with channel, band, last_rssi, mac.
    util: {(band, channel): utilization 0..1} measured by the sensor."""
    others = [a for a in aps if a["mac"] not in my_bssids and a.get("channel")]
    out = {}
    # 2.4 GHz: 20 MHz channels overlap up to 4 channels away; only 1/6/11 don't overlap each other.
    scores = []
    for c in (1, 6, 11):
        s, n = 0.0, 0
        for a in others:
            if a["band"] != "2.4":
                continue
            d = abs(a["channel"] - c)
            ov = {0: 1.0, 1: 0.8, 2: 0.5, 3: 0.2, 4: 0.05}.get(d, 0)
            if ov:
                s += ov * _weight(a.get("last_rssi"))
                n += 1 if d == 0 else 0
        u = util.get(("2.4", c))
        s += (u or 0) * 4
        scores.append({"channel": c, "score": round(s, 2), "aps": n, "utilization": u})
    out["2.4"] = sorted(scores, key=lambda x: x["score"])
    # 5 GHz: prefer the quietest 80 MHz block, then its quietest 20 MHz channel; non-DFS first.
    scores = []
    for lo, hi in BLOCKS_80:
        block = [a for a in others if a["band"] == "5" and lo <= a["channel"] <= hi]
        for c in range(lo, hi + 1, 4):
            same = [a for a in block if a["channel"] == c]
            s = sum(_weight(a.get("last_rssi")) for a in same) + 0.4 * sum(_weight(a.get("last_rssi")) for a in block)
            u = util.get(("5", c))
            s += (u or 0) * 4
            dfs = c not in NON_DFS_5
            scores.append({"channel": c, "score": round(s + (0.5 if dfs else 0), 2), "aps": len(same),
                           "block_aps": len(block), "dfs": dfs, "utilization": u})
    scores.append({"channel": 165, "score": round(sum(_weight(a.get("last_rssi")) for a in others
                                                      if a["band"] == "5" and a["channel"] == 165)
                                                  + (util.get(("5", 165)) or 0) * 4, 2),
                   "aps": sum(1 for a in others if a["band"] == "5" and a["channel"] == 165), "dfs": False,
                   "utilization": util.get(("5", 165)), "note": "20 MHz only"})
    out["5"] = sorted(scores, key=lambda x: x["score"])
    scores = []
    for c in PSC_6:
        same = [a for a in others if a["band"] == "6" and abs(a["channel"] - c) < 16]
        scores.append({"channel": c, "score": round(sum(_weight(a.get("last_rssi")) for a in same)
                                                    + (util.get(("6", c)) or 0) * 4, 2), "aps": len(same),
                       "utilization": util.get(("6", c))})
    out["6"] = sorted(scores, key=lambda x: x["score"])
    return out


def routes(ctx):
    r = APIRouter()

    def utilization(since, sensor=None):
        w, p = ("AND sensor=?", [sensor]) if sensor else ("", [])
        rows = ctx.rows(f"SELECT freq, SUM(dwell_ms) dwell, SUM(frames) frames, SUM(bytes) bytes, SUM(airtime_us) air, "
                        f"SUM(retries) retries, SUM(noise_sum) ns, SUM(noise_cnt) nc FROM channel_stats WHERE minute>=? "
                        f"{w} GROUP BY freq ORDER BY freq", [since] + p)
        for x in rows:
            x["channel"], x["band"] = freq_to_channel(x["freq"]), band_of(x["freq"])
            x["utilization"] = round(min(1.0, x["air"] / (x["dwell"] * 1000)), 4) if x["dwell"] else None
            x["retry_rate"] = round(x["retries"] / x["frames"], 4) if x["frames"] else None
            x["noise"] = round(x["ns"] / x["nc"], 1) if x["nc"] else None
            x["fps"] = round(x["frames"] / (x["dwell"] / 1000), 1) if x["dwell"] else None
        return rows

    @r.get("/api/channels")
    def channels(hours: float = 24, sensor: str = None, _=Depends(current_user)):
        now = time.time()
        since = now - hours * 3600
        stats = utilization(since, sensor)
        aps = ctx.rows("SELECT mac, ssid, channel, band, last_rssi, enc, wifi_gen FROM devices WHERE kind='ap' "
                       "AND channel IS NOT NULL AND last_seen >= ?", (since,))
        by_ch = {}
        for a in aps:
            by_ch.setdefault((a["band"], a["channel"]), []).append(a)
        for x in stats:
            lst = by_ch.get((x["band"], x["channel"]), [])
            x["aps"] = len(lst)
            x["strongest"] = max((a["last_rssi"] for a in lst if a["last_rssi"] is not None), default=None)
        n = ctx.settings.get("networks")
        my_ssids = set(n["ssids"])
        trusted = set(n["trusted_bssids"])
        # With a trusted list, only trusted BSSIDs count as mine (an evil twin isn't).
        mine = [a for a in aps if a["ssid"] in my_ssids and (not trusted or a["mac"] in trusted)]
        util = {(x["band"], x["channel"]): x["utilization"] for x in stats}
        rec = recommend(aps, util, {a["mac"] for a in mine})
        advice = []
        for a in mine:
            ranks = rec.get(a["band"]) or []
            if not ranks:
                continue
            best = ranks[0]
            cur = next((x for x in ranks if x["channel"] == a["channel"]), None)
            better = cur and best["channel"] != a["channel"] and cur["score"] - best["score"] >= 0.5
            advice.append({"mac": a["mac"], "ssid": a["ssid"], "band": a["band"], "channel": a["channel"],
                           "recommended": best["channel"] if better else a["channel"], "change": bool(better),
                           "current_score": cur["score"] if cur else None, "best_score": best["score"]})
        sensors = [r_["sensor"] for r_ in ctx.rows("SELECT DISTINCT sensor FROM channel_stats WHERE minute >= ?",
                                                   (since,))]
        return {"channels": stats, "aps_by_channel": [{"band": b, "channel": c, "aps": len(v)}
                                                      for (b, c), v in sorted(by_ch.items(), key=lambda kv: (kv[0][0] != "2.4", kv[0]))],
                "recommend": rec, "advice": advice, "sensors": sensors, "has_survey": bool(stats)}

    @r.get("/api/channels/timeline")
    def timeline(freq: int, hours: float = 24, _=Depends(current_user)):
        since = time.time() - hours * 3600
        b = 3600 if hours > 24 else 600
        return {"bucket": b, "points": ctx.rows(
            "SELECT (minute/?)*? t, SUM(airtime_us)*1.0/NULLIF(SUM(dwell_ms)*1000,0) util, "
            "SUM(retries)*1.0/NULLIF(SUM(frames),0) retry, SUM(noise_sum)*1.0/NULLIF(SUM(noise_cnt),0) noise "
            "FROM channel_stats WHERE freq=? AND minute>=? GROUP BY t ORDER BY t", (b, b, freq, since))}

    return r


__all__ = ["SurveyCollector", "routes", "frame_airtime_us", "rate_from_radiotap", "recommend", "ch_to_freq"]
