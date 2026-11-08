"""Non-Wi-Fi interference detection from the channel survey.

Every few minutes the last 10 minutes of each channel are compared with that channel's own baseline
(the previous 24 hours). A raised noise floor, or retransmissions far above normal while the channel
isn't busy, means energy the radio can't decode as Wi-Fi: a microwave oven, video sender, baby monitor,
cordless phone, faulty power supply or radar. Anomalies are grouped per band into episodes.
"""
import json
import statistics
import time

from fastapi import APIRouter, Depends

from .auth import current_user
from .config import band_of, freq_to_channel

SCHEMA = """
CREATE TABLE IF NOT EXISTS interference(
  id INTEGER PRIMARY KEY AUTOINCREMENT, band TEXT NOT NULL, start_ts REAL NOT NULL, end_ts REAL NOT NULL,
  channels TEXT, peak_noise_delta REAL, peak_retry REAL, base_retry REAL, kind TEXT, detail TEXT, open INTEGER DEFAULT 1);
CREATE INDEX IF NOT EXISTS idx_interference_end ON interference(end_ts);
"""
RUN_EVERY = 300        # seconds between analyses
WINDOW = 600           # recent window compared with the baseline
NOISE_DELTA = 6.0      # dB above the channel's usual noise floor
RETRY_MIN = 0.30       # retry ratio that is suspicious on its own...
RETRY_FACTOR = 2.0     # ...when it is also this many times the channel's normal ratio
BUSY = 0.6             # above this airtime use, retries are explained by congestion
CLOSE_AFTER = 900      # an episode ends after this long without anomalies
MIN_MINUTES = 2        # anomalous minutes needed within the window


def classify(band, chans, duration, has_noise):
    if band == "2.4":
        centre = [c for c in chans if 6 <= c <= 13]
        if duration < 1200 and centre and len(centre) >= len(chans) * 0.6:
            kind = "Microwave oven likely"
            why = "short burst centred on 2.45 GHz (channels 6–13), the band microwave ovens leak into"
        elif len(chans) >= 3 and duration >= 3600:
            kind = "Persistent 2.4 GHz interferer"
            why = "long-lasting and across several channels: e.g. a video sender, wireless camera, baby monitor " \
                  "or a faulty power supply / USB 3 device"
        elif len(chans) >= 3:
            kind = "Broadband 2.4 GHz interference"
            why = "several channels at once: e.g. a cordless phone, baby monitor, video sender or microwave"
        else:
            kind = "Narrowband 2.4 GHz interference"
            why = "one or two channels: e.g. an analog video sender, wireless audio or a nearby busy device"
    else:
        kind = f"Non-Wi-Fi interference on {band} GHz"
        why = "e.g. weather/airport radar (DFS channels), wireless video links or LTE-U"
    if not has_noise:
        why += "; this adapter reports no noise level, so the call is based on retransmissions only " \
               "(hidden Wi-Fi stations cause these too)"
    return kind, why


class InterferenceDetector:
    """Store plugin: sweep() runs on the writer thread; reads channel_stats through its own connection."""

    def __init__(self, ctx):
        self.ctx = ctx
        ctx.store.conn.executescript(SCHEMA)
        self.last_run = 0
        self.open = {}    # band -> episode dict
        self.closed = []  # episodes closed since the last flush
        for r in ctx.rows("SELECT * FROM interference WHERE open=1"):
            r["channels"] = json.loads(r["channels"] or "[]")
            self.open[r["band"]] = r
        self.pending = False

    def analyse(self, now):
        """Return {band: {"chans": [...], "noise": peak delta, "retry": peak ratio, "base": base retry, "has_noise": bool}}.

        The baseline uses 10-minute buckets of the previous 24 h; the recent window is judged per minute, so a
        3-minute microwave burst isn't averaged away. At least MIN_MINUTES anomalous minutes are required.
        """
        base_rows = self.ctx.rows(
            "SELECT freq, minute / 600 AS b, SUM(noise_sum) ns, SUM(noise_cnt) nc, SUM(retries) r, SUM(frames) f "
            "FROM channel_stats WHERE minute >= ? AND minute < ? GROUP BY freq, b", (now - 86400, now - WINDOW - 1200))
        recent = self.ctx.rows(
            "SELECT freq, minute, SUM(noise_sum) ns, SUM(noise_cnt) nc, SUM(retries) r, SUM(frames) f, "
            "SUM(airtime_us) a, SUM(dwell_ms) d FROM channel_stats WHERE minute >= ? GROUP BY freq, minute",
            (now - WINDOW,))
        base = {}
        for x in base_rows:
            base.setdefault(x["freq"], []).append(x)
        cur = {}
        for x in recent:
            cur.setdefault(x["freq"], []).append(x)
        out = {}
        for freq, lst in cur.items():
            bl = base.get(freq) or []
            if len(bl) < 6:
                continue  # not enough history for a baseline yet
            bn = [x["ns"] / x["nc"] for x in bl if x["nc"]]
            br = [x["r"] / x["f"] for x in bl if x["f"] >= 20]
            b_noise = statistics.median(bn) if bn else None
            b_retry = statistics.median(br) if br else None
            deltas, retries, minutes = [], [], set()
            for x in lst:
                if x["nc"] and b_noise is not None:
                    d = x["ns"] / x["nc"] - b_noise
                    if d >= NOISE_DELTA:
                        deltas.append(d)
                        minutes.add(x["minute"])
                util = x["a"] / (x["d"] * 1000) if x["d"] else 0
                if x["f"] >= 20 and b_retry is not None and util < BUSY:
                    r_ = x["r"] / x["f"]
                    if r_ >= RETRY_MIN and r_ >= RETRY_FACTOR * b_retry:
                        retries.append(r_)
                        minutes.add(x["minute"])
            noisy, retrying = len(deltas) >= MIN_MINUTES, len(retries) >= MIN_MINUTES
            if noisy or retrying:
                band = band_of(freq)
                e = out.setdefault(band, {"chans": [], "noise": None, "retry": 0, "base": 0, "has_noise": False,
                                          "first": min(minutes), "last": max(minutes) + 60})
                e["first"], e["last"] = min(e["first"], min(minutes)), max(e["last"], max(minutes) + 60)
                e["chans"].append(freq_to_channel(freq))
                if bn:
                    e["has_noise"] = True
                if deltas:
                    e["noise"] = max(e["noise"] or 0, max(deltas))
                peak_r = max(retries) if retries else max((x["r"] / x["f"] for x in lst if x["f"]), default=0)
                e["retry"] = max(e["retry"], peak_r)
                e["base"] = max(e["base"], b_retry or 0)
        return out

    def reset(self, module):
        """Episodes in progress belong to rows that Settings -> Clear data just deleted."""
        if module == "wifi":
            self.open, self.closed, self.pending = {}, [], False

    def sweep(self, store, now):
        if now - self.last_run < RUN_EVERY:
            return
        self.last_run = now
        found = self.analyse(now)
        for band, a in found.items():
            ep = self.open.get(band)
            if ep is None:
                ep = self.open[band] = {"id": None, "band": band, "start_ts": a["first"], "end_ts": a["last"], "channels": [],
                                        "peak_noise_delta": None, "peak_retry": 0, "base_retry": a["base"], "open": 1}
                new = True
            else:
                new = False
            ep["end_ts"] = max(ep["end_ts"], a["last"])
            ep["channels"] = sorted(set(ep["channels"]) | set(a["chans"]))
            if a["noise"] is not None:
                ep["peak_noise_delta"] = round(max(ep["peak_noise_delta"] or 0, a["noise"]), 1)
            ep["peak_retry"] = round(max(ep["peak_retry"] or 0, a["retry"]), 3)
            ep["kind"], ep["detail"] = classify(band, ep["channels"], ep["end_ts"] - ep["start_ts"], a["has_noise"])
            ep["dirty"] = True
            if new:
                what = f"+{a['noise']:.0f} dB noise" if a["noise"] is not None else f"{a['retry']:.0%} retransmissions"
                store._event(now, f"rf:{band}", "interference", None,
                             f"{ep['kind']} on {band} GHz channels {', '.join(map(str, ep['channels']))} ({what})",
                             always=True)
        for band, ep in list(self.open.items()):
            if band not in found and now - ep["end_ts"] > CLOSE_AFTER:
                ep["open"], ep["dirty"] = 0, True
                del self.open[band]
                self.closed.append(ep)
        self.pending = any(e.get("dirty") for e in self.open.values()) or bool(self.closed)

    def flush(self, store, c):
        if not self.pending:
            return
        for ep in list(self.open.values()) + self.closed:
            if not ep.get("dirty"):
                continue
            vals = (ep["band"], ep["start_ts"], ep["end_ts"], json.dumps(ep["channels"]), ep["peak_noise_delta"],
                    ep["peak_retry"], ep["base_retry"], ep["kind"], ep["detail"], ep["open"])
            if ep["id"] is None:
                ep["id"] = c.execute("INSERT INTO interference(band, start_ts, end_ts, channels, peak_noise_delta, "
                                     "peak_retry, base_retry, kind, detail, open) VALUES(?,?,?,?,?,?,?,?,?,?)", vals).lastrowid
            else:
                c.execute("UPDATE interference SET band=?, start_ts=?, end_ts=?, channels=?, peak_noise_delta=?, "
                          "peak_retry=?, base_retry=?, kind=?, detail=?, open=? WHERE id=?", vals + (ep["id"],))
            ep["dirty"] = False
        self.closed = []
        self.pending = False

    def prune(self, store, c, cutoff):
        c.execute("DELETE FROM interference WHERE open=0 AND end_ts < ?", (cutoff,))


def routes(ctx):
    r = APIRouter()

    @r.get("/api/interference")
    def episodes(days: float = 7, _=Depends(current_user)):
        rows = ctx.rows("SELECT * FROM interference WHERE end_ts >= ? ORDER BY start_ts DESC LIMIT 200",
                        (time.time() - days * 86400,))
        for x in rows:
            x["channels"] = json.loads(x["channels"] or "[]")
        return {"episodes": rows, "now": time.time()}

    return r
