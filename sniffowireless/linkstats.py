"""Link quality per client: which PHY rates and MCS its data frames use, and how often they are sent again.

The sensor reads the radiotap header and frame control of every data frame between a client and its access point (both ways),
and counts per client and direction, per minute: frames, retries (the retry bit: the frame was sent before and not acknowledged)
and how many frames went at each rate and each MCS. The server adds the minutes up per hour.

That tells apart the usual reasons a client is slow:
* a weak signal: low MCS (0-3) with few retries; the link has adapted down to what the distance allows
* interference or collisions: a high MCS with many retries; the signal is good but frames get lost
* an old or limited radio: legacy rates or one spatial stream, whatever the signal

Rates of HT, VHT and HE frames are worked out from MCS, spatial streams, channel width and guard interval (the 802.11 rate
tables); a driver that reports none of these leaves only the retry count.
"""
import json
import threading
import time

from fastapi import APIRouter, Depends, HTTPException

from .auth import current_user

# Data rate in Mb/s of one spatial stream on 20 MHz with the long (0.8 µs) guard interval, per MCS
HT_VHT_20 = [6.5, 13, 19.5, 26, 39, 52, 58.5, 65, 78, 86.7, 97.5, 108.3]
HE_20 = [8.6, 17.2, 25.8, 34.4, 51.6, 68.8, 77.4, 86.0, 103.2, 114.7, 129.0, 143.4, 154.9, 172.1]   # 0.8 µs GI; MCS 12-13: EHT
WIDTH_HT = {20: 1.0, 40: 108 / 52, 80: 234 / 52, 160: 468 / 52}       # data subcarriers relative to 20 MHz
WIDTH_HE = {20: 1.0, 40: 468 / 234, 80: 980 / 234, 160: 1960 / 234}
HE_GI = {0: 1.0, 1: 13.6 / 14.4, 2: 13.6 / 16.0}                       # 0.8, 1.6, 3.2 µs


def _fields(d):
    """{bit: (offset, size)} of the radiotap fields we read, and the header length; None when it is no radiotap header."""
    if len(d) < 8 or d[0] != 0:
        return None
    length = int.from_bytes(d[2:4], "little")
    if length < 8 or length > len(d):
        return None
    words, at = [], 4
    while at + 4 <= length:
        w = int.from_bytes(d[at:at + 4], "little")
        words.append(w)
        at += 4
        if not w & 0x80000000:
            break
    sizes = {0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (2, 4), 4: (1, 2), 5: (1, 1), 6: (1, 1), 7: (2, 2), 8: (2, 2), 9: (2, 2), 10: (1, 1),
             11: (1, 1), 12: (1, 1), 13: (1, 1), 14: (2, 2), 15: (2, 2), 16: (1, 1), 17: (1, 1), 18: (4, 8), 19: (1, 3), 20: (4, 8),
             21: (2, 12), 22: (8, 12), 23: (2, 12)}
    out, p = {}, at
    w = words[0] if words else 0
    for b in range(24):   # only the first namespace: the combined values
        if not w >> b & 1:
            continue
        align, size = sizes[b]
        p = (p + align - 1) // align * align
        if p + size > length:
            break
        out[b] = (p, size)
        p += size
    return out, length


def phy(d):
    """{"rate": Mb/s or None, "mcs": label or None, "fc": frame-control offset} from the raw frame (radiotap + 802.11)."""
    got = _fields(d)
    if not got:
        return None
    f, length = got
    out = {"rate": None, "mcs": None, "fc": length, "rssi": None}
    if 5 in f:
        v = d[f[5][0]]
        out["rssi"] = v - 256 if v > 127 else v
    if 2 in f:
        v = d[f[2][0]]
        if v:
            out["rate"] = v / 2
            out["mcs"] = None
    if 19 in f:   # HT
        o = f[19][0]
        known, flags, idx = d[o], d[o + 1], d[o + 2]
        bw = 40 if known & 1 and flags & 3 == 1 else 20
        sgi = bool(known & 4 and flags & 4)
        nss, m = idx // 8 + 1, idx % 8
        out["rate"] = round(HT_VHT_20[m] * nss * WIDTH_HT[bw] * (10 / 9 if sgi else 1), 1)
        out["mcs"] = f"HT MCS {m} {nss}SS {bw}"
    if 21 in f:   # VHT: first user only
        o = f[21][0]
        known, flags, bwc, mn = int.from_bytes(d[o:o + 2], "little"), d[o + 2], d[o + 3] & 0x1F, d[o + 4]
        m, nss = mn >> 4, mn & 0x0F
        bw = 20 if bwc == 0 else 40 if bwc <= 3 else 80 if bwc <= 10 else 160
        sgi = bool(known & 0x04 and flags & 0x04)
        if nss and m < len(HT_VHT_20):
            out["rate"] = round(HT_VHT_20[m] * nss * WIDTH_HT[bw] * (10 / 9 if sgi else 1), 1)
            out["mcs"] = f"VHT MCS {m} {nss}SS {bw}"
    if 23 in f:   # HE: data1..data6, 16 bits each
        o = f[23][0]
        data = [int.from_bytes(d[o + 2 * i:o + 2 * i + 2], "little") for i in range(6)]
        if data[0] & 0x0020:   # data_mcs known
            m = data[2] >> 8 & 0x0F
            nss = max(1, data[5] & 0x0F)   # data6 bits 0-3: the number of space-time streams (0: not known)
            bwi = data[4] & 0x0F if data[0] & 0x4000 else 0   # data5 bits 0-3: bandwidth / RU allocation
            bw = {0: 20, 1: 40, 2: 80, 3: 160}.get(bwi, 20)
            gi = data[4] >> 4 & 0x03 if data[1] & 0x0002 else 0
            if m < len(HE_20):
                out["rate"] = round(HE_20[m] * nss * WIDTH_HE[bw] * HE_GI.get(gi, 1.0), 1)
                out["mcs"] = f"HE MCS {m} {nss}SS {bw}"
    return out


def _mac(b):
    return ":".join(f"{x:02x}" for x in b)


# ------------------------------------------------------------------ the sensor
MAX_LINKS = 4000      # clients x directions counted at once (a busy site; more are left out until the next minute)
MAX_KEYS = 48         # rates / MCS values kept per client and direction (the rarest go into "other")
EMIT_EVERY = 60


class LinkCounter:
    """Counts the data frames of every client, per direction, until drain() hands them over as `link` observations."""

    def __init__(self):
        self.lock = threading.Lock()
        self.links = {}
        self.last = time.time()

    def feed(self, raw):
        """One captured frame, radiotap header included. Only data frames with data in them count (not null frames)."""
        p = phy(raw)
        if not p:
            return
        o = p["fc"]
        if len(raw) < o + 24:
            return
        fc0, fc1 = raw[o], raw[o + 1]
        if (fc0 >> 2) & 3 != 2 or fc0 >> 4 & 4:   # not a data frame, or one that carries no data (null, QoS null, CF-...)
            return
        ds = fc1 & 3
        if ds == 1:     # client -> access point
            client, bssid, way = raw[o + 10:o + 16], raw[o + 4:o + 10], "up"
        elif ds == 2:   # access point -> client
            client, bssid, way = raw[o + 4:o + 10], raw[o + 10:o + 16], "down"
        else:
            return
        if client[0] & 1:   # group-addressed
            return
        key = (_mac(client), way)
        with self.lock:
            e = self.links.get(key)
            if e is None:
                if len(self.links) >= MAX_LINKS:
                    return
                e = self.links[key] = {"bssid": _mac(bssid), "frames": 0, "retries": 0, "bytes": 0, "rates": {}, "mcs": {}, "rssi_sum": 0,
                                       "rssi_n": 0}
            e["frames"] += 1
            e["bytes"] += len(raw) - o   # the frame without its radiotap header: for the airtime it took
            if fc1 & 0x08:
                e["retries"] += 1
            if p["rate"]:
                k = f"{p['rate']:g}"
                if k in e["rates"] or len(e["rates"]) < MAX_KEYS:
                    e["rates"][k] = e["rates"].get(k, 0) + 1
            if p["mcs"]:
                if p["mcs"] in e["mcs"] or len(e["mcs"]) < MAX_KEYS:
                    e["mcs"][p["mcs"]] = e["mcs"].get(p["mcs"], 0) + 1
            if way == "up" and p.get("rssi") is not None:
                e["rssi_sum"] += p["rssi"]
                e["rssi_n"] += 1

    def due(self, now):
        return now - self.last >= EMIT_EVERY

    def drain(self, now=None):
        now = now or time.time()
        with self.lock:
            links, self.links, self.last = self.links, {}, now
        return [{"t": "link", "ts": now, "mac": mac, "dir": way, **e} for (mac, way), e in links.items()]


# ------------------------------------------------------------------ the server
SCHEMA = """
CREATE TABLE IF NOT EXISTS link_stats(
  hour INTEGER NOT NULL, mac TEXT NOT NULL, dir TEXT NOT NULL, bssid TEXT, frames INTEGER DEFAULT 0, retries INTEGER DEFAULT 0,
  rssi_sum INTEGER DEFAULT 0, rssi_n INTEGER DEFAULT 0, rates TEXT, mcs TEXT, bytes INTEGER DEFAULT 0, PRIMARY KEY(hour, mac, dir)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_link_mac ON link_stats(mac, hour);
"""
MIN_FRAMES = 50        # fewer data frames than this say too little to judge a link


def _merge(a, b, limit=MAX_KEYS * 2):
    for k, v in (b or {}).items():
        if k in a or len(a) < limit:
            a[k] = a.get(k, 0) + v
    return a


class LinkCollector:
    """Store plugin: adds the sensors' per-minute `link` observations up per hour and client."""

    def __init__(self, ctx):
        self.ctx = ctx
        ctx.store.conn.executescript(SCHEMA)
        cols = {r[1] for r in ctx.store.conn.execute("PRAGMA table_info(link_stats)")}
        if "bytes" not in cols:   # release 34 had no byte count
            ctx.store.conn.execute("ALTER TABLE link_stats ADD COLUMN bytes INTEGER DEFAULT 0")
        self.pending = {}

    def observe(self, store, o, dev):
        if o["t"] != "link":
            return
        k = (int(o["ts"] // 3600) * 3600, o["mac"], o["dir"])
        p = self.pending.setdefault(k, {"bssid": None, "frames": 0, "retries": 0, "bytes": 0, "rssi_sum": 0, "rssi_n": 0, "rates": {}, "mcs": {}})
        p["bssid"] = o.get("bssid") or p["bssid"]
        for f in ("frames", "retries", "bytes", "rssi_sum", "rssi_n"):
            p[f] += int(o.get(f) or 0)
        _merge(p["rates"], o.get("rates"))
        _merge(p["mcs"], o.get("mcs"))

    def flush(self, store, c):
        for (hour, mac, way), p in self.pending.items():
            row = c.execute("SELECT frames, retries, rssi_sum, rssi_n, rates, mcs, bytes FROM link_stats WHERE hour=? AND mac=? AND dir=?",
                            (hour, mac, way)).fetchone()
            if row:
                p["frames"] += row[0]
                p["retries"] += row[1]
                p["rssi_sum"] += row[2]
                p["rssi_n"] += row[3]
                p["rates"] = _merge(json.loads(row[4] or "{}"), p["rates"])
                p["mcs"] = _merge(json.loads(row[5] or "{}"), p["mcs"])
                p["bytes"] += row[6] or 0
            c.execute("INSERT OR REPLACE INTO link_stats(hour, mac, dir, bssid, frames, retries, rssi_sum, rssi_n, rates, mcs, bytes) "
                      "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                      (hour, mac, way, p["bssid"], p["frames"], p["retries"], p["rssi_sum"], p["rssi_n"], json.dumps(p["rates"]), json.dumps(p["mcs"]),
                       p["bytes"]))
        self.pending.clear()

    def prune(self, store, c, cutoff):
        c.execute("DELETE FROM link_stats WHERE hour < ?", (cutoff,))


def parse_mcs(label):
    """"HE MCS 7 2SS 80" -> ("HE", 7, 2, 80)."""
    try:
        p = label.split()
        return p[0], int(p[2]), int(p[3][:-2]), int(p[4])
    except (IndexError, ValueError):
        return None


def summarize(rows):
    """One direction of one client, from its hourly rows: totals, the spread of rates and MCS, and what they point to."""
    s = {"frames": 0, "retries": 0, "rssi_sum": 0, "rssi_n": 0, "rates": {}, "mcs": {}, "bssid": None}
    for r in rows:
        for f in ("frames", "retries", "rssi_sum", "rssi_n"):
            s[f] += r[f] or 0
        _merge(s["rates"], json.loads(r["rates"] or "{}"), 10 ** 6)
        _merge(s["mcs"], json.loads(r["mcs"] or "{}"), 10 ** 6)
        s["bssid"] = r["bssid"] or s["bssid"]
    rates = sorted(((float(k), v) for k, v in s["rates"].items()), key=lambda x: x[0])
    n = sum(v for _, v in rates)
    out = {"frames": s["frames"], "retries": s["retries"], "retry_rate": round(s["retries"] / s["frames"], 4) if s["frames"] else None,
           "rssi": round(s["rssi_sum"] / s["rssi_n"]) if s["rssi_n"] else None, "bssid": s["bssid"],
           "rates": [{"rate": k, "frames": v} for k, v in rates], "median_rate": None, "mcs": [], "phy": None, "nss": None, "width": None,
           "mcs_median": None}
    if n:
        half, acc = n / 2, 0
        for k, v in rates:
            acc += v
            if acc >= half:
                out["median_rate"] = k
                break
    parsed = [(parse_mcs(k), v) for k, v in s["mcs"].items()]
    parsed = [(p, v) for p, v in parsed if p]
    if parsed:
        order = {"HT": 1, "VHT": 2, "HE": 3}
        out["phy"] = max((p[0] for p, _ in parsed), key=lambda x: order.get(x, 0))
        out["nss"] = max(p[2] for p, _ in parsed)
        out["width"] = max(p[3] for p, _ in parsed)
        by_mcs = {}
        for p, v in parsed:
            by_mcs[p[1]] = by_mcs.get(p[1], 0) + v
        out["mcs"] = [{"mcs": k, "frames": v} for k, v in sorted(by_mcs.items())]
        total, acc = sum(by_mcs.values()), 0
        for k, v in sorted(by_mcs.items()):
            acc += v
            if acc >= total / 2:
                out["mcs_median"] = k
                break
    elif rates:
        out["phy"] = "legacy"
    out["verdict"] = verdict(out)
    return out


def verdict(s):
    """(level, short, explanation) for one direction of a link."""
    if s["frames"] < MIN_FRAMES:
        return {"level": "none", "short": "too little data", "text": f"Only {s['frames']} data frames heard: too few to judge."}
    retry = s["retry_rate"] or 0
    m, rssi = s["mcs_median"], s["rssi"]
    weak = rssi is not None and rssi < -70
    if s["phy"] == "legacy" and (s["median_rate"] or 0) <= 54:
        legacy = s["median_rate"] is not None and s["median_rate"] <= 11
        return {"level": "warn", "short": "legacy rates",
                "text": ("Its data goes at 802.11b rates (1–11 Mb/s): a very old radio, or a link so weak only the slowest rates get through."
                         if legacy else "Only legacy (802.11a/g) rates, no MCS: an old radio, or a driver that does not report MCS.")
                + (" Its signal is weak too." if weak else "")}
    if retry >= 0.25 and m is not None and m >= 5:
        return {"level": "bad", "short": "interference",
                "text": f"{retry * 100:.0f} % of its frames are sent again while the rate stays high (median MCS {m}). The signal is good enough, "
                        "but frames get lost: interference, a hidden node or a busy channel."}
    if retry >= 0.25:
        return {"level": "bad", "short": "weak and lossy",
                "text": f"{retry * 100:.0f} % retries at a low rate (median MCS {m if m is not None else '?'})"
                        + (f", at {rssi} dBm" if rssi is not None else "") + ": too far from the access point, and frames get lost on top of that."}
    if m is not None and m <= 3:
        return {"level": "warn", "short": "weak signal",
                "text": f"A low rate (median MCS {m}) with few retries"
                        + (f", at {rssi} dBm" if rssi is not None else "") + ": the link has slowed down to what the distance allows. "
                        "A closer access point, or one on this side of the wall, would help."}
    if retry >= 0.10:
        return {"level": "warn", "short": "some retries",
                "text": f"{retry * 100:.0f} % of the frames are sent again: more than the usual few percent."}
    return {"level": "ok", "short": "healthy", "text": "A good rate with few retries."}


def client_link(ctx, mac, since):
    rows = ctx.rows("SELECT * FROM link_stats WHERE mac=? AND hour >= ? ORDER BY hour", (mac, int(since // 3600) * 3600))
    out = {"mac": mac, "min_frames": MIN_FRAMES}
    for way in ("up", "down"):
        sel = [r for r in rows if r["dir"] == way]
        out[way] = summarize(sel) if sel else None
    out["hours"] = [{"hour": h, **{w: {"frames": r["frames"], "retry_rate": round(r["retries"] / r["frames"], 4) if r["frames"] else None}
                                   for w in ("up", "down") for r in rows if r["hour"] == h and r["dir"] == w}}
                    for h in sorted({r["hour"] for r in rows})]
    return out


def clients(ctx, since, bssid=None):
    w, p = ("AND bssid=?", [bssid]) if bssid else ("", [])
    rows = ctx.rows(f"SELECT * FROM link_stats WHERE hour >= ? {w}", [int(since // 3600) * 3600] + p)
    by = {}
    for r in rows:
        by.setdefault(r["mac"], {}).setdefault(r["dir"], []).append(r)
    out = []
    for mac, ways in by.items():
        s = {w: summarize(ways[w]) for w in ways}
        main = max(s.values(), key=lambda x: x["frames"])
        rank = {"bad": 0, "warn": 1, "ok": 2, "none": 3}
        worst = min((x["verdict"] for x in s.values() if x["frames"] >= MIN_FRAMES), key=lambda v: rank[v["level"]], default=main["verdict"])
        out.append({"mac": mac, "bssid": main["bssid"], "frames": sum(x["frames"] for x in s.values()),
                    "up": {k: s["up"][k] for k in ("frames", "retry_rate", "median_rate", "mcs_median", "rssi")} if "up" in s else None,
                    "down": {k: s["down"][k] for k in ("frames", "retry_rate", "median_rate", "mcs_median")} if "down" in s else None,
                    "phy": main["phy"], "nss": max((x["nss"] or 0 for x in s.values()), default=0) or None, "verdict": worst})
    rank = {"bad": 0, "warn": 1, "ok": 2, "none": 3}
    out.sort(key=lambda x: (rank[x["verdict"]["level"]], -x["frames"]))
    names = {r["mac"]: r for r in ctx.rows(f"SELECT mac, name, vendor, brand, model FROM devices WHERE mac IN ({','.join('?' * len(out))})",
                                            [x["mac"] for x in out])} if out else {}
    for x in out:
        d = names.get(x["mac"]) or {}
        x["name"] = d.get("name") or " ".join(v for v in (d.get("brand"), d.get("model")) if v) or d.get("vendor")
    return out


# ------------------------------------------------------------------ who uses the airtime
LEGACY_DSSS = {1.0, 2.0, 5.5, 11.0}
LEGACY_OFDM = {6.0, 9.0, 12.0, 18.0, 24.0, 36.0, 48.0, 54.0}
ASSUMED_LEN = 600     # bytes per frame when a sensor (before release 34.1) did not count them
HOG_SHARE, SLOW_RATE = 0.05, 24.0


def frame_us(rate, length):
    """Time on the air of one frame: preamble (DSSS long, OFDM, or HT/VHT/HE with its training fields) and the payload."""
    pre = 192 if rate in LEGACY_DSSS else 20 if rate in LEGACY_OFDM else 40
    return pre + length * 8 / rate


def airtime_us(row):
    """(µs on the air, median rate) of one hourly link_stats row; frames whose rate is not known go at the median rate."""
    rates = sorted(((float(k), v) for k, v in json.loads(row["rates"] or "{}").items() if float(k) > 0), key=lambda x: x[0])
    frames = row["frames"] or 0
    if not frames or not rates:
        return 0.0, None
    length = (row["bytes"] or 0) / frames if row["bytes"] else ASSUMED_LEN
    known = sum(v for _, v in rates)
    acc, median = 0, rates[-1][0]
    for k, v in rates:
        acc += v
        if acc >= known / 2:
            median = k
            break
    us = sum(v * frame_us(k, length) for k, v in rates) + max(0, frames - known) * frame_us(median, length)
    return us, median


def airtime(ctx, since):
    """Per channel: how much of the time a sensor listened there each client's and each access point's data frames were on the
    air (clients: what they sent; access points: what they sent to their clients, plus their beacons)."""
    from . import beacons
    from .config import ch_to_freq
    hour0 = int(since // 3600) * 3600
    aps = {r["mac"]: r for r in ctx.rows("SELECT mac, ssid, channel, band, name, vendor, extra FROM devices WHERE kind='ap'")}
    dwell = {r["freq"]: (r["dwell"] or 0) / 1000 for r in ctx.rows(
        "SELECT freq, SUM(dwell_ms) dwell FROM channel_stats WHERE minute >= ? GROUP BY freq", (hour0,))}
    util = {r["freq"]: r for r in ctx.rows(
        "SELECT freq, SUM(airtime_us) air, SUM(dwell_ms) dwell FROM channel_stats WHERE minute >= ? GROUP BY freq", (hour0,))}
    per = {}   # (band, channel) -> mac -> {"us", "frames", "rates"...}
    for r in ctx.rows("SELECT * FROM link_stats WHERE hour >= ?", (hour0,)):
        ap = aps.get(r["bssid"])
        if not ap or not ap["channel"] or ap["band"] not in ("2.4", "5", "6"):
            continue
        us, median = airtime_us(r)
        who = r["mac"] if r["dir"] == "up" else r["bssid"]
        d = per.setdefault((ap["band"], ap["channel"]), {}).setdefault(who, {"us": 0.0, "frames": 0, "kind": "client" if r["dir"] == "up" else "ap",
                                                                             "medians": [], "assumed": False})
        d["us"] += us
        d["frames"] += r["frames"] or 0
        if median:
            d["medians"].append((median, r["frames"] or 0))
        d["assumed"] |= not r["bytes"]
    names = {}
    macs = {m for v in per.values() for m in v}
    if macs:
        names = {x["mac"]: x for x in ctx.rows(f"SELECT mac, kind, name, vendor, brand, model, ssid FROM devices WHERE mac IN ({','.join('?' * len(macs))})",
                                               list(macs))}
    out = []
    for (band, ch), devs in per.items():
        freq = ch_to_freq(ch, band)
        seconds = dwell.get(freq) or 0
        if not seconds:
            continue
        rows = []
        for mac, d in devs.items():
            share = d["us"] / (seconds * 1e6)
            if d["kind"] == "ap":   # and its beacons, about ten a second whether anyone listens or not
                try:
                    info = (json.loads(aps[mac]["extra"] or "{}").get("ap") or {})
                except ValueError:
                    info = {}
                share += beacons.airtime(info.get("beacon_len") or beacons.DEFAULT_LEN, info.get("basic_rate") or beacons.DEFAULT_RATE[band],
                                         info.get("beacon_tu") or beacons.DEFAULT_TU, band)
            med = max(d["medians"], key=lambda x: x[1])[0] if d["medians"] else None
            n = names.get(mac) or {}
            slow = share >= HOG_SHARE and med is not None and med <= SLOW_RATE
            rows.append({"mac": mac, "kind": d["kind"], "name": n.get("name") or " ".join(v for v in (n.get("brand"), n.get("model")) if v) or n.get("vendor"),
                         "ssid": n.get("ssid") if d["kind"] == "ap" else (aps.get(mac) or {}).get("ssid"), "share": round(min(share, 1.0), 4),
                         "frames": d["frames"], "median_rate": med, "assumed_size": d["assumed"], "slow": slow,
                         "at_100": round(share * med / 100, 4) if slow else None})
        rows.sort(key=lambda x: -x["share"])
        u = util.get(freq)
        out.append({"band": band, "channel": ch, "freq": freq, "listened_s": round(seconds), "devices": rows[:30],
                    "accounted": round(min(1.0, sum(x["share"] for x in rows)), 4),
                    "utilization": round(min(1.0, u["air"] / (u["dwell"] * 1000)), 4) if u and u["dwell"] else None})
    out.sort(key=lambda c: -c["accounted"])
    hogs = [{"band": c["band"], "channel": c["channel"], **d} for c in out for d in c["devices"] if d["slow"]]
    return {"channels": out, "slow": sorted(hogs, key=lambda x: -x["share"]), "hog_share": HOG_SHARE, "slow_rate": SLOW_RATE}


def routes(ctx):
    r = APIRouter()

    @r.get("/api/link")
    def link_clients(hours: float = 24, bssid: str = None, limit: int = 200, _=Depends(current_user)):
        """Every client's link quality in the last `hours` (of one access point with `bssid`), the worst first."""
        return {"clients": clients(ctx, time.time() - hours * 3600, bssid and bssid.lower())[:max(1, min(limit, 1000))], "min_frames": MIN_FRAMES}

    @r.get("/api/channels/airtime")
    def airtime_by_device(hours: float = 24, _=Depends(current_user)):
        """Per channel, the share of the listening time each client's and access point's data frames took, and the slow ones."""
        return airtime(ctx, time.time() - hours * 3600)

    @r.get("/api/link/{mac}")
    def link_client(mac: str, hours: float = 24, _=Depends(current_user)):
        """One client's rates, MCS and retries per direction, and what they point to."""
        if len(mac) > 64:
            raise HTTPException(400, "Not an address")
        return client_link(ctx, mac.lower(), time.time() - hours * 3600)

    return r
