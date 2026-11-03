"""Guess which Bluetooth address and which Wi-Fi address belong to the same physical device (a phone, tablet or
laptop has both radios), and let the user confirm ("link") or reject the pairing.

Signals, per candidate pair:
* co-presence: Jaccard overlap of the minutes both were heard (samples table)
* arrivals / departures at the same time
* signal strength moving together (Pearson correlation of per-minute RSSI)
* adjacent public MAC addresses (vendors usually allocate Wi-Fi and Bluetooth MACs next to each other)
* similar names (Bluetooth name "Sam's iPhone" vs DHCP hostname "Sams-iPhone")
* the same brand (and a different known brand is strong evidence against)
Companion devices that also move with a phone (earbuds, watches, tags, bikes) are not candidates.
"""
import math
import re
import time
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .auth import current_user, require_admin
from .sanitize import clean_mac

SCHEMA = """
CREATE TABLE IF NOT EXISTS device_links(
  mac_a TEXT NOT NULL, mac_b TEXT NOT NULL, status TEXT NOT NULL, score REAL, created REAL,
  PRIMARY KEY(mac_a, mac_b)) WITHOUT ROWID;
"""
DAYS = 7
MIN_MINUTES = 20            # a device must have been heard for at least this many minutes in the window
COMPANION_TYPES = {"headphones", "watch", "wearable", "tag", "bike", "speaker", "input", "sensor", "car", "light",
                   "beacon", "iot", "tv", "printer", "smart_home", "router", "network", "media", "streaming"}
EDGE_SLACK = 300            # arrival / departure within 5 minutes counts as together


def pair(a, b):
    return (a, b) if a < b else (b, a)


def norm_name(s):
    s = (s or "").lower().replace("’", "'")
    s = re.sub(r"'s\b", "s", s)
    return re.sub(r"[^a-z0-9]", "", s)


def name_score(a, b):
    na, nb = norm_name(a), norm_name(b)
    if len(na) < 4 or len(nb) < 4:
        return 0.0
    if na == nb:
        return 1.0
    if na in nb or nb in na:
        return 0.7 if min(len(na), len(nb)) >= 6 else 0.4
    return 0.0


def mac_adjacent(a, b):
    """Public MACs from the same OUI within a few addresses of each other."""
    if a[:8] != b[:8] or int(a[:2], 16) & 0x02 or int(b[:2], 16) & 0x02:
        return False
    return 0 < abs(int(a.replace(":", ""), 16) - int(b.replace(":", ""), 16)) <= 4


def pearson(xs, ys):
    n = len(xs)
    if n < 15:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    sx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    sy = math.sqrt(sum((y - my) ** 2 for y in ys))
    if sx < 1e-6 or sy < 1e-6:
        return None
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / (sx * sy)


def edges(spans):
    return [a for a, _ in spans], [b for _, b in spans]


def load(ctx, since):
    """Candidate devices with their per-minute presence/RSSI and presence spans."""
    devs = {d["mac"]: d for d in ctx.rows(
        "SELECT d.mac, d.kind, d.name, d.vendor, d.brand, d.dev_type, d.randomized, d.ip, d.last_seen, m.label, "
        "m.group_id FROM devices d LEFT JOIN device_meta m ON m.mac=d.mac WHERE d.last_seen >= ? AND "
        "(d.kind IN ('ble', 'bt_classic') OR d.kind = 'wifi_client')", (since,))}
    devs = {m: d for m, d in devs.items() if (d["dev_type"] or "") not in COMPANION_TYPES}
    minutes, rssi, spans = defaultdict(set), defaultdict(dict), defaultdict(list)
    macs = list(devs)
    for i in range(0, len(macs), 500):  # only candidate devices, in chunks (SQLite parameter limit)
        chunk = macs[i:i + 500]
        q = ",".join("?" * len(chunk))
        for r in ctx.rows(f"SELECT mac, minute, rssi_sum, rssi_count FROM samples WHERE minute >= ? AND mac IN ({q})",
                          [since] + chunk):
            minutes[r["mac"]].add(r["minute"])
            if r["rssi_count"]:
                rssi[r["mac"]][r["minute"]] = r["rssi_sum"] / r["rssi_count"]
        for r in ctx.rows(f"SELECT mac, start_ts, end_ts FROM sessions WHERE type='presence' AND end_ts >= ? "
                          f"AND mac IN ({q})", [since] + chunk):
            spans[r["mac"]].append((r["start_ts"], r["end_ts"]))
    devs = {m: d for m, d in devs.items() if len(minutes[m]) >= MIN_MINUTES}
    return devs, minutes, rssi, spans


def score_pair(bt, wf, minutes, rssi, spans):
    a, b = minutes[bt["mac"]], minutes[wf["mac"]]
    inter = len(a & b)
    if not inter:
        return None
    jac = inter / len(a | b)
    reasons = []
    s = 0.55 * jac
    reasons.append(f"present together {jac:.0%} of their time")
    sa, sb = edges(spans[bt["mac"]]), edges(spans[wf["mac"]])
    together = sum(1 for t in sa[0] if any(abs(t - u) <= EDGE_SLACK for u in sb[0])) + \
        sum(1 for t in sa[1] if any(abs(t - u) <= EDGE_SLACK for u in sb[1]))
    total = len(sa[0]) + len(sa[1])
    if total:
        s += 0.15 * together / total
        if together >= 2:
            reasons.append(f"arrived/left together {together}×")
    shared = sorted(set(rssi[bt["mac"]]) & set(rssi[wf["mac"]]))
    corr = pearson([rssi[bt["mac"]][m] for m in shared], [rssi[wf["mac"]][m] for m in shared])
    if corr is not None:
        s += 0.15 * max(0.0, corr)
        if corr >= 0.4:
            reasons.append(f"signal moves together (r={corr:.2f})")
    if mac_adjacent(bt["mac"], wf["mac"]):
        s += 0.4
        reasons.append("adjacent hardware addresses")
    ns = max(name_score(bt["name"], wf["name"]), name_score(bt["label"], wf["label"]))
    if ns:
        s += 0.35 * ns
        reasons.append(f"similar names ({bt['name'] or bt['label']} / {wf['name'] or wf['label']})")
    if bt["brand"] and wf["brand"]:
        if bt["brand"].split(" ")[0] == wf["brand"].split(" ")[0]:
            s += 0.05
            reasons.append(f"both {bt['brand']}")
        else:
            s -= 0.5
            reasons.append(f"different brands ({bt['brand']} / {wf['brand']})")
    if bt["dev_type"] and wf["dev_type"] and bt["dev_type"] != wf["dev_type"]:
        s -= 0.15
    s = max(0.0, min(1.0, s))
    return {"score": round(s, 3), "jaccard": round(jac, 3), "rssi_corr": None if corr is None else round(corr, 2),
            "together": together, "reasons": reasons,
            "level": "high" if s >= 0.7 else "medium" if s >= 0.45 else "low"}


def suggestions(ctx, mac=None, limit=50, min_score=0.3):
    now = time.time()
    since = now - DAYS * 86400
    devs, minutes, rssi, spans = load(ctx, since)
    decided = {(r["mac_a"], r["mac_b"]): r["status"] for r in ctx.rows("SELECT mac_a, mac_b, status FROM device_links")}
    linked_macs = {m for k, st in decided.items() if st == "linked" for m in k}
    bts = [d for d in devs.values() if d["kind"] in ("ble", "bt_classic")]
    wfs = [d for d in devs.values() if d["kind"] == "wifi_client"]
    if mac:
        bts = [d for d in bts if d["mac"] == mac] or bts
        wfs = [d for d in wfs if d["mac"] == mac] or wfs
        if mac not in devs:
            return []
    out = []
    for bt in bts:
        for wf in wfs:
            if mac and mac not in (bt["mac"], wf["mac"]):
                continue
            key = pair(bt["mac"], wf["mac"])
            if key in decided:
                continue
            if not mac and (bt["mac"] in linked_macs or wf["mac"] in linked_macs):
                continue  # already matched elsewhere
            sc = score_pair(bt, wf, minutes, rssi, spans)
            if sc and sc["score"] >= min_score:
                out.append({"bt": brief(bt), "wifi": brief(wf), **sc})
    out.sort(key=lambda x: -x["score"])
    if not mac:  # each device in its single best pairing only
        used, best = set(), []
        for x in out:
            if x["bt"]["mac"] in used or x["wifi"]["mac"] in used:
                continue
            used |= {x["bt"]["mac"], x["wifi"]["mac"]}
            best.append(x)
        out = best
    return out[:limit]


def brief(d):
    return {k: d.get(k) for k in ("mac", "kind", "name", "label", "vendor", "brand", "dev_type", "randomized", "ip",
                                  "last_seen", "group_id")}


def links_for(ctx, mac):
    rows = ctx.rows("SELECT mac_a, mac_b, status, score, created FROM device_links WHERE (mac_a=? OR mac_b=?) "
                    "AND status='linked'", (mac, mac))
    out = []
    for r in rows:
        other = r["mac_b"] if r["mac_a"] == mac else r["mac_a"]
        d = ctx.one("SELECT d.mac, d.kind, d.name, d.vendor, d.brand, d.dev_type, d.ip, d.last_seen, m.label FROM devices d "
                    "LEFT JOIN device_meta m ON m.mac=d.mac WHERE d.mac=?", (other,)) or {"mac": other}
        out.append({**d, "score": r["score"], "created": r["created"]})
    return out


class LinkBody(BaseModel):
    a: str = Field(max_length=17)
    b: str = Field(max_length=17)
    status: str = Field("linked", pattern="^(linked|rejected)$")
    score: Optional[float] = Field(None, ge=0, le=1)


def routes(ctx):
    r = APIRouter()

    cache = {"at": 0, "data": None}

    @r.get("/api/matching")
    def all_suggestions(_=Depends(current_user)):
        if cache["data"] is None or time.time() - cache["at"] > 60:
            cache["data"], cache["at"] = suggestions(ctx), time.time()
        linked = ctx.rows("SELECT mac_a, mac_b, score, created FROM device_links WHERE status='linked' ORDER BY created DESC")
        named = []
        for x in linked:
            info = {m: ctx.one("SELECT d.mac, d.kind, d.name, d.vendor, d.brand, d.dev_type, d.ip, d.last_seen, m.label "
                               "FROM devices d LEFT JOIN device_meta m ON m.mac=d.mac WHERE d.mac=?", (m,)) or {"mac": m}
                    for m in (x["mac_a"], x["mac_b"])}
            bt = next((v for v in info.values() if v.get("kind") in ("ble", "bt_classic")), info[x["mac_a"]])
            wf = info[x["mac_b"]] if bt is info[x["mac_a"]] else info[x["mac_a"]]
            named.append({"bt": bt, "wifi": wf, "score": x["score"], "created": x["created"]})
        decided = {(r["mac_a"], r["mac_b"]) for r in ctx.rows("SELECT mac_a, mac_b FROM device_links")}
        fresh = [x for x in cache["data"] if pair(x["bt"]["mac"], x["wifi"]["mac"]) not in decided]
        return {"suggestions": fresh, "linked": named, "days": DAYS}

    @r.get("/api/devices/{mac}/matches")
    def device_matches(mac: str, _=Depends(current_user)):
        m = clean_mac(mac)
        if not m:
            raise HTTPException(400, "invalid MAC address")
        return {"linked": links_for(ctx, m), "suggestions": suggestions(ctx, m, limit=5, min_score=0.25)}

    @r.post("/api/links")
    def set_link(body: LinkBody, _=Depends(require_admin)):
        a, b = clean_mac(body.a), clean_mac(body.b)
        if not a or not b or a == b:
            raise HTTPException(400, "two different MAC addresses required")
        ka, kb = pair(a, b)
        ctx.execute("INSERT OR REPLACE INTO device_links(mac_a, mac_b, status, score, created) VALUES(?,?,?,?,?)",
                    (ka, kb, body.status, body.score, time.time()))
        if body.status == "linked":
            # Linked devices belong to the same person/thing: share group membership and the "known" flag.
            metas = {m: ctx.one("SELECT * FROM device_meta WHERE mac=?", (m,)) for m in (a, b)}
            gid = next((x["group_id"] for x in metas.values() if x and x["group_id"]), None)
            known = any(x and x["known"] for x in metas.values())
            for m in (a, b):
                ctx.execute("INSERT INTO device_meta(mac, known, group_id, updated) VALUES(?,?,?,?) ON CONFLICT(mac) DO "
                            "UPDATE SET group_id=COALESCE(device_meta.group_id, excluded.group_id), "
                            "known=MAX(device_meta.known, excluded.known), updated=excluded.updated",
                            (m, int(known), gid, time.time()))
            from .manage import apply_meta
            apply_meta(ctx)
        return {"ok": True}

    @r.delete("/api/links/{a}/{b}")
    def delete_link(a: str, b: str, _=Depends(require_admin)):
        a, b = clean_mac(a), clean_mac(b)
        if not a or not b:
            raise HTTPException(400, "invalid MAC address")
        ctx.execute("DELETE FROM device_links WHERE mac_a=? AND mac_b=?", pair(a, b))
        return {"ok": True}

    return r
