"""Global search across all records: devices, groups, networks, probed SSIDs, DNS lookups, events, alerts,
security findings and sensors."""
import re
import time

from fastapi import APIRouter, Depends

from .auth import current_user

SECTIONS = ("devices", "groups", "networks", "probes", "dns", "events", "alerts", "findings", "sensors")
MAC_CHARS = re.compile(r"^[0-9a-fA-F:.\-]+$")


def _like(q):
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def search(ctx, q, limit=8, sections=SECTIONS):
    q = q.strip()
    out = {s: [] for s in sections}
    if len(q) < 2:
        return {"q": q, "results": out, "total": 0}
    like = _like(q)
    # "aabbcc", "aa-bb-cc" or "aa.bb.cc" also match MACs stored as "aa:bb:cc".
    hexq = re.sub(r"[^0-9a-f]", "", q.lower())
    mac_like = _like(":".join(hexq[i:i + 2] for i in range(0, len(hexq), 2))) \
        if MAC_CHARS.match(q) and len(hexq) >= 4 else like
    e = " ESCAPE '\\'"

    def rows(sql, params):
        return ctx.rows(sql + " LIMIT ?", list(params) + [limit + 1])

    if "devices" in sections:
        cols = ["d.name", "d.ssid", "d.vendor", "d.brand", "d.model", "d.ip", "d.os", "m.label", "m.notes"]
        where = " OR ".join(f"{c} LIKE ?{e}" for c in cols) + f" OR d.mac LIKE ?{e}"
        out["devices"] = rows(
            "SELECT d.mac, d.kind, d.name, d.ssid, d.vendor, d.ip, d.last_seen, d.dev_type, d.ident, m.label, m.notes "
            f"FROM devices d LEFT JOIN device_meta m ON m.mac = d.mac WHERE {where} "
            "ORDER BY (m.label IS NOT NULL) DESC, d.last_seen DESC", [like] * len(cols) + [mac_like])
        for d in out["devices"]:
            ctx.jsonf(d, "ident")
            d["ident"] = (d["ident"] or {}).get("label")
    if "groups" in sections:
        out["groups"] = rows(f"SELECT id, name, kind, notes FROM groups WHERE name LIKE ?{e} OR notes LIKE ?{e} "
                             "ORDER BY name", [like, like])
    if "networks" in sections:
        out["networks"] = rows(f"SELECT ssid, COUNT(*) aps, MAX(last_seen) last_seen, GROUP_CONCAT(DISTINCT enc) enc "
                               f"FROM devices WHERE kind='ap' AND ssid LIKE ?{e} GROUP BY ssid ORDER BY last_seen DESC",
                               [like])
    if "probes" in sections:
        out["probes"] = rows(f"SELECT ssid, COUNT(DISTINCT mac) devices, MAX(last_seen) last_seen FROM probes "
                             f"WHERE ssid LIKE ?{e} GROUP BY ssid ORDER BY devices DESC", [like])
    if "dns" in sections:
        out["dns"] = rows(f"SELECT name, COUNT(DISTINCT mac) devices, MAX(last_seen) last_seen FROM lan_dns "
                          f"WHERE name LIKE ?{e} GROUP BY name ORDER BY devices DESC, last_seen DESC", [like])
    if "events" in sections:
        out["events"] = rows(
            "SELECT e.id, e.ts, e.mac, e.type, e.peer, e.detail, d.kind, d.name, d.ssid, d.vendor, m.label "
            "FROM events e LEFT JOIN devices d ON d.mac = e.mac LEFT JOIN device_meta m ON m.mac = e.mac "
            f"WHERE e.detail LIKE ?{e} OR e.type LIKE ?{e} OR e.mac LIKE ?{e} OR e.peer LIKE ?{e} OR m.label LIKE ?{e} "
            "ORDER BY e.id DESC", [like, like, mac_like, mac_like, like])
    if "alerts" in sections:
        out["alerts"] = rows(f"SELECT id, ts, mac, type, title, severity FROM alert_log WHERE title LIKE ?{e} "
                             f"OR body LIKE ?{e} OR rule_name LIKE ?{e} OR mac LIKE ?{e} ORDER BY id DESC",
                             [like, like, like, mac_like])
    if "findings" in sections:
        out["findings"] = rows(f"SELECT id, type, severity, mac, ssid, title, status, last_seen FROM findings "
                               f"WHERE title LIKE ?{e} OR detail LIKE ?{e} OR ssid LIKE ?{e} OR mac LIKE ?{e} "
                               "ORDER BY status = 'resolved', last_seen DESC", [like, like, like, mac_like])
    if "sensors" in sections:
        out["sensors"] = rows(f"SELECT id, name, room, last_seen FROM sensors WHERE id LIKE ?{e} OR name LIKE ?{e} "
                              f"OR room LIKE ?{e} ORDER BY name", [like, like, like])
    more = {}
    for s, lst in out.items():
        more[s] = len(lst) > limit
        out[s] = lst[:limit]
    return {"q": q, "results": out, "more": more, "total": sum(len(v) for v in out.values())}


def routes(ctx):
    r = APIRouter()

    @r.get("/api/search")
    def api_search(q: str = "", limit: int = 8, section: str = None, _=Depends(current_user)):
        secs = (section,) if section in SECTIONS else SECTIONS
        t0 = time.time()
        res = search(ctx, q, max(1, min(limit, 200)), secs)
        res["ms"] = round((time.time() - t0) * 1000)
        return res

    return r
