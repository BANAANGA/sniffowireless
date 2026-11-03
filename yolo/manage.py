"""Admin management: ignore list, "my networks", device labels / watch list and device groups."""
import time
from contextlib import closing
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .auth import current_user, require_admin


class IgnoreSsid(BaseModel):
    ssid: str
    clients: bool = False


class IgnoreList(BaseModel):
    macs: List[str] = []
    prefixes: List[str] = []
    ssids: List[IgnoreSsid] = []
    purge: bool = False


class Networks(BaseModel):
    ssids: List[str] = []
    trusted_bssids: List[str] = []


class Meta(BaseModel):
    label: Optional[str] = None
    notes: Optional[str] = None
    known: Optional[bool] = None
    watch: Optional[bool] = None
    group_id: Optional[int] = None
    clear_group: bool = False


class Group(BaseModel):
    name: str
    kind: str = "person"
    notes: str = ""
    watch: bool = False


class Members(BaseModel):
    macs: List[str]


def _norm_mac(m):
    m = m.strip().lower().replace("-", ":")
    return m


def apply_ignore(ctx):
    ig = ctx.settings.get("ignore")
    known = [(r["mac"], r["ssid"]) for r in ctx.rows(
        "SELECT mac, ssid FROM devices WHERE kind='ap' AND ssid IN (%s)" % ",".join("?" * len(ig["ssids"])),
        [e["ssid"] for e in ig["ssids"]])] if ig["ssids"] else []
    ctx.store.set_ignore(ig["macs"], ig["prefixes"], ig["ssids"], known)


def apply_meta(ctx):
    rows = [(r["mac"], r["label"], r["known"], r["watch"], r["group_id"]) for r in ctx.rows(
        "SELECT mac, label, known, watch, group_id FROM device_meta")]
    groups = {r["id"]: r["name"] for r in ctx.rows("SELECT id, name FROM groups")}
    ctx.store.set_meta(rows, groups)


def matching_ignored(ctx, ig):
    """MACs currently stored that the ignore list covers (for purging)."""
    macs = set(ig["macs"])
    for p in ig["prefixes"]:
        macs |= {r["mac"] for r in ctx.rows("SELECT mac FROM devices WHERE mac LIKE ?", (p.lower().rstrip(":*") + "%",))}
    for e in ig["ssids"]:
        aps = [r["mac"] for r in ctx.rows("SELECT mac FROM devices WHERE kind='ap' AND ssid=?", (e["ssid"],))]
        macs |= set(aps)
        if e.get("clients") and aps:
            q = ",".join("?" * len(aps))
            macs |= {r["mac"] for r in ctx.rows(f"SELECT DISTINCT mac FROM sessions WHERE type='assoc' AND peer IN ({q})",
                                                 aps)}
    return macs


def routes(ctx):
    r = APIRouter()

    # ---------------------------------------------------------------- ignore
    @r.get("/api/settings/ignore")
    def get_ignore(_=Depends(current_user)):
        return ctx.settings.get("ignore")

    @r.put("/api/settings/ignore")
    def set_ignore(body: IgnoreList, _=Depends(require_admin)):
        ig = {"macs": sorted({_norm_mac(m) for m in body.macs if m.strip()}),
              "prefixes": sorted({_norm_mac(p).rstrip(":*") for p in body.prefixes if p.strip()}),
              "ssids": [{"ssid": e.ssid, "clients": e.clients} for e in body.ssids if e.ssid]}
        ctx.settings.set("ignore", ig)
        apply_ignore(ctx)
        purged = 0
        if body.purge:
            macs = matching_ignored(ctx, ig)
            purged = len(macs)
            if macs:
                ctx.store.command(lambda st: st.forget(macs))
        return {"ok": True, "purged": purged}

    @r.post("/api/settings/ignore/preview")
    def preview_ignore(body: IgnoreList, _=Depends(require_admin)):
        ig = {"macs": [_norm_mac(m) for m in body.macs], "prefixes": body.prefixes,
              "ssids": [e.dict() for e in body.ssids]}
        return {"devices": len(matching_ignored(ctx, ig))}

    # ------------------------------------------------------------- networks
    @r.get("/api/settings/networks")
    def get_networks(_=Depends(current_user)):
        n = ctx.settings.get("networks")
        if n["ssids"]:
            q = ",".join("?" * len(n["ssids"]))
            n["bssids"] = ctx.rows(f"SELECT mac, ssid, channel, band, enc, vendor, last_seen, last_rssi FROM devices "
                                   f"WHERE kind='ap' AND ssid IN ({q}) ORDER BY ssid, mac", n["ssids"])
        else:
            n["bssids"] = []
        return n

    @r.put("/api/settings/networks")
    def set_networks(body: Networks, _=Depends(require_admin)):
        ctx.settings.set("networks", {"ssids": sorted({s for s in body.ssids if s}),
                                      "trusted_bssids": sorted({_norm_mac(b) for b in body.trusted_bssids if b})})
        return {"ok": True}

    @r.get("/api/settings/{key}")
    def get_setting(key: str, _=Depends(current_user)):
        if key not in ("security", "report", "floorplan"):
            raise HTTPException(404)
        return ctx.settings.get(key)

    @r.put("/api/settings/{key}")
    def put_setting(key: str, body: dict, _=Depends(require_admin)):
        if key not in ("security", "report"):
            raise HTTPException(404)
        cur = ctx.settings.get(key)
        cur.update({k: v for k, v in body.items() if k in cur and k != "last_sent"})
        ctx.settings.set(key, cur)
        return cur

    # ----------------------------------------------------------- device meta
    @r.put("/api/devices/{mac}/meta")
    def set_meta(mac: str, body: Meta, _=Depends(require_admin)):
        mac = _norm_mac(mac)
        cur = ctx.one("SELECT * FROM device_meta WHERE mac=?", (mac,)) or {
            "label": None, "notes": None, "known": 0, "watch": 0, "group_id": None}
        for f in ("label", "notes"):
            v = getattr(body, f)
            if v is not None:
                cur[f] = v.strip() or None
        for f in ("known", "watch"):
            v = getattr(body, f)
            if v is not None:
                cur[f] = int(v)
        if body.clear_group:
            cur["group_id"] = None
        elif body.group_id is not None:
            if not ctx.one("SELECT id FROM groups WHERE id=?", (body.group_id,)):
                raise HTTPException(404, "group not found")
            cur["group_id"] = body.group_id
        if cur["group_id"] and not cur.get("known"):
            cur["known"] = 1
        ctx.execute("INSERT OR REPLACE INTO device_meta(mac, label, notes, known, watch, group_id, updated) "
                    "VALUES(?,?,?,?,?,?,?)", (mac, cur["label"], cur["notes"], cur["known"], cur["watch"],
                                              cur["group_id"], time.time()))
        apply_meta(ctx)
        if cur["known"]:  # a tag marked as yours is no longer a suspected tracker
            ctx.execute("UPDATE findings SET status='resolved' WHERE key=?", (f"tracker:{mac}",))
            if ctx.security:
                ctx.security.status[f"tracker:{mac}"] = "resolved"
        return cur

    @r.post("/api/devices/known")
    def bulk_known(body: Members, _=Depends(require_admin)):
        with closing(ctx.wdb()) as c:
            for m in body.macs:
                m = _norm_mac(m)
                c.execute("INSERT INTO device_meta(mac, known, updated) VALUES(?,1,?) ON CONFLICT(mac) DO UPDATE "
                          "SET known=1, updated=excluded.updated", (m, time.time()))
        apply_meta(ctx)
        return {"ok": True, "count": len(body.macs)}

    @r.get("/api/devices/{mac}/suggestions")
    def suggestions(mac: str, _=Depends(current_user)):
        """Other MACs that are probably the same physical device: same probe fingerprint (or same
        BLE name) and never present at the same time as this one (typical of MAC rotation)."""
        mac = _norm_mac(mac)
        d = ctx.one("SELECT mac, kind, fp_hash, name, dev_type FROM devices WHERE mac=?", (mac,))
        if not d:
            raise HTTPException(404)
        if d["fp_hash"]:
            cands = ctx.rows("SELECT d.mac, d.first_seen, d.last_seen, d.name, d.dev_type, d.brand, m.group_id "
                             "FROM devices d LEFT JOIN device_meta m ON m.mac=d.mac "
                             "WHERE d.fp_hash=? AND d.mac != ? ORDER BY d.last_seen DESC LIMIT 200",
                             (d["fp_hash"], mac))
            why = "same probe fingerprint"
        elif d["name"]:
            cands = ctx.rows("SELECT d.mac, d.first_seen, d.last_seen, d.name, d.dev_type, d.brand, m.group_id "
                             "FROM devices d LEFT JOIN device_meta m ON m.mac=d.mac WHERE d.name=? AND d.kind=? "
                             "AND d.mac != ? ORDER BY d.last_seen DESC LIMIT 200", (d["name"], d["kind"], mac))
            why = "same name"
        else:
            return []
        mine = [(s["start_ts"], s["end_ts"]) for s in ctx.rows(
            "SELECT start_ts, end_ts FROM sessions WHERE mac=? AND type='presence'", (mac,))]
        out = []
        for cnd in cands:
            theirs = [(s["start_ts"], s["end_ts"]) for s in ctx.rows(
                "SELECT start_ts, end_ts FROM sessions WHERE mac=? AND type='presence'", (cnd["mac"],))]
            overlap = sum(max(0, min(a1, b1) - max(a0, b0)) for a0, a1 in mine for b0, b1 in theirs)
            if overlap > 120:  # seen simultaneously -> a different device
                continue
            gap = min((abs(b0 - a1) for _, a1 in mine for b0, _ in theirs), default=None)
            cnd["reason"] = why
            cnd["gap"] = gap
            out.append(cnd)
        out.sort(key=lambda c: c["gap"] if c["gap"] is not None else 1e12)
        return out[:25]

    # ---------------------------------------------------------------- groups
    @r.get("/api/groups")
    def groups(_=Depends(current_user)):
        now = time.time()
        gs = ctx.rows("SELECT g.*, COUNT(m.mac) members, MAX(d.last_seen) last_seen, "
                      "SUM(d.last_seen >= ?) present FROM groups g LEFT JOIN device_meta m ON m.group_id=g.id "
                      "LEFT JOIN devices d ON d.mac=m.mac GROUP BY g.id ORDER BY g.name",
                      (now - ctx.cfg.active_window,))
        return gs

    @r.post("/api/groups")
    def create_group(body: Group, _=Depends(require_admin)):
        if not body.name.strip():
            raise HTTPException(400, "name required")
        with closing(ctx.wdb()) as c:
            gid = c.execute("INSERT INTO groups(name, kind, notes, watch, created) VALUES(?,?,?,?,?)",
                            (body.name.strip(), body.kind, body.notes, int(body.watch), time.time())).lastrowid
        apply_meta(ctx)
        return {"id": gid}

    @r.put("/api/groups/{gid}")
    def update_group(gid: int, body: Group, _=Depends(require_admin)):
        ctx.execute("UPDATE groups SET name=?, kind=?, notes=?, watch=? WHERE id=?",
                    (body.name.strip(), body.kind, body.notes, int(body.watch), gid))
        apply_meta(ctx)
        return {"ok": True}

    @r.delete("/api/groups/{gid}")
    def delete_group(gid: int, _=Depends(require_admin)):
        with closing(ctx.wdb()) as c:
            c.execute("UPDATE device_meta SET group_id=NULL WHERE group_id=?", (gid,))
            c.execute("DELETE FROM groups WHERE id=?", (gid,))
        apply_meta(ctx)
        return {"ok": True}

    @r.post("/api/groups/{gid}/members")
    def add_members(gid: int, body: Members, _=Depends(require_admin)):
        if not ctx.one("SELECT id FROM groups WHERE id=?", (gid,)):
            raise HTTPException(404)
        with closing(ctx.wdb()) as c:
            for m in body.macs:
                c.execute("INSERT INTO device_meta(mac, known, group_id, updated) VALUES(?,1,?,?) ON CONFLICT(mac) "
                          "DO UPDATE SET group_id=excluded.group_id, known=1, updated=excluded.updated",
                          (_norm_mac(m), gid, time.time()))
        apply_meta(ctx)
        return {"ok": True}

    @r.get("/api/groups/{gid}")
    def group(gid: int, hours: float = 168, _=Depends(current_user)):
        g = ctx.one("SELECT * FROM groups WHERE id=?", (gid,))
        if not g:
            raise HTTPException(404)
        since = time.time() - hours * 3600
        g["members"] = ctx.rows("SELECT d.*, m.label FROM device_meta m JOIN devices d ON d.mac=m.mac "
                                "WHERE m.group_id=? ORDER BY d.last_seen DESC", (gid,))
        for m in g["members"]:
            ctx.jsonf(m, "ident", "extra")
        macs = [m["mac"] for m in g["members"]]
        sess = []
        if macs:
            q = ",".join("?" * len(macs))
            sess = ctx.rows(f"SELECT s.*, a.ssid peer_ssid FROM sessions s LEFT JOIN devices a ON a.mac=s.peer "
                            f"WHERE s.mac IN ({q}) AND s.end_ts >= ? ORDER BY s.start_ts", macs + [since])
        # Union of member presence = when the person/thing was around.
        spans = sorted((s["start_ts"], s["end_ts"]) for s in sess if s["type"] == "presence")
        merged = []
        for a, b in spans:
            if merged and a <= merged[-1][1] + 60:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        g["presence"] = merged
        g["sessions"] = sess
        g["events"] = ctx.rows(f"SELECT e.*, d.kind, d.name, m.label, p.ssid peer_ssid FROM events e "
                               f"LEFT JOIN devices d ON d.mac=e.mac LEFT JOIN device_meta m ON m.mac=e.mac "
                               f"LEFT JOIN devices p ON p.mac=e.peer WHERE e.mac IN ({','.join('?' * len(macs))}) "
                               f"ORDER BY e.id DESC LIMIT 100", macs) if macs else []
        g["since"], g["now"] = since, time.time()
        return g

    return r
