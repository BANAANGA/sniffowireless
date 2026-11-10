"""Settings -> Privacy: hashed MAC storage (macprivacy.py) and how long data is kept (Store.prune)."""
import os
import time
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from . import macprivacy
from .auth import require_admin

# kind -> (label, what is deleted when it is older than that)
RETENTION_KINDS = {
    "devices": ("Devices", "A device that was not heard for this long is forgotten. Labelled, grouped and watched devices are kept."),
    "history": ("Signal history and presence", "The minute-by-minute signal strength and the hourly presence behind the graphs."),
    "events": ("Events", "Arrived / left / connected / security events. (The alert history follows the general limit.)"),
    "sessions": ("Sessions", "When a device was present or connected to a network."),
    "probes": ("Probed networks", "Which network names a device asked for: it can show where a person has been."),
    "sightings": ("Where devices were heard", "Which sensor (room) last heard a device."),
}
MAX_DAYS = 3650


class StorageBody(BaseModel):
    hash_macs: bool
    scope: Optional[str] = "static"


class RetentionBody(BaseModel):
    days: Dict[str, int]


def is_static(mac, scope="static"):
    raw = macprivacy._parse((mac or "").lower())
    return bool(raw) and not raw[0] & 1 and (scope == "all" or not raw[0] & 2)


def routes(ctx):
    r = APIRouter()
    cfg, store = ctx.cfg, ctx.store

    def files_in(sub):
        d = os.path.join(cfg.data_dir, sub)
        try:
            return sum(1 for f in os.listdir(d) if not f.startswith("."))
        except OSError:
            return 0

    def storage():
        p, h = ctx.settings.get("privacy"), store.macpriv
        scope = h.scope if h else (p.get("hash_scope") or "static")
        unhashed = None
        try:
            known = {x["pseud"] for x in ctx.rows("SELECT pseud FROM mac_alias")} if h else set()
            unhashed = sum(1 for x in ctx.rows("SELECT mac FROM devices") if is_static(x["mac"], scope) and x["mac"] not in known)
        except Exception:
            pass
        return {"hash_macs": h is not None, "forced": bool(cfg.hash_macs), "scope": scope,
                "aliases": h.count() if h else 0, "unhashed_devices": unhashed,
                "key": macprivacy.key_source(cfg.data_dir, cfg.privacy_key) if h else None,
                "pending_existing": bool(p.get("hash_existing")), "hashed_at": p.get("hashed_at"),
                "handshakes": files_in("handshakes"), "backups": files_in("backups")}

    @r.get("/api/privacy/storage")
    def get_storage(_=Depends(require_admin)):
        return storage()

    @r.put("/api/privacy/storage")
    def put_storage(body: StorageBody, _=Depends(require_admin)):
        scope = body.scope or "static"
        if scope not in macprivacy.SCOPES:
            raise HTTPException(400, "scope must be static or all")
        if not body.hash_macs and cfg.hash_macs:
            raise HTTPException(400, "Privacy mode is forced on by HASH_MACS=1; remove that setting to switch it off")
        p = dict(ctx.settings.get("privacy"))
        p.update(hash_macs=body.hash_macs, hash_scope=scope)
        ctx.settings.set("privacy", p)
        if body.hash_macs:
            store.enable_macprivacy(scope)
        else:
            store.disable_macprivacy()
        from .manage import apply_ignore
        apply_ignore(ctx)  # the ignore list is rebuilt with (or without) hashed addresses
        return storage()

    @r.post("/api/privacy/storage/hash-existing")
    def hash_existing(_=Depends(require_admin)):
        if store.macpriv is None:
            raise HTTPException(400, "Switch privacy mode on first")
        p = dict(ctx.settings.get("privacy"))
        p["hash_existing"] = True
        ctx.settings.set("privacy", p)
        return {**storage(), "restart_required": True}

    @r.get("/api/retention")
    def get_retention(_=Depends(require_admin)):
        cur = ctx.settings.get("retention")
        try:
            size = os.path.getsize(cfg.db_path)
        except OSError:
            size = 0
        return {"default": cfg.retention_days, "db_bytes": size,
                "kinds": [{"kind": k, "label": label, "hint": hint, "days": int(cur.get(k) or 0),
                           "effective": int(cur.get(k) or 0) or cfg.retention_days} for k, (label, hint) in RETENTION_KINDS.items()]}

    @r.put("/api/retention")
    def put_retention(body: RetentionBody, _=Depends(require_admin)):
        out = {}
        for k, d in body.days.items():
            if k not in RETENTION_KINDS:
                raise HTTPException(400, f"unknown kind {k!r}")
            if d < 0 or d > MAX_DAYS:
                raise HTTPException(400, f"{RETENTION_KINDS[k][0]}: 1 to {MAX_DAYS} days (0 for the default)")
            out[k] = d
        cur = dict(ctx.settings.get("retention"))
        cur.update(out)
        ctx.settings.set("retention", cur)
        store.set_retention(cur)
        return get_retention()

    @r.post("/api/retention/run")
    def run_cleanup(_=Depends(require_admin)):
        store.command(lambda st: st.prune(time.time()))  # on the thread that owns the database connection
        return {"ok": True}

    return r
