"""Backup and restore.

* Configuration backup (JSON): settings, labels/groups, alert rules, notification channels (secrets only on
  request), sensors and users (password hashes). Restoring it replaces those tables and applies immediately.
* Full backup (.tar.gz): a consistent SQLite snapshot (online backup API, safe while sniffowireless is running) plus
  uploaded files (floor plan). Restoring it is staged and applied on the next start; the API then restarts
  the process (Docker's restart policy brings it back).
* Scheduled backups into DATA_DIR/backups with retention.
"""
import gzip
import io
import json
import logging
import os
import re
import shutil
import signal
import sqlite3
import tarfile
import tempfile
import threading
import time
from contextlib import closing

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from . import __version__
from .alerts import SECRET_FIELDS
from .auth import require_admin
from .sanitize import clean_json
from .settings import DEFAULTS

log = logging.getLogger("sniffowireless.backup")

FORMAT = "sniffowireless-config"
CONFIG_TABLES = ["device_meta", "groups", "alert_rules", "notifiers", "sensors"]  # settings (incl. investigate) too
STAGED = "restore-pending.tar.gz"
LEGACY_DB_MEMBER, LEGACY_FORMAT = "yolo.db", "yolo-full"  # from before the yolo -> sniffowireless rename
NAME_RX = re.compile(r"^sniffowireless-\d{8}-\d{6}\.tar\.gz$")


class BackupSettings(BaseModel):
    enabled: bool = False
    hour: int = Field(3, ge=0, le=23)
    keep: int = Field(7, ge=1, le=365)


def backups_dir(cfg):
    d = os.path.join(cfg.data_dir, "backups")
    os.makedirs(d, exist_ok=True)
    return d


# ------------------------------------------------------------------ config
def export_config(ctx, include_secrets=False, include_users=True):
    out = {"format": FORMAT, "version": 1, "app_version": __version__, "created": time.time(),
           "settings": {}, "tables": {}}
    with closing(ctx.db()) as c:
        for k, v in c.execute("SELECT key, value FROM settings"):
            out["settings"][k] = json.loads(v)
        for t in CONFIG_TABLES:
            rows = [dict(r) for r in c.execute(f"SELECT * FROM {t}")]
            if t == "sensors":
                for r in rows:
                    r["token_id"] = None  # tokens aren't exported; re-create them on the new server
            if t == "notifiers":
                for r in rows:
                    cfg = json.loads(r["config"] or "{}")
                    if not include_secrets:
                        cfg = {k: v for k, v in cfg.items() if k not in SECRET_FIELDS}
                    r["config"] = json.dumps(cfg)
            out["tables"][t] = rows
        if include_users:
            out["tables"]["users"] = [dict(r) for r in c.execute(
                "SELECT id, username, pw_hash, role, created, from_env FROM users")]
    out["settings"].get("report", {}).pop("last_sent", None)
    out["includes_secrets"] = include_secrets
    return out


def import_config(ctx, data):
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise ValueError("Not a sniffowireless configuration backup")
    tables = data.get("tables") or {}
    with closing(ctx.wdb()) as c:
        known_cols = {t: {r[1] for r in c.execute(f"PRAGMA table_info({t})")} for t in CONFIG_TABLES + ["users"]}
        c.execute("BEGIN")
        try:
            for k, v in (data.get("settings") or {}).items():
                if k in DEFAULTS and isinstance(v, dict):  # only known settings, bounded values
                    c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)", (k, json.dumps(clean_json(v))))
            for t in CONFIG_TABLES + ["users"]:
                if t not in tables:
                    continue
                rows = tables[t]
                if t == "users" and not rows:
                    continue  # never lock everyone out
                if t == "notifiers":  # keep secrets that weren't exported
                    old = {r[0]: json.loads(r[1] or "{}") for r in c.execute("SELECT id, config FROM notifiers")}
                    for r in rows:
                        cfg = json.loads(r.get("config") or "{}")
                        for k, v in old.get(r.get("id"), {}).items():
                            if k in SECRET_FIELDS and k not in cfg:
                                cfg[k] = v
                        r["config"] = json.dumps(cfg)
                c.execute(f"DELETE FROM {t}" if t != "sensors" else "DELETE FROM sensors WHERE id != 'local'")
                for r in rows:
                    cols = [k for k in r if k in known_cols[t]]
                    c.execute(f"INSERT OR REPLACE INTO {t}({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
                              [r[k] for k in cols])
                if t == "users":
                    c.execute("DELETE FROM auth_sessions WHERE user_id NOT IN (SELECT id FROM users)")
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
    # reload everything that caches configuration
    ctx.settings.cache.clear()
    with closing(ctx.db()) as c:
        for k, v in c.execute("SELECT key, value FROM settings"):
            ctx.settings.cache[k] = json.loads(v)
    from .manage import apply_ignore, apply_meta
    apply_ignore(ctx)
    apply_meta(ctx)
    ctx.alerts.invalidate()
    ctx.security.reload()
    ctx.location.reload()
    ctx.lan.reload()
    if ctx.investigate:
        ctx.investigate.reload()
    return {t: len(tables.get(t) or []) for t in CONFIG_TABLES + ["users"] if t in tables}


# -------------------------------------------------------------------- full
def create_full_backup(ctx, dest_dir=None):
    """Write a .tar.gz with a consistent database snapshot and uploaded files; returns its path."""
    dest_dir = dest_dir or backups_dir(ctx.cfg)
    name = time.strftime("sniffowireless-%Y%m%d-%H%M%S.tar.gz")
    path = os.path.join(dest_dir, name)
    with tempfile.TemporaryDirectory(dir=ctx.cfg.data_dir) as tmp:
        snap = os.path.join(tmp, "sniffowireless.db")
        src = sqlite3.connect(ctx.cfg.db_path, timeout=30)
        dst = sqlite3.connect(snap)
        with dst:
            src.backup(dst)  # consistent even while the writer thread is active
        src.close()
        dst.close()
        manifest = {"format": "sniffowireless-full", "app_version": __version__, "created": time.time()}
        with tarfile.open(path + ".part", "w:gz") as tar:
            tar.add(snap, arcname="sniffowireless.db")
            for f in os.listdir(ctx.cfg.data_dir):
                if f.startswith(("floorplan.", "appicon.")):
                    tar.add(os.path.join(ctx.cfg.data_dir, f), arcname=f"files/{f}")
            data = json.dumps(manifest).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    os.replace(path + ".part", path)
    return path


def validate_full_backup(path):
    """Check an uploaded archive: manifest, safe member names, and a readable sniffowireless database.
    Also accepts a backup made before the yolo -> sniffowireless rename (same format, old file/member
    names) — upgrading shouldn't make your existing backups unrestorable."""
    with tarfile.open(path, "r:gz") as tar:
        names = tar.getnames()
        db_member = "sniffowireless.db" if "sniffowireless.db" in names else LEGACY_DB_MEMBER if LEGACY_DB_MEMBER in names else None
        if not db_member or "manifest.json" not in names:
            raise ValueError("Not a sniffowireless full backup (manifest.json / sniffowireless.db missing)")
        for m in tar.getmembers():
            if m.name.startswith("/") or ".." in m.name.split("/") or not (m.isfile() or m.isdir()):
                raise ValueError(f"Unsafe entry in archive: {m.name}")
        manifest = json.load(tar.extractfile("manifest.json"))
        if manifest.get("format") not in ("sniffowireless-full", LEGACY_FORMAT):
            raise ValueError("Unknown backup format")
        with tempfile.TemporaryDirectory() as tmp:
            tar.extract(db_member, tmp, filter="data")
            c = sqlite3.connect(os.path.join(tmp, db_member))
            try:
                if c.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("Database in backup is corrupt")
                c.execute("SELECT COUNT(*) FROM devices").fetchone()
            finally:
                c.close()
    return manifest


def apply_staged_restore(cfg):
    """Called at startup before the database is opened: swap in a staged full backup."""
    staged = os.path.join(cfg.data_dir, STAGED)
    if not os.path.exists(staged):
        return False
    try:
        validate_full_backup(staged)
        keep = os.path.join(backups_dir(cfg), time.strftime("pre-restore-%Y%m%d-%H%M%S.db"))
        if os.path.exists(cfg.db_path):
            src, dst = sqlite3.connect(cfg.db_path), sqlite3.connect(keep)
            with dst:
                src.backup(dst)
            src.close()
            dst.close()
        with tarfile.open(staged, "r:gz") as tar:
            db_member = "sniffowireless.db" if "sniffowireless.db" in tar.getnames() else LEGACY_DB_MEMBER
            with tempfile.TemporaryDirectory(dir=cfg.data_dir) as tmp:
                tar.extractall(tmp, filter="data")
                for ext in ("-wal", "-shm"):
                    if os.path.exists(cfg.db_path + ext):
                        os.remove(cfg.db_path + ext)
                shutil.move(os.path.join(tmp, db_member), cfg.db_path)
                files = os.path.join(tmp, "files")
                if os.path.isdir(files):
                    for f in os.listdir(files):
                        shutil.move(os.path.join(files, f), os.path.join(cfg.data_dir, f))
        log.warning("Restored full backup; the previous database was saved as %s", keep)
    except Exception as e:
        log.error("Staged restore failed, keeping the current database: %s", e)
    finally:
        os.remove(staged)
    return True


def prune_backups(cfg, keep):
    d = backups_dir(cfg)
    files = sorted(f for f in os.listdir(d) if NAME_RX.match(f))
    for f in files[:-keep] if keep > 0 else []:
        os.remove(os.path.join(d, f))


class BackupScheduler:
    def __init__(self, ctx):
        self.ctx = ctx

    def start(self, stop):
        threading.Thread(target=self.run, args=(stop,), daemon=True, name="backup").start()

    def due(self, cfg, now):
        lt = time.localtime(now)
        return cfg["enabled"] and lt.tm_hour == int(cfg["hour"]) and now - (cfg.get("last_run") or 0) > 20 * 3600

    def run_once(self):
        cfg = self.ctx.settings.get("backup")
        path = create_full_backup(self.ctx)
        prune_backups(self.ctx.cfg, int(cfg["keep"]))
        cfg["last_run"] = time.time()
        self.ctx.settings.set("backup", cfg)
        log.info("Scheduled backup written: %s", os.path.basename(path))
        return path

    def run(self, stop):
        while not stop.wait(600):
            try:
                if self.due(self.ctx.settings.get("backup"), time.time()):
                    self.run_once()
            except Exception as e:
                log.warning("Scheduled backup failed: %s", e)


# ------------------------------------------------------------------ routes
def routes(ctx):
    r = APIRouter()
    cfg = ctx.cfg

    def restart_soon():
        def go():
            time.sleep(1.5)
            os.kill(os.getpid(), signal.SIGTERM)  # graceful stop; Docker's restart policy starts us again
        threading.Thread(target=go, daemon=True).start()

    @r.get("/api/backup/config")
    def download_config(secrets: int = 0, users: int = 1, _=Depends(require_admin)):
        data = json.dumps(export_config(ctx, bool(secrets), bool(users)), indent=1)
        name = time.strftime("sniffowireless-config-%Y%m%d-%H%M%S.json")
        return Response(data, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @r.post("/api/backup/config")
    async def restore_config(request: Request, _=Depends(require_admin)):
        raw = await request.body()
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        try:
            return {"ok": True, "restored": import_config(ctx, json.loads(raw))}
        except (ValueError, json.JSONDecodeError) as e:
            raise HTTPException(400, str(e))

    @r.get("/api/backup/list")
    def list_backups(_=Depends(require_admin)):
        d = backups_dir(cfg)
        files = [{"name": f, "size": os.path.getsize(os.path.join(d, f)), "created": os.path.getmtime(os.path.join(d, f))}
                 for f in os.listdir(d) if NAME_RX.match(f)]
        return {"backups": sorted(files, key=lambda x: -x["created"]), "settings": ctx.settings.get("backup"),
                "staged": os.path.exists(os.path.join(cfg.data_dir, STAGED))}

    @r.post("/api/backup/full")
    def make_full(_=Depends(require_admin)):
        path = create_full_backup(ctx)
        prune_backups(cfg, int(ctx.settings.get("backup")["keep"]))
        return {"name": os.path.basename(path), "size": os.path.getsize(path)}

    def _file(name):
        if not NAME_RX.match(name):
            raise HTTPException(400, "invalid name")
        path = os.path.join(backups_dir(cfg), name)
        if not os.path.exists(path):
            raise HTTPException(404)
        return path

    @r.get("/api/backup/files/{name}")
    def download_full(name: str, _=Depends(require_admin)):
        return FileResponse(_file(name), media_type="application/gzip", filename=name)

    @r.delete("/api/backup/files/{name}")
    def delete_full(name: str, _=Depends(require_admin)):
        os.remove(_file(name))
        return {"ok": True}

    def _stage(path):
        try:
            manifest = validate_full_backup(path)
        except (ValueError, tarfile.TarError, OSError) as e:
            raise HTTPException(400, f"Invalid backup: {e}")
        shutil.copyfile(path, os.path.join(cfg.data_dir, STAGED))
        restart_soon()
        return {"ok": True, "restarting": True, "backup_created": manifest.get("created")}

    @r.post("/api/backup/files/{name}/restore")
    def restore_existing(name: str, _=Depends(require_admin)):
        return _stage(_file(name))

    @r.post("/api/backup/restore")
    async def restore_upload(request: Request, _=Depends(require_admin)):
        tmp = tempfile.NamedTemporaryFile(dir=cfg.data_dir, suffix=".tar.gz", delete=False)
        try:
            with tmp:
                size = 0
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > 4 * 1024 ** 3:
                        raise HTTPException(413, "Backup too large")
                    tmp.write(chunk)
            return _stage(tmp.name)
        finally:
            os.remove(tmp.name)

    @r.put("/api/backup/settings")
    def backup_settings(body: BackupSettings, _=Depends(require_admin)):
        cur = ctx.settings.get("backup")
        cur.update(enabled=body.enabled, hour=body.hour, keep=body.keep)
        ctx.settings.set("backup", cur)
        return cur

    return r
