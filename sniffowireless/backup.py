"""Backup and restore.

* Configuration backup (JSON): settings, labels/groups, alert rules, notification channels (secrets only on
  request), sensors and users (password hashes). Restoring it replaces those tables and applies immediately.
* Full backup (.tar.gz): a consistent SQLite snapshot (online backup API, safe while sniffowireless is running) plus
  uploaded files (floor plan). Restoring it is staged and applied on the next start; the API then restarts
  the process (Docker's restart policy brings it back).
* Scheduled backups into DATA_DIR/backups with retention.

A restore can take everything, or only the parts you choose (SECTIONS below). Choosing is applied to a full backup at
the next start, before the database is opened, by copying just those tables (and files) over the current ones.
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
from typing import List, Literal, Union

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
STAGED_SECTIONS = "restore-pending.json"  # which sections of the staged backup to restore; absent = everything
UPLOAD = "restore-upload.tar.gz"          # an uploaded backup waiting for the user to choose what to restore
HANDSHAKES = "handshakes"                 # DATA_DIR sub-folder (see handshake.py)
RESTART_DELAY = 1.5                       # seconds between answering a restore request and stopping for it to apply
_restart_thread = None
LEGACY_DB_MEMBER, LEGACY_FORMAT = "yolo.db", "yolo-full"  # from before the yolo -> sniffowireless rename
NAME_RX = re.compile(r"^sniffowireless-\d{8}-\d{6}\.tar\.gz$")


# What a restore can bring back, one checkbox each. "tables" are database tables, "config" the same data as it appears
# in a configuration (JSON) backup. Tables in neither list are internal (meta, auth_sessions, presence_hours: rebuilt)
# or fall into "other", so nothing in a backup is silently out of reach.
SECTIONS = [
    {"id": "settings", "label": "Settings", "tables": ["settings"], "config": ["settings"],
     "hint": "My networks, ignore list, detection thresholds, MQTT, appearance, backup schedule"},
    {"id": "labels", "label": "Device labels & links", "tables": ["device_meta", "device_links"], "config": ["device_meta"],
     "hint": "Names, notes, known and watched flags, confirmed Bluetooth–Wi-Fi links (group membership needs Groups too)"},
    {"id": "groups", "label": "Groups", "tables": ["groups"], "config": ["groups"],
     "hint": "People and things made of several devices"},
    {"id": "alerts", "label": "Alert rules", "tables": ["alert_rules"], "config": ["alert_rules"],
     "hint": "Rules pick notification channels by number, so restore the channels too"},
    {"id": "notifiers", "label": "Notification channels", "tables": ["notifiers"], "config": ["notifiers"],
     "hint": "Telegram, ntfy, e-mail, … (secrets only if the backup includes them)"},
    {"id": "sensors", "label": "Remote sensors", "tables": ["sensors"], "config": ["sensors"],
     "hint": "Names, rooms and map positions (their tokens are API tokens)"},
    {"id": "users", "label": "Users", "tables": ["users"], "config": ["users"],
     "hint": "Accounts and password hashes. You are signed out if your own account changes"},
    {"id": "tokens", "label": "API tokens", "tables": ["api_tokens"], "config": [],
     "hint": "Tokens for scripts and remote sensors"},
    {"id": "history", "label": "Device history", "tables": ["devices", "sessions", "samples", "events", "probes", "sightings"],
     "config": [], "hint": "Every device seen, its visits and connections, signal history, events and probes. Replaces what is recorded now"},
    {"id": "security", "label": "Security findings & alert log", "tables": ["findings", "ap_enc", "alert_log"], "config": [],
     "hint": "Findings you have acknowledged or resolved, and the log of sent alerts"},
    {"id": "network", "label": "LAN, Zigbee, channel & interference data",
     "tables": ["lan_dns", "lan_flows", "lan_traffic", "dhcp_servers", "channel_stats", "interference", "dfs_events",
                "zigbee_channels", "zigbee_energy", "zigbee_networks", "zigbee_radios"], "config": [],
     "hint": "Traffic, DNS, DHCP servers, channel survey, radar and interference history, Zigbee"},
    {"id": "files", "label": "Floor plan & app icon", "tables": [], "config": [], "files": ("floorplan.", "appicon."),
     "hint": "The uploaded floor plan image and custom icon"},
    {"id": "handshakes", "label": "Handshake captures", "tables": [], "config": [], "files": (HANDSHAKES + "/",),
     "hint": "Captured WPA handshakes of your own networks"},
]
SECTION_IDS = {s["id"] for s in SECTIONS} | {"other"}
CONFIG_TABLE_SECTION = {t: s["id"] for s in SECTIONS for t in s["config"] if t != "settings"}
INTERNAL_TABLES = {"meta", "auth_sessions", "presence_hours", "sqlite_sequence"}
MAPPED_TABLES = {t for s in SECTIONS for t in s["tables"]}


def _is_other(t):
    """A table no section names, that holds data of this app (SQLite's own sqlite_* tables and ours-internal ones don't)."""
    return t not in MAPPED_TABLES and t not in INTERNAL_TABLES and not t.startswith("sqlite_")


def _sections_info(counts):
    """The SECTIONS list with a count each (rows or files); "other" appears when the backup holds more tables."""
    out = [{"id": s["id"], "label": s["label"], "hint": s["hint"], "count": counts.get(s["id"], 0),
            "unit": "files" if s.get("files") else "entries"} for s in SECTIONS]
    if counts.get("other"):
        out.append({"id": "other", "label": "Other data", "hint": "Tables this version doesn't know by name",
                    "count": counts["other"], "unit": "entries"})
    return out


def _db_tables(conn, schema="main"):
    return {r[0] for r in conn.execute(f"SELECT name FROM {schema}.sqlite_master WHERE type='table'")}


def section_counts(db_path, names):
    """How much of each section a backup holds: database rows from its snapshot, files from the archive's member names."""
    counts = {}
    with closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as c:
        have = _db_tables(c)
        for s in SECTIONS:
            counts[s["id"]] = sum(c.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0] for t in s["tables"] if t in have)
        other = [t for t in have if _is_other(t)]
        counts["other"] = sum(c.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0] for t in other)
    for s in SECTIONS:
        for prefix in s.get("files", ()):
            base = "files/" if not prefix.endswith("/") else ""
            counts[s["id"]] += sum(1 for n in names if n.startswith(base + prefix) and not n.endswith("/"))
    return counts


class RestoreChoice(BaseModel):
    source: str = Field(max_length=120)                  # "upload" or the name of a stored backup
    sections: Union[Literal["all"], List[str]] = Field(max_length=40)  # "all" replaces the whole database


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


def config_sections(data):
    """What a configuration backup holds, as restore sections with counts."""
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise ValueError("Not a sniffowireless configuration backup")
    tables = data.get("tables") or {}
    counts = {"settings": sum(1 for k in (data.get("settings") or {}) if k in DEFAULTS)}
    for t, sid in CONFIG_TABLE_SECTION.items():
        counts[sid] = len(tables.get(t) or [])
    return [x for x in _sections_info(counts) if x["id"] == "settings" or x["id"] in CONFIG_TABLE_SECTION.values()]


def import_config(ctx, data, only=None):
    """Restore a configuration backup, or just the sections in `only` (None = all of it)."""
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise ValueError("Not a sniffowireless configuration backup")
    tables = data.get("tables") or {}
    with closing(ctx.wdb()) as c:
        known_cols = {t: {r[1] for r in c.execute(f"PRAGMA table_info({t})")} for t in CONFIG_TABLES + ["users"]}
        c.execute("BEGIN")
        try:
            for k, v in (data.get("settings") or {}).items() if only is None or "settings" in only else ():
                if k in DEFAULTS and isinstance(v, dict):  # only known settings, bounded values
                    c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)", (k, json.dumps(clean_json(v))))
            for t in CONFIG_TABLES + ["users"]:
                if t not in tables or (only is not None and CONFIG_TABLE_SECTION.get(t) not in only):
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
            _fix_references(c)
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
    return {t: len(tables.get(t) or []) for t in CONFIG_TABLES + ["users"]
            if t in tables and (only is None or CONFIG_TABLE_SECTION.get(t) in only)}


def _fix_references(c):
    """After restoring some tables but not others, drop links that point at rows that no longer exist."""
    have = _db_tables(c)
    if {"device_meta", "groups"} <= have:
        c.execute("UPDATE device_meta SET group_id=NULL WHERE group_id IS NOT NULL AND group_id NOT IN (SELECT id FROM groups)")
    if {"sensors", "api_tokens"} <= have:
        c.execute("UPDATE sensors SET token_id=NULL WHERE token_id IS NOT NULL AND token_id NOT IN (SELECT id FROM api_tokens)")


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
        members = [("sniffowireless.db", snap)]
        for f in sorted(os.listdir(ctx.cfg.data_dir)):
            if f.startswith(("floorplan.", "appicon.")):
                members.append((f"files/{f}", os.path.join(ctx.cfg.data_dir, f)))
        hs = os.path.join(ctx.cfg.data_dir, HANDSHAKES)
        if os.path.isdir(hs):
            members += [(f"{HANDSHAKES}/{f}", os.path.join(hs, f)) for f in sorted(os.listdir(hs))
                        if os.path.isfile(os.path.join(hs, f)) and not f.endswith(".tmp")]
        manifest["sections"] = section_counts(snap, [a for a, _ in members])  # lets the restore chooser skip unpacking
        with tarfile.open(path + ".part", "w:gz") as tar:
            for arc, src_path in members:
                tar.add(src_path, arcname=arc)
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


def inspect_full_backup(path):
    """What a full backup holds, for the restore chooser: its manifest and a count per section."""
    manifest = validate_full_backup(path)
    with tarfile.open(path, "r:gz") as tar:
        names = tar.getnames()
        counts = manifest.get("sections")
        if not isinstance(counts, dict):  # a backup from before the counts were recorded: look inside
            db_member = "sniffowireless.db" if "sniffowireless.db" in names else LEGACY_DB_MEMBER
            with tempfile.TemporaryDirectory() as tmp:
                tar.extract(db_member, tmp, filter="data")
                counts = section_counts(os.path.join(tmp, db_member), names)
    return {"created": manifest.get("created"), "app_version": manifest.get("app_version"), "sections": _sections_info(counts)}


def _safety_copy(cfg):
    keep = os.path.join(backups_dir(cfg), time.strftime("pre-restore-%Y%m%d-%H%M%S.db"))
    if os.path.exists(cfg.db_path):
        src, dst = sqlite3.connect(cfg.db_path), sqlite3.connect(keep)
        with dst:
            src.backup(dst)
        src.close()
        dst.close()
    return keep


def _copy_table(c, t):
    """Replace table t in the current database with the backup's, over the columns both have."""
    cols = [r[1] for r in c.execute(f'PRAGMA main.table_info("{t}")')]
    cols = [x for x in cols if x in {r[1] for r in c.execute(f'PRAGMA bk.table_info("{t}")')}]
    if not cols:
        return 0
    lst = ",".join(f'"{x}"' for x in cols)
    if t == "users" and not c.execute('SELECT 1 FROM bk."users" LIMIT 1').fetchone():
        return 0  # never lock everyone out
    c.execute('DELETE FROM main."sensors" WHERE id != \'local\'' if t == "sensors" else f'DELETE FROM main."{t}"')
    return c.execute(f'INSERT OR REPLACE INTO main."{t}"({lst}) SELECT {lst} FROM bk."{t}"').rowcount


def restore_sections(cfg, archive, ids):
    """Copy only the chosen sections of a full backup over the current data. Runs at startup, before the database is
    opened by the app, so nothing is writing to it. A copy of the current database is kept first."""
    ids = set(ids)
    keep = _safety_copy(cfg)
    done = {}
    with tarfile.open(archive, "r:gz") as tar, tempfile.TemporaryDirectory(dir=cfg.data_dir) as tmp:
        names = tar.getnames()
        db_member = "sniffowireless.db" if "sniffowireless.db" in names else LEGACY_DB_MEMBER
        tar.extractall(tmp, filter="data")
        c = sqlite3.connect(cfg.db_path, timeout=30, isolation_level=None)
        try:
            c.execute("ATTACH DATABASE ? AS bk", (os.path.join(tmp, db_member),))
            main, bk = _db_tables(c), _db_tables(c, "bk")
            c.execute("BEGIN")
            try:
                for s in SECTIONS:
                    if s["id"] in ids and s["tables"]:
                        done[s["id"]] = sum(_copy_table(c, t) for t in s["tables"] if t in main and t in bk)
                if "other" in ids:
                    done["other"] = sum(_copy_table(c, t) for t in sorted(bk) if t in main and _is_other(t))
                if "users" in ids:
                    c.execute("DELETE FROM auth_sessions WHERE user_id NOT IN (SELECT id FROM users)")
                if "history" in ids:
                    if "presence_hours" in main:  # derived from samples: rebuild rather than trust a copy
                        c.execute("DELETE FROM presence_hours")
                        c.execute("INSERT OR IGNORE INTO presence_hours(hour, mac) SELECT DISTINCT minute / 3600 * 3600, mac FROM samples")
                    c.execute("DELETE FROM meta WHERE key='ident_version'")  # identification is redone for the restored devices
                _fix_references(c)
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise
        finally:
            c.close()
        if "files" in ids:
            src = os.path.join(tmp, "files")
            if os.path.isdir(src) and os.listdir(src):
                for f in os.listdir(cfg.data_dir):  # an older icon with another extension must not linger
                    if f.startswith(("floorplan.", "appicon.")):
                        os.remove(os.path.join(cfg.data_dir, f))
                done["files"] = len(os.listdir(src))
                for f in os.listdir(src):
                    shutil.move(os.path.join(src, f), os.path.join(cfg.data_dir, f))
        if "handshakes" in ids:
            src = os.path.join(tmp, HANDSHAKES)
            if os.path.isdir(src):
                dest = os.path.join(cfg.data_dir, HANDSHAKES)
                os.makedirs(dest, exist_ok=True)
                for f in os.listdir(src):
                    shutil.move(os.path.join(src, f), os.path.join(dest, f))
                done["handshakes"] = len(os.listdir(dest))
    log.warning("Restored from a backup: %s. The previous database was saved as %s",
                ", ".join(f"{k} ({v})" for k, v in done.items()) or "nothing", keep)
    return done


def apply_staged_restore(cfg):
    """Called at startup before the database is opened: apply a staged backup, whole or only the chosen sections."""
    for leftover in (os.path.join(cfg.data_dir, UPLOAD),):  # an uploaded backup nobody chose anything from
        if os.path.exists(leftover):
            os.remove(leftover)
    staged = os.path.join(cfg.data_dir, STAGED)
    sidecar = os.path.join(cfg.data_dir, STAGED_SECTIONS)
    if not os.path.exists(staged):
        if os.path.exists(sidecar):
            os.remove(sidecar)
        return False
    try:
        validate_full_backup(staged)
        chosen = None
        if os.path.exists(sidecar):
            try:
                with open(sidecar, encoding="utf-8") as fh:
                    chosen = [x for x in json.load(fh).get("sections", []) if x in SECTION_IDS]
            except (OSError, ValueError):
                chosen = []
        if chosen is not None and os.path.exists(cfg.db_path):
            restore_sections(cfg, staged, chosen)
            return True
        keep = _safety_copy(cfg)
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
                hs = os.path.join(tmp, HANDSHAKES)
                if os.path.isdir(hs):
                    os.makedirs(os.path.join(cfg.data_dir, HANDSHAKES), exist_ok=True)
                    for f in os.listdir(hs):
                        shutil.move(os.path.join(hs, f), os.path.join(cfg.data_dir, HANDSHAKES, f))
        log.warning("Restored full backup; the previous database was saved as %s", keep)
    except Exception as e:
        log.error("Staged restore failed, keeping the current database: %s", e)
    finally:
        for f in (staged, sidecar):
            if os.path.exists(f):
                os.remove(f)
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
        global _restart_thread

        def go():
            time.sleep(RESTART_DELAY)
            os.kill(os.getpid(), signal.SIGTERM)  # graceful stop; Docker's restart policy starts us again
        _restart_thread = threading.Thread(target=go, daemon=True)
        _restart_thread.start()

    @r.get("/api/backup/config")
    def download_config(secrets: int = 0, users: int = 1, _=Depends(require_admin)):
        data = json.dumps(export_config(ctx, bool(secrets), bool(users)), indent=1)
        name = time.strftime("sniffowireless-config-%Y%m%d-%H%M%S.json")
        return Response(data, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    async def _config_body(request):
        raw = await request.body()
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            raise HTTPException(400, str(e))

    @r.post("/api/backup/config/inspect")
    async def inspect_config(request: Request, _=Depends(require_admin)):
        try:
            return {"sections": config_sections(await _config_body(request))}
        except ValueError as e:
            raise HTTPException(400, str(e))

    @r.post("/api/backup/config")
    async def restore_config(request: Request, sections: str = "", _=Depends(require_admin)):
        data = await _config_body(request)
        only = None
        if sections:  # comma separated section ids; without it everything in the file is restored
            only = {x for x in sections.split(",") if x}
            if not only <= SECTION_IDS:
                raise HTTPException(400, "unknown section")
        try:
            return {"ok": True, "restored": import_config(ctx, data, only)}
        except ValueError as e:
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

    def _stage(path, sections=None, move=False):
        """Queue a backup for the next start: all of it, or just `sections`."""
        try:
            manifest = validate_full_backup(path)
        except (ValueError, tarfile.TarError, OSError) as e:
            raise HTTPException(400, f"Invalid backup: {e}")
        part = os.path.join(cfg.data_dir, STAGED + ".part")
        (shutil.move if move else shutil.copyfile)(path, part)
        sidecar = os.path.join(cfg.data_dir, STAGED_SECTIONS)
        if sections is None:
            if os.path.exists(sidecar):
                os.remove(sidecar)
        else:
            with open(sidecar, "w", encoding="utf-8") as fh:
                json.dump({"sections": sections}, fh)
        os.replace(part, os.path.join(cfg.data_dir, STAGED))
        restart_soon()
        return {"ok": True, "restarting": True, "backup_created": manifest.get("created")}

    def _inspect(path):
        try:
            return inspect_full_backup(path)
        except (ValueError, tarfile.TarError, OSError, sqlite3.Error) as e:
            raise HTTPException(400, f"Invalid backup: {e}")

    @r.get("/api/backup/files/{name}/sections")
    def stored_sections(name: str, _=Depends(require_admin)):
        return _inspect(_file(name))

    @r.post("/api/backup/inspect")
    async def inspect_upload(request: Request, _=Depends(require_admin)):
        """Take an uploaded backup and say what is in it; the choice of what to restore comes next, without
        uploading it again."""
        part = os.path.join(cfg.data_dir, UPLOAD + ".part")
        try:
            with open(part, "wb") as fh:
                size = 0
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > 4 * 1024 ** 3:
                        raise HTTPException(413, "Backup too large")
                    fh.write(chunk)
            info = _inspect(part)
            os.replace(part, os.path.join(cfg.data_dir, UPLOAD))
            return info
        finally:
            if os.path.exists(part):
                os.remove(part)

    @r.post("/api/backup/restore-selected")
    def restore_selected(body: RestoreChoice, _=Depends(require_admin)):
        upload = os.path.join(cfg.data_dir, UPLOAD)
        if body.source == "upload":
            if not os.path.exists(upload):
                raise HTTPException(404, "No uploaded backup: choose the file again")
            path = upload
        else:
            path = _file(body.source)
        if body.sections == "all":
            return _stage(path, None, move=body.source == "upload")
        chosen = [x for x in dict.fromkeys(body.sections)]
        if not chosen or not set(chosen) <= SECTION_IDS:
            raise HTTPException(400, "Choose what to restore")
        return _stage(path, chosen, move=body.source == "upload")

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
