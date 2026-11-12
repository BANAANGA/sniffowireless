"""SQLite-backed device / session / time-series store.

Capture threads push observation dicts onto a queue. A single writer thread
turns them into device records, presence and connection sessions, per-minute
signal samples and events, and flushes everything in batched transactions.
"""
import json
import logging
import os
import queue
import re
import sqlite3
import time

from . import apclock, btversion, identify, macprivacy, ossig, scanbehavior, wifiattrs
from .config import _int
from .oui import bt_company, bt_company_known
from .sanitize import clean_str

BT_VERSION_RULES = "2"
BT_COMPANY_NAMES = "3"
_COMPANY_RX = re.compile(r"^Company 0x([0-9A-Fa-f]{1,4})$")

log = logging.getLogger("sniffowireless.store")

# Every API request opens its own connection, so SQLite's default 2 MB page cache starts cold each time and is too
# small to hold what one aggregate over `samples` touches. A larger per-connection cache (only filled as far as a query
# needs) and a memory map (shared with the OS page cache) make those scans noticeably cheaper.
# Settings → Performance switches this off at runtime for low-memory machines (SQLite's own defaults are used instead).
# DB_CACHE_MB / DB_MMAP_MB set the sizes; 0 means "SQLite's default" / "no memory map".
CACHE_KB = max(0, _int("DB_CACHE_MB", 16)) * 1024
MMAP_BYTES = max(0, _int("DB_MMAP_MB", 256)) * 1024 * 1024
SQLITE_DEFAULT_CACHE_KB = 2000
_tuned = {"on": True}


def set_db_cache(on):
    _tuned["on"] = bool(on)


def tune(conn):
    """Apply the page cache / memory map settings to a connection (new ones get them in connect())."""
    on = _tuned["on"]
    conn.execute(f"PRAGMA cache_size=-{(CACHE_KB if on else 0) or SQLITE_DEFAULT_CACHE_KB}")
    conn.execute(f"PRAGMA mmap_size={MMAP_BYTES if on else 0}")

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS devices(
  mac TEXT PRIMARY KEY, kind TEXT NOT NULL, first_seen REAL, last_seen REAL,
  vendor TEXT, name TEXT, ssid TEXT, channel INTEGER, freq INTEGER, band TEXT, enc TEXT,
  bssid TEXT, randomized INTEGER DEFAULT 0, packets INTEGER DEFAULT 0,
  last_rssi INTEGER, best_rssi INTEGER, extra TEXT, brand TEXT, model TEXT, dev_type TEXT, os TEXT,
  wifi_gen INTEGER, era INTEGER, fp_hash TEXT, ident TEXT, room TEXT, pos_x REAL, pos_y REAL, ip TEXT);
CREATE INDEX IF NOT EXISTS idx_devices_kind ON devices(kind, last_seen);
CREATE INDEX IF NOT EXISTS idx_devices_last ON devices(last_seen);
CREATE INDEX IF NOT EXISTS idx_devices_ssid ON devices(ssid);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS sessions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT NOT NULL, type TEXT NOT NULL,
  peer TEXT, start_ts REAL NOT NULL, end_ts REAL NOT NULL, packets INTEGER DEFAULT 0,
  rssi_min INTEGER, rssi_max INTEGER, rssi_sum INTEGER DEFAULT 0, rssi_count INTEGER DEFAULT 0,
  open INTEGER DEFAULT 1, end_reason TEXT);
CREATE INDEX IF NOT EXISTS idx_sessions_mac ON sessions(mac, type, start_ts);
CREATE INDEX IF NOT EXISTS idx_sessions_peer ON sessions(peer, start_ts);
CREATE INDEX IF NOT EXISTS idx_sessions_end ON sessions(type, end_ts);
CREATE TABLE IF NOT EXISTS samples(
  mac TEXT NOT NULL, minute INTEGER NOT NULL, packets INTEGER DEFAULT 0,
  rssi_sum INTEGER DEFAULT 0, rssi_count INTEGER DEFAULT 0, rssi_min INTEGER, rssi_max INTEGER,
  PRIMARY KEY(mac, minute)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_samples_minute ON samples(minute);
-- Which devices were heard in which hour: a roll-up of `samples` (one row per device-hour instead of per device-minute,
-- ~60x fewer) that the long-range charts count distinct devices from. Kept in step with `samples` as they are written.
CREATE TABLE IF NOT EXISTS presence_hours(
  hour INTEGER NOT NULL, mac TEXT NOT NULL, PRIMARY KEY(hour, mac)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, mac TEXT, type TEXT NOT NULL,
  peer TEXT, detail TEXT);
-- (ts, type): the per-type counts of a period are read from the index alone; replaces the older index on ts only
CREATE INDEX IF NOT EXISTS idx_events_ts_type ON events(ts, type);
DROP INDEX IF EXISTS idx_events_ts;
CREATE INDEX IF NOT EXISTS idx_events_mac ON events(mac, ts);
CREATE TABLE IF NOT EXISTS probes(
  mac TEXT NOT NULL, ssid TEXT NOT NULL, first_seen REAL, last_seen REAL, count INTEGER DEFAULT 0,
  PRIMARY KEY(mac, ssid)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_probes_ssid ON probes(ssid);
CREATE TABLE IF NOT EXISTS device_meta(
  mac TEXT PRIMARY KEY, label TEXT, notes TEXT, known INTEGER DEFAULT 0, watch INTEGER DEFAULT 0,
  group_id INTEGER, updated REAL);
CREATE TABLE IF NOT EXISTS groups(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, kind TEXT DEFAULT 'person', notes TEXT,
  watch INTEGER DEFAULT 0, created REAL);
CREATE TABLE IF NOT EXISTS sightings(
  mac TEXT NOT NULL, sensor TEXT NOT NULL, last_seen REAL, rssi REAL, PRIMARY KEY(mac, sensor)) WITHOUT ROWID;
"""

DEVICE_COLS = ("mac", "kind", "first_seen", "last_seen", "vendor", "name", "ssid", "channel",
               "freq", "band", "enc", "bssid", "randomized", "packets", "last_rssi", "best_rssi", "extra",
               "brand", "model", "dev_type", "os", "wifi_gen", "era", "fp_hash", "ident", "room", "pos_x", "pos_y", "ip")
JSON_COLS = ("extra", "ident")
# Columns added after the first release: name -> SQL type (added by _migrate on old databases).
ADDED_COLS = {"band": "TEXT", "brand": "TEXT", "model": "TEXT", "dev_type": "TEXT", "os": "TEXT",
              "wifi_gen": "INTEGER", "era": "INTEGER", "fp_hash": "TEXT", "ident": "TEXT", "room": "TEXT",
              "pos_x": "REAL", "pos_y": "REAL", "ip": "TEXT"}

WIFI_KINDS = ("ap", "wifi_client")
BT_KINDS = ("ble", "bt_classic")
LAN_KIND = "lan"  # seen only on the wired / LAN side
# Within a radio family a device can be "upgraded" (a client that starts beaconing is an AP,
# a BLE address that answers an inquiry is dual-mode classic).
KIND_RANK = {"wifi_client": 1, "ap": 2, "ble": 1, "bt_classic": 2}
DEDUPE_EVENTS = {"ap_restart": 600, "deauth_broadcast": 60, "deauth": 30, "deauth_flood": 300, "rogue_ap": 3600, "karma_ap": 3600,
                 "moved": 600, "ap_clock_conflict": 3600, "lora_flood": 600, "lora_join_flood": 1800, "lora_fcnt_reset": 3600, "zigbee_permit_join": 600}


class IgnoreRules:
    """Devices / networks dropped before anything is stored (admin ignore list + IGNORE_MACS)."""

    def __init__(self, macs=(), prefixes=(), ssids=()):
        self.macs = {m.lower() for m in macs}
        self.prefixes = tuple(p.lower().rstrip(":*") for p in prefixes if p)
        self.ssids = {e["ssid"]: bool(e.get("clients")) for e in ssids if e.get("ssid")}
        self.bssids = {}  # bssid -> also drop its clients (learned from beacons of ignored SSIDs)

    def mac(self, mac):
        return mac in self.macs or (self.prefixes and mac.startswith(self.prefixes))

    def drop(self, o):
        mac = o["mac"]
        if self.mac(mac):
            return True
        t = o["t"]
        if t == "wifi_ap":
            ssid = o.get("ssid")
            if ssid in self.ssids:
                self.bssids[mac] = self.ssids[ssid]
                return True
            return mac in self.bssids
        if t == "wifi_client":
            b = o.get("bssid")
            if b and (self.mac(b) or self.bssids.get(b)):
                return True
            if o.get("probe") in self.ssids and self.ssids[o["probe"]]:
                return True
        return False


def is_randomized_mac(mac):
    try:
        return bool(int(mac[0:2], 16) & 0x02)
    except (ValueError, TypeError):
        return False


def connect(path, readonly=False):
    conn = sqlite3.connect(path, timeout=10, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    tune(conn)
    if readonly:
        conn.execute("PRAGMA query_only=1")
    return conn


class Session:
    __slots__ = ("id", "mac", "type", "peer", "start", "last", "packets", "rmin", "rmax",
                 "rsum", "rcnt", "bt", "lan", "notimeout", "open", "reason", "dirty")

    def __init__(self, mac, type_, peer, ts, bt=False, notimeout=False, lan=False):
        self.id = None
        self.mac, self.type, self.peer = mac, type_, peer
        self.start = self.last = ts
        self.packets = 0
        self.rmin = self.rmax = None
        self.rsum = self.rcnt = 0
        self.bt, self.notimeout, self.lan = bt, notimeout, lan
        self.open, self.reason = True, None
        self.dirty = True

    def touch(self, ts, rssi=None, count=True):
        if ts > self.last:
            self.last = ts
        if count:
            self.packets += 1
        if rssi is not None:
            self.rsum += rssi
            self.rcnt += 1
            self.rmin = rssi if self.rmin is None else min(self.rmin, rssi)
            self.rmax = rssi if self.rmax is None else max(self.rmax, rssi)
        self.dirty = True


class Store:
    def __init__(self, cfg, vendors):
        self.cfg = cfg
        self.vendors = vendors
        self.q = queue.Queue(maxsize=200_000)
        self.dropped = 0
        self.processed = 0
        os.makedirs(os.path.dirname(os.path.abspath(cfg.db_path)), exist_ok=True)
        self.conn = connect(cfg.db_path)
        self.conn.executescript(SCHEMA)
        self.learner = ossig.OsLearner(self.conn)  # Wi-Fi signatures learned from devices whose OS is known (ossig.py)
        self.scan_learner = ossig.OsLearner(self.conn, prefix="scan")   # ... and the same for how a client scans (scanbehavior.py)
        identify.set_learner(self.learner.lookup, self.scan_learner.lookup)
        self.scans = scanbehavior.ScanTracker()
        self._migrate()
        self.macpriv = None
        self.clockwatch = apclock.ClockWatch()
        self.retention = {}     # days per kind of data from Settings -> Privacy (0 = RETENTION_DAYS)
        self._init_macprivacy()
        self.scan_learner.reload()
        self.learner.reload()   # (addresses may just have been replaced by pseudonyms)
        n = self.conn.execute(
            "UPDATE sessions SET open=0, end_reason=COALESCE(end_reason,'restart') WHERE open=1").rowcount
        if n:
            log.info("Closed %d sessions left open by a previous run", n)

        self.devices = {}       # mac -> device dict (write-through cache)
        self.dirty = set()
        self.presence = {}      # mac -> Session (presence)
        self.assoc = {}         # mac -> Session (connection to an AP / BT adapter)
        self.closed = []        # closed Sessions awaiting flush
        self.buckets = {}       # (mac, minute) -> [packets, rsum, rcnt, rmin, rmax]
        self.events = []
        self.probe_updates = {}  # (mac, ssid) -> [first, last, count]
        self.known_probes = set()
        self._last_event = {}
        self._boots = {}                      # AP mac -> estimated boot time, to notice a restart
        self.seq_linker = wifiattrs.SeqLinker()  # only fed when WIFI_SEQ_LINK is on
        self.ignore = IgnoreRules(self._env_macs())
        self.important = set()  # labelled / watched / grouped devices: always log their events
        self.mac_group = {}     # mac -> group id
        self.group_names = {}
        self.group_present = {}  # group id -> set of present member macs
        self.sightings = {}     # (mac, sensor) -> [last_seen, rssi ewma]
        self.sightings_dirty = set()
        self.hooks = []         # plugins with optional observe(store, o, dev) / sweep(store, now) / flush(store, c)
        self.listeners = []     # called with newly committed events (list of dicts)

    # ------------------------------------------------------------------ privacy mode (see macprivacy.py)
    def _stored_privacy(self):
        row = self.conn.execute("SELECT value FROM settings WHERE key='privacy'").fetchone() if self._has_table("settings") else None
        try:
            return json.loads(row[0]) if row else {}
        except (ValueError, TypeError):
            return {}

    def _has_table(self, name):
        return bool(self.conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone())

    def _init_macprivacy(self):
        p = self._stored_privacy()
        if not (self.cfg.hash_macs or p.get("hash_macs")):
            return
        self.enable_macprivacy(p.get("hash_scope") or "static")
        if p.get("hash_existing"):  # asked for in the interface: done now, before anything else uses the database
            try:
                self.macpriv.migrate_existing(self.conn)
                p["hash_existing"], p["hashed_at"] = False, time.time()
                self.conn.execute("INSERT OR REPLACE INTO settings(key, value) VALUES('privacy', ?)", (json.dumps(p),))
            except Exception:
                log.exception("Privacy: replacing the stored MAC addresses failed; it is tried again at the next start")

    def enable_macprivacy(self, scope="static"):
        """Switch privacy mode on (also at run time): everything from now on is stored hashed."""
        key = macprivacy.load_key(self.cfg.data_dir, self.cfg.privacy_key)
        self.macpriv = macprivacy.MacHasher(connect(self.cfg.db_path), key, scope)
        macprivacy.set_current(self.macpriv)
        log.info("Privacy mode on: full static MAC addresses are never stored (scope: %s)", self.macpriv.scope)

    def disable_macprivacy(self):
        self.macpriv = None
        macprivacy.set_current(None)

    def _env_macs(self):
        """IGNORE_MACS from the environment (real addresses), hashed when privacy mode is on."""
        h = getattr(self, "macpriv", None)
        return {h.pseudonym(m) for m in self.cfg.ignore_macs} if h else set(self.cfg.ignore_macs)

    def set_retention(self, days):
        self.retention = {k: int(v) for k, v in (days or {}).items() if isinstance(v, (int, float)) and v > 0}

    def retention_days(self, kind):
        return self.retention.get(kind) or self.cfg.retention_days

    def _migrate(self):
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(devices)")}
        for col, typ in ADDED_COLS.items():
            if col not in cols:
                self.conn.execute(f"ALTER TABLE devices ADD COLUMN {col} {typ}")
                log.info("Migrated database: added devices.%s", col)
        if "band" not in cols:
            self.conn.execute("UPDATE devices SET band = CASE WHEN freq >= 5925 THEN '6' WHEN freq >= 4900 THEN '5' "
                              "WHEN freq > 0 THEN '2.4' WHEN channel <= 14 THEN '2.4' WHEN channel > 14 THEN '5' END "
                              "WHERE kind IN ('ap', 'wifi_client')")
        for idx in ("dev_type", "brand", "fp_hash"):
            self.conn.execute(f"CREATE INDEX IF NOT EXISTS idx_devices_{idx} ON devices({idx})")
        # What the charts need of a device when they join presence rows to it, so they don't open the (large) device row for each.
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_join ON devices(mac, kind, band, randomized)")
        if not self.conn.execute("SELECT 1 FROM meta WHERE key='presence_hours'").fetchone():
            n = self.conn.execute("INSERT OR IGNORE INTO presence_hours(hour, mac) "
                                  "SELECT DISTINCT minute / 3600 * 3600, mac FROM samples").rowcount
            self.conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('presence_hours', '1')")
            if n:
                log.info("Migrated database: built the hourly presence roll-up (%d device-hours)", n)
        row = self.conn.execute("SELECT value FROM meta WHERE key='bt_versions'").fetchone()
        if not row or row[0] != BT_VERSION_RULES:  # the rules for deriving it changed (v2: LE Audio services, model lookup)
            self._backfill_bt_versions()
            self.conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('bt_versions', ?)", (BT_VERSION_RULES,))
        row = self.conn.execute("SELECT value FROM meta WHERE key='bt_company_names'").fetchone()
        if not row or row[0] != BT_COMPANY_NAMES:  # company names are stored as seen: re-name the "Company 0x…" ones
            self._rename_bt_companies()
            self.conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('bt_company_names', ?)", (BT_COMPANY_NAMES,))
        row = self.conn.execute("SELECT value FROM meta WHERE key='ident_version'").fetchone()
        if not row or int(row[0]) != identify.IDENT_VERSION:
            self.reidentify_all()
            self.conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('ident_version', ?)",
                              (str(identify.IDENT_VERSION),))

    def _backfill_bt_versions(self):
        """Work out the Bluetooth version of the devices stored before it was kept (once, from what they already hold)."""
        n = 0
        for r in self.conn.execute("SELECT mac, kind, extra, model FROM devices WHERE kind IN ('ble', 'bt_classic')").fetchall():
            extra = json.loads(r["extra"] or "{}")
            if btversion.apply(r["kind"], extra, r["model"]):
                self.conn.execute("UPDATE devices SET extra=? WHERE mac=?", (json.dumps(extra), r["mac"]))
                n += 1
        if n:
            log.info("Migrated database: worked out the Bluetooth version of %d devices", n)

    def _rename_bt_companies(self):
        """Devices stored while a company ID was unknown keep "Company 0x0160"; look the names up again."""
        rx = _COMPANY_RX
        n = 0
        for r in self.conn.execute("SELECT mac, vendor, extra FROM devices WHERE kind IN ('ble', 'bt_classic')").fetchall():
            extra = json.loads(r["extra"] or "{}")
            vendor, changed = r["vendor"], False
            for key in ("company", "chip"):
                m = rx.match(extra.get(key) or "")
                if m and bt_company(int(m.group(1), 16)) != extra[key]:
                    extra[key] = bt_company(int(m.group(1), 16))
                    changed = True
            m = rx.match(vendor or "")
            if m:  # an unnamed company is not a vendor
                vendor, changed = bt_company_known(int(m.group(1), 16)), True
            if changed:
                self.conn.execute("UPDATE devices SET vendor=?, extra=? WHERE mac=?", (vendor, json.dumps(extra), r["mac"]))
                n += 1
        if n:
            log.info("Migrated database: named the Bluetooth company of %d devices", n)

    def _link_same(self, dev, old, step, ts):
        """Record that two randomised addresses are possibly one device (frame counter carried on). Both pages show it."""
        for a_dev, other in ((dev, old), (self.devices.get(old), dev["mac"])):
            if a_dev is None:
                continue
            links = [x for x in (a_dev["extra"].get("same_as") or []) if x.get("mac") != other][-4:]
            links.append({"mac": other, "step": step, "ts": int(ts)})
            a_dev["extra"]["same_as"] = links

    def _learn(self, dev):
        """A client whose OS is established by strong evidence teaches its Wi-Fi signature (ossig.py)."""
        if dev.get("kind") != "wifi_client":
            return
        sig = ossig.wifi_signature(dev)
        fam = ossig.trusted_family(((dev.get("ident") or {}).get("evidence")))
        if sig and fam:
            self.learner.observe(dev["mac"], sig, fam)
        ssig = ossig.scan_signature(dev)
        if ssig and fam:
            self.scan_learner.observe(dev["mac"], ssig, fam)

    def _load_dev(self, mac):
        dev = self.devices.get(mac)
        if dev is None:
            row = self.conn.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
            if not row:
                return None
            dev = dict(row)
            dev["extra"] = json.loads(dev["extra"] or "{}")
            dev["ident"] = json.loads(dev["ident"] or "null")
            self.devices[mac] = dev
        return dev

    def _beacon_clock(self, dev, mac, sensor, ts, tsf):
        """Clock-drift check (apclock.py): two timers under one BSSID is a cloned address; the drift itself is kept for the page."""
        why = self.clockwatch.feed(sensor, mac, ts, tsf)
        if why:
            self._event(ts, mac, "ap_clock_conflict", None, why + " - possibly a second access point using this address", dev=dev, always=True)
        if ts - (dev["extra"].get("skew") or {}).get("ts", 0) > 120:
            ppm = self.clockwatch.skew_ppm(sensor, mac)
            if ppm is not None and abs(ppm) < 5000:
                dev["extra"]["skew"] = {"ppm": ppm, "ts": int(ts)}
                self.dirty.add(mac)

    def apply_mobility(self, results):
        """results: {mac: {"c", "std", "bins", "ts"}} from mobility.compute; stored in extra["mobility"] (writer thread)."""
        for mac, m in results.items():
            dev = self._load_dev(mac)
            if dev is None or dev["extra"].get("mobility") == m:
                continue
            dev["extra"]["mobility"] = m
            self.conn.execute("UPDATE devices SET extra=? WHERE mac=?", (json.dumps(dev["extra"]), mac))

    def clear_mobility(self, keep):
        """A device that no longer has enough recent signal samples loses its old class (a stale 'fixed' would mislead)."""
        for mac, dev in list(self.devices.items()):
            if "mobility" in dev["extra"] and mac not in keep:
                del dev["extra"]["mobility"]
                self.conn.execute("UPDATE devices SET extra=? WHERE mac=?", (json.dumps(dev["extra"]), mac))
        for r in self.conn.execute("SELECT mac, extra FROM devices WHERE extra LIKE '%\"mobility\"%'").fetchall():
            if r["mac"] in keep or r["mac"] in self.devices:
                continue
            extra = json.loads(r["extra"] or "{}")
            if extra.pop("mobility", None) is not None:
                self.conn.execute("UPDATE devices SET extra=? WHERE mac=?", (json.dumps(extra), r["mac"]))

    def propagate_linked_os(self):
        """Carry the OS across Bluetooth <-> Wi-Fi links that a person confirmed: a phone has both radios, and its Wi-Fi side often
        says more about the OS than its Bluetooth side. Only links with status 'linked' count; a pair that is later rejected loses it."""
        try:
            pairs = self.conn.execute("SELECT mac_a, mac_b, status FROM device_links").fetchall()
        except sqlite3.OperationalError:
            return 0
        changed = 0

        def refresh(dev):
            dev.update(identify.identify(dev))
            self.dirty.add(dev["mac"])

        for a, b, status in pairs:
            da, db = self._load_dev(a), self._load_dev(b)
            if da is None or db is None:
                continue
            if status == "linked":
                for src, dst in ((da, db), (db, da)):
                    fam = ossig.trusted_family((src.get("ident") or {}).get("evidence"), 65)
                    have = ossig.trusted_family((dst.get("ident") or {}).get("evidence"), 65)
                    cur = dst["extra"].get("linked_os") or {}
                    if fam and not have and (cur.get("os"), cur.get("from")) != (fam, src["mac"]):
                        dst["extra"]["linked_os"] = {"os": fam, "from": src["mac"], "conf": 70}
                        refresh(dst)
                        changed += 1
            else:
                for dev, other in ((da, b), (db, a)):
                    if (dev["extra"].get("linked_os") or {}).get("from") == other:
                        dev["extra"].pop("linked_os", None)
                        refresh(dev)
                        changed += 1
        return changed

    def reidentify_all(self):
        """Re-run identification for every stored device (after the rules changed). Two passes: the first lets devices with strong OS evidence
        teach their Wi-Fi signatures, the second identifies everything again with what was learned."""
        rows = self.conn.execute("SELECT * FROM devices").fetchall()
        self.conn.execute("BEGIN")
        for r in rows:
            if r["kind"] == "wifi_client":
                d = dict(r)
                d["extra"] = json.loads(d["extra"] or "{}")
                d["ident"] = identify.identify(d)["ident"]
                self._learn(d)
        for r in rows:
            d = dict(r)
            d["extra"] = json.loads(d["extra"] or "{}")
            res = identify.identify(d)
            self.conn.execute("UPDATE devices SET brand=?, model=?, dev_type=?, os=?, wifi_gen=?, era=?, ident=? "
                              "WHERE mac=?", (res["brand"], res["model"], res["dev_type"], res["os"],
                                              res["wifi_gen"], res["era"], json.dumps(res["ident"]), d["mac"]))
        self.conn.execute("COMMIT")
        if rows:
            log.info("Re-identified %d devices (identification rules v%d; %d Wi-Fi signatures learned from %d devices)", len(rows),
                     identify.IDENT_VERSION, len(self.learner.counts), len(self.learner.seen))

    # ------------------------------------------------------------------ input
    def command(self, fn):
        """Run fn(store) on the writer thread (keeps in-memory state consistent)."""
        self.q.put({"t": "_cmd", "fn": fn, "mac": "-"})

    def set_ignore(self, macs, prefixes, ssids, known_bssids=()):
        rules = IgnoreRules(set(macs) | self._env_macs(), prefixes, ssids)
        for bssid, ssid in known_bssids:
            if ssid in rules.ssids:
                rules.bssids[bssid] = rules.ssids[ssid]
        self.ignore = rules

    def set_meta(self, rows, groups):
        """rows: (mac, label, known, watch, group_id); groups: {id: name}."""
        self.important = {r[0] for r in rows if r[1] or r[2] or r[3] or r[4]}
        self.mac_group = {r[0]: r[4] for r in rows if r[4]}
        self.group_names = dict(groups)

    def forget(self, macs):
        """Drop devices from memory and delete their stored history (writer thread only)."""
        macs = set(macs)
        for table in (self.presence, self.assoc):
            for m in [m for m in table if m in macs]:
                del table[m]
        self.closed = [s for s in self.closed if s.mac not in macs]
        for m in macs:
            self.devices.pop(m, None)
            self.dirty.discard(m)
        self.buckets = {k: v for k, v in self.buckets.items() if k[0] not in macs}
        self.events = [e for e in self.events if e[1] not in macs]
        self.probe_updates = {k: v for k, v in self.probe_updates.items() if k[0] not in macs}
        c = self.conn
        c.execute("BEGIN")
        todo = sorted(macs)
        for i in range(0, len(todo), 400):  # in batches: one statement per table for 400 devices, not 400
            chunk = todo[i:i + 400]
            q = ",".join("?" * len(chunk))
            for sql, twice in (("DELETE FROM devices WHERE mac IN ({q})", False), ("DELETE FROM sessions WHERE mac IN ({q}) OR peer IN ({q})", True),
                               ("DELETE FROM samples WHERE mac IN ({q})", False), ("DELETE FROM presence_hours WHERE mac IN ({q})", False),
                               ("DELETE FROM events WHERE mac IN ({q}) OR peer IN ({q})", True), ("DELETE FROM probes WHERE mac IN ({q})", False),
                               ("DELETE FROM sightings WHERE mac IN ({q})", False)):
                c.execute(sql.format(q=q), chunk * 2 if twice else chunk)
        c.execute("COMMIT")
        log.info("Purged %d devices", len(macs))

    def retune(self):
        """Re-apply the cache settings to the writer's own connection (on the writer thread, which owns it)."""
        self.command(lambda s: tune(s.conn))

    def put(self, obs):
        try:
            self.q.put_nowait(obs)
        except queue.Full:
            self.dropped += 1

    def run(self, stop):
        last_flush = last_sweep = time.time()
        last_prune = 0
        while not stop.is_set():
            try:
                self.process(self.q.get(timeout=0.5))
                for _ in range(5000):
                    self.process(self.q.get_nowait())
            except queue.Empty:
                pass
            except Exception:
                log.exception("Failed to process observation")
            now = time.time()
            try:
                if now - last_sweep >= 5:
                    self.sweep(now)
                    last_sweep = now
                if now - last_flush >= self.cfg.flush_interval:
                    self.flush()
                    last_flush = now
                if now - last_prune >= 3600:
                    self.prune(now)
                    self.propagate_linked_os()
                    last_prune = now
            except Exception:
                log.exception("Store maintenance failed")
        # Shutdown: persist state without generating disconnect events.
        for s in list(self.presence.values()) + list(self.assoc.values()):
            self._close(s, "shutdown")
        self.flush()

    # ------------------------------------------------------------- processing
    def process(self, o):
        t = o["t"]
        if t == "_cmd":
            o["fn"](self)
            return
        if t in ("chan", "lan_traffic", "dhcp_server", "zb_network", "zb_energy", "zb_frames", "lora_frame"):  # aggregate observations, handled by plugins
            if self.macpriv is not None:
                o = self.macpriv.scrub(o)
            for h in self.hooks:
                if hasattr(h, "observe"):
                    h.observe(self, o, None)
            return
        if self.macpriv is not None:  # privacy mode: nothing below ever sees a full static address
            o = self.macpriv.scrub(o)
        mac = o.get("mac")
        if not mac or self.ignore.drop(o):
            return
        self.processed += 1
        ts, rssi = o["ts"], o.get("rssi")
        if rssi is not None:
            k = (mac, o.get("sensor") or "local")
            sg = self.sightings.get(k)
            if sg is None:
                self.sightings[k] = [ts, float(rssi)]
            else:
                sg[0], sg[1] = max(sg[0], ts), sg[1] * 0.7 + rssi * 0.3
            self.sightings_dirty.add(k)

        if t == "wifi_ap":
            dev = self._device(mac, "ap", ts, rssi, o, ("ssid", "channel", "freq", "band", "enc", "vendor"))
            self._presence(dev, ts, rssi)
            tsf = o.get("tsf")
            if isinstance(tsf, int) and tsf > 0:
                self._beacon_clock(dev, mac, o.get("sensor") or "local", ts, tsf)
            boot = ((o.get("extra") or {}).get("ap") or {}).get("boot")  # estimated boot time from the beacon timestamp
            if isinstance(boot, (int, float)):
                prev = self._boots.get(mac)
                if len(self._boots) > 5000:
                    self._boots.clear()
                self._boots[mac] = boot
                if prev and boot - prev > 90:  # its timer started over: the AP restarted (or reset its timer)
                    self._event(ts, mac, "ap_restart", None, "timer restarted (estimated from the beacon timestamp)", dev=dev, always=True)

        elif t == "wifi_client":
            dev = self._device(mac, "wifi_client", ts, rssi, o, ("channel", "freq", "band", "vendor"))
            self._presence(dev, ts, rssi)
            if o.get("seq") is not None and self.cfg.wifi_seq_link and dev.get("randomized"):
                for old, step in self.seq_linker.feed(mac, ts, o["seq"]):
                    self._link_same(dev, old, step, ts)
            bssid, frame = o.get("bssid"), o.get("frame")
            if frame in ("deauth", "disassoc"):
                s = self.assoc.get(mac)
                if s and (bssid is None or s.peer == bssid):
                    self._close(s, frame)
                    self._event(ts, mac, "disconnected", s.peer, f"{frame} reason {o.get('reason', '?')}",
                                dev=dev, always=True)
            elif bssid and frame in ("data", "assoc"):
                self._assoc(dev, bssid, ts, rssi)
            if o.get("probe"):
                self._probe(dev, o["probe"], ts)
            if frame == "probe":
                got = self.scans.feed(mac, ts)
                if got:
                    dev["extra"]["scan"] = got
                    self.dirty.add(mac)

        elif t == "bt":
            dev = self._device(mac, o["kind"], ts, rssi, o, ("name", "vendor"))
            self._presence(dev, ts, rssi)

        elif t == "bt_conn":
            dev = self._device(mac, o["kind"], ts, None, o, ("name",))
            peer = o.get("peer") or "local"
            s = self.assoc.get(mac)
            if o.get("connected"):
                if s and s.peer != peer:
                    self._close(s, "replaced")
                    s = None
                if s is None:
                    s = Session(mac, "assoc", peer, ts, bt=True, notimeout=True)
                    self.assoc[mac] = s
                    self._event(ts, mac, "connected", peer, o.get("detail"), dev=dev, always=True)
                s.touch(ts)
                self._presence(dev, ts, None)
            elif s:
                s.touch(ts, count=False)
                self._close(s, o.get("detail") or "disconnect")
                self._event(ts, mac, "disconnected", peer, o.get("detail"), dev=dev, always=True)

        elif t == "lan":
            dev = self._device(mac, LAN_KIND, ts, None, o, ("ip", "name"))
            self._presence(dev, ts, None)

        elif t == "event":
            dev = self.devices.get(mac)
            self._event(ts, mac, o["type"], o.get("peer"), o.get("detail"), dev=dev, always=True)

        if self.hooks:
            dev = self.devices.get(mac)
            for h in self.hooks:
                if hasattr(h, "observe"):
                    h.observe(self, o, dev)

    def _device(self, mac, kind, ts, rssi, o, field_names):
        dev = self.devices.get(mac)
        if dev is None:
            row = self.conn.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
            if row:
                dev = dict(row)
                dev["extra"] = json.loads(dev["extra"] or "{}")
                dev["ident"] = json.loads(dev["ident"] or "null")
            else:
                randomized = o.get("randomized")
                if randomized is None:
                    randomized = is_randomized_mac(mac) if kind in WIFI_KINDS else False
                vendor = o.get("vendor")
                if not vendor and not randomized and not (kind == "ble" and o.get("addr_random")):
                    vendor = self.vendors.lookup(mac)
                dev = {c: None for c in DEVICE_COLS}
                dev.update(mac=mac, kind=kind, first_seen=ts, last_seen=ts, vendor=vendor,
                           randomized=int(bool(randomized)), packets=0, extra={})
                self._event(ts, mac, "new_device", None, kind, dev=dev)
            self.devices[mac] = dev

        cur = dev["kind"]
        if cur == LAN_KIND and kind != LAN_KIND:
            dev["kind"] = kind  # a radio sighting is more specific than "seen on the LAN"
        elif cur != kind and cur != LAN_KIND and kind == LAN_KIND:
            pass  # a Wi-Fi/BT device also seen on the LAN keeps its kind
        elif cur != kind and KIND_RANK.get(kind, 0) > KIND_RANK.get(cur, 0) and \
                ((cur in WIFI_KINDS) == (kind in WIFI_KINDS)):
            dev["kind"] = kind
        if ts > (dev["last_seen"] or 0):
            dev["last_seen"] = ts
        if ts < (dev["first_seen"] or ts):
            dev["first_seen"] = ts
        dev["packets"] = (dev["packets"] or 0) + 1
        if rssi is not None:
            dev["last_rssi"] = rssi
            if dev["best_rssi"] is None or rssi > dev["best_rssi"]:
                dev["best_rssi"] = rssi
        for f in field_names:
            v = o.get(f)
            if isinstance(v, str):
                v = clean_str(v, 253 if f == "dns" else 128)
            if v is not None and v != "":
                dev[f] = v
        if o.get("extra"):
            dev["extra"].update({k: v for k, v in o["extra"].items() if v is not None})
            m = _COMPANY_RX.match(dev.get("vendor") or "")
            if m:
                dev["vendor"] = bt_company_known(int(m.group(1), 16))
            for k in ("company", "chip"):  # remote sensors on an older image still send "Company 0x0160"
                m = _COMPANY_RX.match(dev["extra"].get(k) or "")
                if m:
                    dev["extra"][k] = bt_company(int(m.group(1), 16))
        fp_changed = self._merge_fp(dev, o.get("fp"))
        ex = dev["extra"]
        key = (dev["kind"], dev["name"], dev["vendor"], dev["ssid"], dev["band"], dev["randomized"],
               ex.get("appearance"), ex.get("company"), ex.get("cod"), ex.get("class"))
        if fp_changed or dev.get("_ikey") != key or dev.get("ident") is None:
            dev["_ikey"] = key
            dev.update(identify.identify(dev))
            self._learn(dev)
        if dev["kind"] in ("ble", "bt_classic"):  # after identification: the model it found can give the version
            btversion.apply(dev["kind"], ex, dev.get("model"))
        self.dirty.add(mac)
        return dev

    def _merge_fp(self, dev, fp):
        """Merge a frame/advert fingerprint into the device; True if anything changed."""
        if not fp:
            return False
        store = dev["extra"].setdefault("fp", {})
        before = json.dumps(store, sort_keys=True)
        if fp.get("wifi"):
            store["wifi"] = identify.merge_wifi(store.get("wifi"), fp["wifi"])
            if fp.get("src") == "probe" and fp["wifi"].get("sig"):
                # Probe-request element layout is characteristic of chipset + OS build.
                dev["fp_hash"] = identify.probe_hash(fp["wifi"]["sig"])
        if fp.get("ble"):
            store["ble"] = identify.merge_ble(store.get("ble"), fp["ble"])
        if fp.get("lan"):
            store["lan"] = identify.merge_lan(store.get("lan"), fp["lan"])
        return json.dumps(store, sort_keys=True) != before

    def _presence(self, dev, ts, rssi):
        mac = dev["mac"]
        s = self.presence.get(mac)
        if s is None:
            s = Session(mac, "presence", None, ts, bt=dev["kind"] in BT_KINDS, lan=dev["kind"] == LAN_KIND)
            self.presence[mac] = s
            if ts - (dev["first_seen"] or ts) > 1:
                self._event(ts, mac, "arrived", None, None, dev=dev)
            g = self.mac_group.get(mac)
            if g:
                members = self.group_present.setdefault(g, set())
                if not members:
                    self._event(ts, mac, "group_arrived", f"group:{g}", self.group_names.get(g), always=True)
                members.add(mac)
        s.touch(ts, rssi)
        self._sample(mac, ts, rssi)

    def _assoc(self, dev, bssid, ts, rssi):
        mac = dev["mac"]
        s = self.assoc.get(mac)
        roamed_from = None
        if s and s.peer != bssid:
            roamed_from = s.peer
            self._close(s, "roamed")
            s = None
        if s is None:
            s = Session(mac, "assoc", bssid, ts)
            self.assoc[mac] = s
            if roamed_from:
                self._event(ts, mac, "roamed", bssid, f"from {roamed_from}", dev=dev, always=True)
            else:
                self._event(ts, mac, "connected", bssid, None, dev=dev, always=True)
        s.touch(ts, rssi)
        dev["bssid"] = bssid

    def _probe(self, dev, ssid, ts):
        ssid = clean_str(ssid, 64)
        if not ssid:
            return
        key = (dev["mac"], ssid)
        u = self.probe_updates.get(key)
        if u is None:
            if key not in self.known_probes:
                exists = self.conn.execute("SELECT 1 FROM probes WHERE mac=? AND ssid=?", key).fetchone()
                self.known_probes.add(key)
                if not exists:
                    self._event(ts, dev["mac"], "new_probe", None, ssid, dev=dev)
            self.probe_updates[key] = [ts, ts, 1]
        else:
            u[0], u[1], u[2] = min(u[0], ts), max(u[1], ts), u[2] + 1

    def _sample(self, mac, ts, rssi, count=True):
        key = (mac, int(ts // 60) * 60)
        b = self.buckets.get(key)
        if b is None:
            b = self.buckets[key] = [0, 0, 0, None, None]
        if count:
            b[0] += 1
        if rssi is not None:
            b[1] += rssi
            b[2] += 1
            b[3] = rssi if b[3] is None else min(b[3], rssi)
            b[4] = rssi if b[4] is None else max(b[4], rssi)

    def _event(self, ts, mac, type_, peer, detail, dev=None, always=False):
        if not always and not self.cfg.events_for_randomized and dev is not None and dev.get("randomized") \
                and mac not in self.important:
            return
        window = DEDUPE_EVENTS.get(type_)
        if window:
            k = (mac, type_, peer)
            if ts - self._last_event.get(k, 0) < window:
                return
            self._last_event[k] = ts
        self.events.append((ts, mac, type_, peer, detail))

    def _close(self, s, reason):
        s.open = False
        s.reason = reason
        s.dirty = True
        self.closed.append(s)
        table = self.presence if s.type == "presence" else self.assoc
        if table.get(s.mac) is s:
            del table[s.mac]

    def sweep(self, now):
        wifi_to, bt_to = self.cfg.wifi_session_timeout, self.cfg.bt_session_timeout
        for s in list(self.assoc.values()):
            if s.notimeout:
                # Connected to our own adapter: present for as long as the link is up.
                s.touch(now, count=False)
                p = self.presence.get(s.mac)
                if p:
                    p.touch(now, count=False)
                self._sample(s.mac, now, None, count=False)
            elif now - s.last > wifi_to:
                self._close(s, "timeout")
                self._event(s.last, s.mac, "disconnected", s.peer, "timeout", always=True)
        for s in list(self.presence.values()):
            if now - s.last > (bt_to if s.bt else self.cfg.lan_session_timeout if s.lan else wifi_to):
                self._close(s, "timeout")
                self._event(s.last, s.mac, "left", None, None, dev=self.devices.get(s.mac))
                g = self.mac_group.get(s.mac)
                members = self.group_present.get(g)
                if members and s.mac in members:
                    members.discard(s.mac)
                    if not members:
                        self._event(s.last, s.mac, "group_left", f"group:{g}", self.group_names.get(g),
                                    always=True)
        for h in self.hooks:
            if hasattr(h, "sweep"):
                h.sweep(self, now)
        # Evict idle devices from the cache.
        for mac in [m for m, d in self.devices.items()
                    if m not in self.presence and m not in self.assoc and m not in self.dirty
                    and now - (d["last_seen"] or 0) > 900]:
            del self.devices[mac]
        if len(self.known_probes) > 200_000:
            self.known_probes.clear()
        if len(self._last_event) > 50_000:
            self._last_event.clear()

    # ------------------------------------------------------------- persistence
    def flush(self):
        c = self.conn
        sessions = [s for s in list(self.presence.values()) + list(self.assoc.values()) if s.dirty]
        sessions += self.closed
        if not (self.dirty or sessions or self.buckets or self.events or self.probe_updates or
                self.sightings_dirty or any(getattr(h, "pending", False) for h in self.hooks)):
            return
        c.execute("BEGIN")
        try:
            rows = []
            for mac in self.dirty:
                d = self.devices.get(mac)
                if d:
                    rows.append(tuple(json.dumps(d[k]) if k in JSON_COLS else d[k] for k in DEVICE_COLS))
            c.executemany(f"INSERT OR REPLACE INTO devices({','.join(DEVICE_COLS)}) "
                          f"VALUES({','.join('?' * len(DEVICE_COLS))})", rows)
            for s in sessions:
                vals = (s.start, s.last, s.packets, s.rmin, s.rmax, s.rsum, s.rcnt, int(s.open), s.reason)
                if s.id is None:
                    cur = c.execute(
                        "INSERT INTO sessions(mac,type,peer,start_ts,end_ts,packets,rssi_min,rssi_max,"
                        "rssi_sum,rssi_count,open,end_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (s.mac, s.type, s.peer) + vals)
                    s.id = cur.lastrowid
                else:
                    c.execute("UPDATE sessions SET start_ts=?,end_ts=?,packets=?,rssi_min=?,rssi_max=?,"
                              "rssi_sum=?,rssi_count=?,open=?,end_reason=? WHERE id=?", vals + (s.id,))
                s.dirty = False
            c.executemany(
                "INSERT INTO samples(mac,minute,packets,rssi_sum,rssi_count,rssi_min,rssi_max) "
                "VALUES(?,?,?,?,?,?,?) ON CONFLICT(mac,minute) DO UPDATE SET "
                "packets=packets+excluded.packets, rssi_sum=rssi_sum+excluded.rssi_sum, "
                "rssi_count=rssi_count+excluded.rssi_count, "
                "rssi_min=MIN(COALESCE(rssi_min,excluded.rssi_min),COALESCE(excluded.rssi_min,rssi_min)), "
                "rssi_max=MAX(COALESCE(rssi_max,excluded.rssi_max),COALESCE(excluded.rssi_max,rssi_max))",
                [(m, mi, *b) for (m, mi), b in self.buckets.items()])
            c.executemany("INSERT OR IGNORE INTO presence_hours(hour, mac) VALUES(?,?)",
                          {(mi // 3600 * 3600, m) for (m, mi) in self.buckets})
            c.executemany("INSERT INTO events(ts,mac,type,peer,detail) VALUES(?,?,?,?,?)", self.events)
            c.executemany(
                "INSERT INTO probes(mac,ssid,first_seen,last_seen,count) VALUES(?,?,?,?,?) "
                "ON CONFLICT(mac,ssid) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen), "
                "count=count+excluded.count",
                [(m, s, *u) for (m, s), u in self.probe_updates.items()])
            c.executemany("INSERT OR REPLACE INTO sightings(mac, sensor, last_seen, rssi) VALUES(?,?,?,?)",
                          [(m, sn, *self.sightings[(m, sn)]) for m, sn in self.sightings_dirty
                           if (m, sn) in self.sightings])
            for h in self.hooks:
                if hasattr(h, "flush"):
                    h.flush(self, c)
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
        new_events = [{"ts": e[0], "mac": e[1], "type": e[2], "peer": e[3], "detail": e[4]} for e in self.events]
        self.dirty.clear()
        self.closed.clear()
        self.buckets.clear()
        self.events.clear()
        self.probe_updates.clear()
        self.sightings_dirty.clear()
        if len(self.sightings) > 100_000:
            cutoff = time.time() - 3600
            self.sightings = {k: v for k, v in self.sightings.items() if v[0] > cutoff}
        for fn in self.listeners:
            try:
                fn(new_events)
            except Exception:
                log.exception("Event listener failed")

    def prune(self, now):
        day = 86400
        cut = lambda kind: now - self.retention_days(kind) * day  # noqa: E731
        cutoff = now - self.cfg.retention_days * day
        c = self.conn
        c.execute("BEGIN")
        c.execute("DELETE FROM samples WHERE minute < ?", (cut("history"),))
        c.execute("DELETE FROM presence_hours WHERE hour < ?", (cut("history"),))
        c.execute("DELETE FROM events WHERE ts < ?", (cut("events"),))
        c.execute("DELETE FROM sessions WHERE open=0 AND end_ts < ?", (cut("sessions"),))
        c.execute("DELETE FROM probes WHERE last_seen < ?", (cut("probes"),))
        c.execute("DELETE FROM devices WHERE last_seen < ? AND mac NOT IN (SELECT mac FROM device_meta)", (cut("devices"),))
        c.execute("DELETE FROM sightings WHERE last_seen < ?", (cut("sightings"),))
        for h in self.hooks:
            if hasattr(h, "prune"):
                h.prune(self, c, cutoff)
        c.execute("COMMIT")
        c.execute("PRAGMA optimize")

    def stats(self):
        try:
            size = os.path.getsize(self.cfg.db_path)
        except OSError:
            size = 0
        return {"queue": self.q.qsize(), "dropped": self.dropped, "processed": self.processed,
                "open_presence": len(self.presence), "open_connections": len(self.assoc),
                "db_bytes": size}
