"""Zigbee / IEEE 802.15.4 monitoring through a USB coordinator stick: the sensor thread, a store plugin and the API.

Between network scans the sensor listens passively to all 802.15.4 traffic on one or more channels, which also picks
up systems other than Zigbee. It never transmits. See zigbee_radio.py for the protocol side.
"""
import json
import logging
import os
import threading
import time

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from . import adapters, status
from .auth import current_user, require_admin
from .zigbee_radio import (ALL_CHANNELS, CAP_MAINS, CAP_RX_IDLE, HINTS, ROLE_GP_SWITCH, ROLE_GREEN_POWER, ROLE_LABELS, ROUTER_MASK, TYPE_NAMES, FrameBatch,
                           NoCaptureMode, ZigbeeError, capability_labels, detect, role_of)

from .modules import cutoff_for
from .radiowatch import watch_map
from .web_util import csv_response

log = logging.getLogger("sniffowireless.zigbee")

SCHEMA = """
CREATE TABLE IF NOT EXISTS zigbee_networks(
  ext_pan TEXT NOT NULL, pan INTEGER NOT NULL, channel INTEGER NOT NULL, permit_join INTEGER, stack_profile INTEGER,
  update_id INTEGER, lqi INTEGER, rssi INTEGER, routers TEXT, vendor TEXT, first_seen REAL, last_seen REAL,
  sightings INTEGER DEFAULT 0, protocol TEXT DEFAULT 'zigbee', name TEXT, version INTEGER, PRIMARY KEY(ext_pan, pan, channel)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_zigbee_networks_last ON zigbee_networks(last_seen);
CREATE TABLE IF NOT EXISTS zigbee_radios(
  pan INTEGER NOT NULL, addr TEXT NOT NULL, channels INTEGER DEFAULT 0, sent INTEGER DEFAULT 0, received INTEGER DEFAULT 0,
  encrypted INTEGER DEFAULT 0, hint INTEGER DEFAULT 0, types INTEGER DEFAULT 0, rssi INTEGER, lqi INTEGER, vendor TEXT,
  first_seen REAL, last_seen REAL, PRIMARY KEY(pan, addr)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_zigbee_radios_last ON zigbee_radios(last_seen);
-- which radios / nodes were heard in each 5 minutes (zigbee and lora), for the overview's active-devices graph
CREATE TABLE IF NOT EXISTS radio_seen(
  slot INTEGER NOT NULL, kind TEXT NOT NULL, addr TEXT NOT NULL, PRIMARY KEY(slot, kind, addr)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS zigbee_channels(
  minute INTEGER NOT NULL, channel INTEGER NOT NULL, frames INTEGER DEFAULT 0, PRIMARY KEY(minute, channel)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS zigbee_energy(
  minute INTEGER NOT NULL, channel INTEGER NOT NULL, rssi INTEGER, PRIMARY KEY(minute, channel)) WITHOUT ROWID;
"""
OBSERVATIONS = ("zb_network", "zb_energy", "zb_frames")
HINT_LABELS = {"unknown": "Unknown protocol", "encrypted": "Encrypted at the radio layer, protocol unknown",
               "thread": "Looks like Thread / 6LoWPAN", "zigbee": "Looks like Zigbee"}


def device_guess(addr, roles, caps, hint):
    """What kind of device a radio probably is, in words, from what its unencrypted headers showed: its role, what its join request
    said about power and sleep, and (Zigbee) the coordinator's fixed address. A guess to help recognise it, never a product name."""
    if roles & ROLE_GREEN_POWER:
        return "Battery-less switch (Green Power)" if roles & ROLE_GP_SWITCH else "Battery-less switch or sensor (Green Power)"
    if hint == "zigbee" and addr == "0x0000":
        return "Coordinator (the hub or gateway of this network)"
    router = bool(roles & ROUTER_MASK)
    if caps is not None:
        if caps & CAP_MAINS:
            return "Mains-powered device (plug, bulb, switch or repeater)"
        return "Battery device that stays awake" if caps & CAP_RX_IDLE else "Battery device that sleeps (sensor, remote or button)"
    if router:
        return "Thread router (mains powered, or a border router)" if hint == "thread" else "Router: mains powered (plug, bulb or repeater)"
    if role_of(roles) == "end device":
        return "Sleepy end device: battery powered (sensor, remote or button)"
    return None


BAUD_RATE = 115200
REPORT_INTERVAL = 10
RETRY_INTERVAL = 30


class SerialLink:
    """A stick on a serial port. No flow control is enabled: the parsers drop XON/XOFF, and frames are short."""

    def __init__(self, path):
        import serial
        self.port = serial.Serial(path, BAUD_RATE, timeout=0.1, rtscts=False, dsrdtr=False, xonxoff=False)

    def write(self, data):
        self.port.write(data)

    def read(self, timeout):
        self.port.timeout = timeout
        return self.port.read(max(1, self.port.in_waiting))

    def set_pins(self, dtr, rts):
        self.port.dtr, self.port.rts = dtr, rts

    def close(self):
        self.port.close()


OVERRIDE_KEYS = ("channels", "hop_interval", "scan_interval", "sniff")
HOP_MIN, HOP_MAX = 0.2, 600.0
SCAN_MIN, SCAN_MAX = 30, 86400


def parse_channels(spec):
    """'15,20-25' -> [15, 20, ..., 25]; ValueError saying what is wrong. 802.15.4's 2.4 GHz channels are 11-26."""
    out = []
    for tok in [t.strip() for t in str(spec).split(",") if t.strip()]:
        lo, _, hi = tok.partition("-")
        try:
            a, b = int(lo), int(hi or lo)
        except ValueError:
            raise ValueError(f"'{tok}' is not a channel number or range like 20-25")
        if not (11 <= a <= 26 and 11 <= b <= 26) or a > b:
            raise ValueError(f"'{tok}': Zigbee channels are 11 to 26")
        out.extend(c for c in range(a, b + 1) if c not in out)
    if not out:
        raise ValueError("The channel list is empty")
    return out


def clean_override(o):
    """Only the known keys with their values checked (ValueError saying what is wrong); None means 'the sensor's own setting'."""
    o = o if isinstance(o, dict) else {}
    out = {"channels": None, "hop_interval": None, "scan_interval": None, "sniff": None}
    if o.get("channels") not in (None, ""):
        if not isinstance(o["channels"], str) or len(o["channels"]) > 200:
            raise ValueError("The channel list is too long")
        out["channels"] = ",".join(str(c) for c in parse_channels(o["channels"]))
    for key, lo, hi, label in (("hop_interval", HOP_MIN, HOP_MAX, "The time on each channel"),
                               ("scan_interval", SCAN_MIN, SCAN_MAX, "The time between network scans")):
        if o.get(key) not in (None, ""):
            try:
                v = float(o[key])
            except (TypeError, ValueError):
                raise ValueError(f"{label} is a number of seconds")
            if not lo <= v <= hi:
                raise ValueError(f"{label} must be between {lo:g} and {hi:g} seconds")
            out[key] = int(v) if key == "scan_interval" else v
    if o.get("sniff") is not None:
        out["sniff"] = bool(o["sniff"])
    return out


class ZigbeeControl:
    """Which channels the Zigbee sticks of this process listen on, for how long on each, how often they scan and whether they
    listen passively at all. Starts from ZIGBEE_* and takes an override on top while running: set in the web UI (settings key
    "zigbee") for this server, or sent in the ingest reply for a remote sensor, which reports the revision it runs (`zb_rev`)."""

    def __init__(self, cfg, override=None, rev=0):
        self.cfg, self.rev = cfg, rev
        self.override = clean_override(override) if override else None
        self.lock = threading.Lock()
        self.sensors = []
        self._rejected_rev = None

    def effective(self):
        o = self.override or {}
        channels = parse_channels(o["channels"]) if o.get("channels") else list(self.cfg.zigbee_channels)
        return {"channels": channels, "hop_interval": float(o.get("hop_interval") or self.cfg.zigbee_hop_interval),
                "scan_interval": int(o.get("scan_interval") or self.cfg.zigbee_scan_interval),
                "sniff": self.cfg.zigbee_sniff if o.get("sniff") is None else bool(o["sniff"])}

    def apply(self, override, rev):
        """Switch to new settings (ValueError, nothing changed, if they are not valid). The sticks pick them up within a second or two."""
        override = clean_override(override) if override else None
        if override and all(v is None for v in override.values()):
            override = None
        with self.lock:
            self.override, self.rev = override, rev
        for s in list(self.sensors):
            s.publish()

    def apply_local(self, settings):
        entry = (settings.get("local") or {}) if isinstance(settings, dict) else {}
        rev = entry.get("rev") or 0
        if rev != self.rev:
            try:
                self.apply({k: entry.get(k) for k in OVERRIDE_KEYS}, rev)
            except ValueError as e:
                log.warning("Ignoring the Zigbee settings: %s", e)

    def apply_remote(self, conf):
        if not isinstance(conf, dict) or not isinstance(conf.get("rev"), int) or conf["rev"] == self.rev or conf["rev"] == self._rejected_rev:
            return
        try:
            self.apply({k: conf.get(k) for k in OVERRIDE_KEYS}, conf["rev"])
            log.info("Zigbee settings from the server applied (revision %d)", conf["rev"])
        except ValueError as e:
            self._rejected_rev = conf["rev"]
            log.warning("Ignoring Zigbee settings from the server (revision %d): %s", conf["rev"], e)


def attach(ctx):
    """The server's own Zigbee control, started from the saved settings and kept in step with later changes."""
    entry = ctx.settings.get("zigbee")["local"] or {}
    try:
        control = ZigbeeControl(ctx.cfg, {k: entry.get(k) for k in OVERRIDE_KEYS} if entry else None, entry.get("rev") or 0)
    except ValueError as e:
        log.warning("Ignoring the saved Zigbee settings (%s); using the environment", e)
        control = ZigbeeControl(ctx.cfg)
    ctx.zigbee_control = control
    ctx.settings.on_change(lambda k: control.apply_local(ctx.settings.get("zigbee")) if k == "zigbee" else None)
    return control


class ZigbeeSensor:
    def __init__(self, device, cfg, sink, link_factory=SerialLink, control=None):
        self.device, self.cfg, self.sink, self.link_factory = device, cfg, sink, link_factory
        self.control = control or ZigbeeControl(cfg)
        self.control.sensors.append(self)
        self.name = f"zigbee:{os.path.basename(device)}"
        self.stop = None
        self.no_capture = False
        self.packets = 0
        self.link, self.reset_requested = None, threading.Event()
        adapters.REGISTRY[self.name] = self
        status.register(self.name, type="zigbee", iface=device)
        self.publish()

    def publish(self):
        status.update(self.name, zb_rev=self.control.rev, zb_channels=self.control.effective()["channels"])

    def start(self, stop):
        self.stop = stop
        threading.Thread(target=self._loop, daemon=True, name=self.name).start()

    def _loop(self):
        while not self.stop.is_set():
            link = None
            try:
                link = self.link = self.link_factory(self.device)
                self.run(link)
            except Exception as e:  # serial errors depend on the platform; a replug must not end the thread
                log.warning("%s: %s", self.name, e)
                status.update(self.name, state="error", error=str(e)[:200])
            finally:
                if link is not None:
                    try:
                        link.close()
                    except Exception:
                        pass
            self._retry_wait()

    def reset(self, usb=False):
        """Close the serial link so the loop opens it (and runs the handshake) again at once; optionally reset the USB device too."""
        steps = ["serial link closed, reconnecting"]
        self.reset_requested.set()
        link = self.link
        if link is not None:
            try:
                link.close()
            except Exception:
                pass
        if usb:
            steps.insert(0, adapters.usb_reset("/sys/class/tty/" + os.path.basename(os.path.realpath(self.device)) + "/device"))
        return steps

    def _retry_wait(self):
        """Between attempts: the usual pause, cut short by a reset request."""
        end = time.monotonic() + RETRY_INTERVAL
        while not self.stop.is_set() and not self.reset_requested.is_set() and time.monotonic() < end:
            self.stop.wait(1)
        self.reset_requested.clear()

    def run(self, link):
        family, last_scan = None, None
        while not self.stop.is_set():
            status.update(self.name, state="connecting", error=None)
            driver = detect(link, family, self.stop)
            if driver is None:
                if self.stop.is_set():
                    return
                raise ZigbeeError("This stick didn't answer as an EmberZNet or Z-Stack coordinator. It may have router or "
                                  "Thread firmware, or another program may be using it")
            family = driver.family
            status.update(self.name, firmware=driver.firmware, warning=" ".join(driver.notes) or None)
            eff = self.control.effective()
            if last_scan is None or time.monotonic() >= last_scan + eff["scan_interval"]:
                self.scan(driver)
                last_scan = time.monotonic()
                eff = self.control.effective()
                if not (eff["sniff"] and driver.can_capture and not self.no_capture):
                    continue  # the next pass waits below; EZSP restarts cleanly when it comes round again
            rev = self.control.rev
            next_scan = last_scan + eff["scan_interval"]
            if eff["sniff"] and driver.can_capture and not self.no_capture:
                try:
                    self.capture(driver, next_scan, eff, rev)
                except NoCaptureMode as e:
                    log.warning("%s: %s", self.name, e)
                    self.no_capture = True
                    status.update(self.name, warning=str(e))
            else:
                status.update(self.name, state="idle", channel=None)
                while not self.stop.is_set() and self.control.rev == rev and time.monotonic() < next_scan:
                    self.stop.wait(min(1.0, max(0.0, next_scan - time.monotonic())))

    def scan(self, driver):
        status.update(self.name, state="scanning", channel=None)
        now = time.time()
        energy = []
        driver.scan(lambda n: self.sink.put({"t": "zb_network", "ts": now, "mac": "-", **n}),
                    lambda ch, rssi: energy.append([ch, rssi]), self.stop)
        if energy:
            self.sink.put({"t": "zb_energy", "ts": now, "mac": "-", "readings": energy})

    def capture(self, driver, next_scan, eff, rev):
        batch = FrameBatch()
        last_report = [time.monotonic()]

        def on_frame(captured):
            batch.add(captured)
            self.packets += 1
            now = time.monotonic()
            if now - last_report[0] >= REPORT_INTERVAL:
                self._report(batch)
                last_report[0] = now

        def until():
            # Quiet channels produce no frames, so this also has to flush what a lone frame left behind.
            now = time.monotonic()
            if now - last_report[0] >= REPORT_INTERVAL:
                self._report(batch)
                last_report[0] = now
            return self.stop.is_set() or now >= next_scan or self.control.rev != rev  # new settings: start over with them

        status.update(self.name, state="capturing", error=None)
        try:
            driver.capture(eff["channels"], eff["hop_interval"], until,
                           lambda ch: status.update(self.name, channel=str(ch)), on_frame)
        finally:
            self._report(batch)

    def _report(self, batch):
        o = batch.drain(time.time())
        if o:
            self.sink.put(o)
        status.update(self.name, packets=self.packets)


SEEN_SLOT = 300  # radio_seen granularity, seconds


class ZigbeeMonitor:
    """Store plugin (writer thread)."""

    def __init__(self, ctx):
        self.ctx = ctx
        ctx.store.conn.executescript(SCHEMA)
        have = {r[1] for r in ctx.store.conn.execute("PRAGMA table_info(zigbee_networks)")}
        for col, typ in (("protocol", "TEXT DEFAULT 'zigbee'"), ("name", "TEXT"), ("version", "INTEGER")):  # Thread networks (added after the first release)
            if col not in have:
                ctx.store.conn.execute(f"ALTER TABLE zigbee_networks ADD COLUMN {col} {typ}")
        have = {r[1] for r in ctx.store.conn.execute("PRAGMA table_info(zigbee_radios)")}
        for col, typ in (("roles", "INTEGER DEFAULT 0"), ("eui", "TEXT"), ("caps", "INTEGER")):   # behaviour seen in the radio's frames, 64-bit address from the network header
            if col not in have:
                ctx.store.conn.execute(f"ALTER TABLE zigbee_radios ADD COLUMN {col} {typ}")
        ctx.store.conn.execute("UPDATE zigbee_networks SET vendor=NULL WHERE vendor IS NOT NULL")  # older versions guessed one from the extended PAN ID
        self.networks = {}
        self.radios = {}
        self.channels = {}
        self.energy = {}
        self.seen = set()
        self.known_nets, self.open_nets = set(), set()  # for "new network" and "joining opened" events
        try:
            for ext, pan, ch, permit in ctx.store.conn.execute("SELECT ext_pan, pan, channel, permit_join FROM zigbee_networks"):
                self.known_nets.add((ext, pan, ch))
                if permit:
                    self.open_nets.add((ext, pan, ch))
        except Exception:
            pass
        self.pending = False

    def _vendor(self, store, address):
        """A radio's 64-bit address is an IEEE address, so its first bytes name the maker (still shown with a question mark: the label is a hint).
        Short addresses have none, and a network's extended PAN ID is not used at all: the coordinator chooses it, many pick random bytes
        (Zigbee2MQTT, ZHA), and no frame we hear confirms that one is derived from the maker's own address."""
        if not address or address.startswith(("0x", "gpd:")) or int(address[:2], 16) & 2:
            return None
        return store.vendors.lookup(address)

    def observe(self, store, o, dev):
        t = o["t"]
        if t == "zb_network":
            self._network(store, o)
        elif t == "zb_energy":
            minute = int(o["ts"] // 60) * 60
            for ch, rssi in o.get("readings") or []:
                self.energy[(minute, ch)] = rssi
            self.pending = True
        elif t == "zb_frames":
            self._frames(store, o)

    def reset(self, module):
        """Forget what is remembered about what Settings -> Clear data deleted (new networks raise events again)."""
        if module == "zigbee":
            self.networks, self.radios, self.channels, self.energy, self.seen = {}, {}, {}, {}, set()
            self.known_nets, self.open_nets, self.pending = set(), set(), False

    def _network(self, store, o):
        key = (o["ext_pan"], o["pan"], o["channel"])
        mac = f"zb:{o['pan']:04x}"
        thread = o.get("protocol") == "thread"
        label = f"Thread network “{o['name']}”" if thread and o.get("name") else "Thread network" if thread else "Zigbee network"
        if key not in self.known_nets and len(self.known_nets) < 10_000:
            self.known_nets.add(key)
            store._event(o["ts"], mac, "zigbee_new_network", f"ext:{o['ext_pan']}",
                         f"New {label}: PAN 0x{o['pan']:04x} on channel {o['channel']}, extended ID {o['ext_pan']}", always=True)
        if o.get("permit_join") and key not in self.open_nets:
            self.open_nets.add(key)
            store._event(o["ts"], mac, "zigbee_permit_join", f"ext:{o['ext_pan']}",
                         f"{label[0].upper() + label[1:]} PAN 0x{o['pan']:04x} (channel {o['channel']}) is accepting new devices", always=True)
        elif not o.get("permit_join"):
            self.open_nets.discard(key)
        n = self.networks.get(key)
        if n is None:
            n = self.networks[key] = {"permit_join": False, "lqi": None, "rssi": None, "routers": set(),
                                      "first": o["ts"], "sightings": 0}
        # Several routers of one network each answer a scan: combine them, keeping the best signal.
        n["permit_join"] = n["permit_join"] or bool(o.get("permit_join"))
        n["lqi"] = max((v for v in (n["lqi"], o.get("lqi")) if v is not None), default=None)
        n["rssi"] = max((v for v in (n["rssi"], o.get("rssi")) if v is not None), default=None)
        n["routers"].update(o.get("routers") or [])
        n["stack_profile"], n["update_id"], n["last"] = o.get("stack_profile"), o.get("update_id"), o["ts"]
        n["protocol"], n["name"], n["version"] = o.get("protocol") or "zigbee", o.get("name") or None, o.get("version")
        n["vendor"] = None  # no maker is guessed from the extended PAN ID: the coordinator picks it, often at random (see _vendor)
        n["sightings"] += 1
        self.pending = True

    def _frames(self, store, o):
        ts = o["ts"]
        minute = int(ts // 60) * 60
        for ch, frames in (o.get("channels") or {}).items():
            k = (minute, int(ch))
            self.channels[k] = self.channels.get(k, 0) + frames
        for t in o.get("networks") or []:  # Thread networks that announced themselves in a beacon we heard
            self._network(store, {"ts": ts, "protocol": "thread", "ext_pan": t["ext_pan"], "pan": t["pan"], "channel": t["channel"],
                                  "permit_join": t.get("joining"), "name": t.get("name"), "version": t.get("version"),
                                  "lqi": t.get("lqi"), "rssi": t.get("rssi"), "routers": []})
        for pan, addr, channels, sent, received, encrypted, hint, types, rssi, lqi in o.get("radios") or []:
            if len(self.seen) < 100_000:
                self.seen.add((int(ts // SEEN_SLOT) * SEEN_SLOT, f"{pan}:{addr}"))
            r = self.radios.get((pan, addr))
            if r is None:
                self.radios[(pan, addr)] = {
                    "channels": channels, "sent": sent, "received": received, "encrypted": encrypted, "hint": hint,
                    "types": types, "rssi": rssi, "lqi": lqi, "vendor": self._vendor(store, addr), "first": ts, "last": ts,
                    "roles": 0, "eui": None, "caps": None}
                continue
            r["channels"] |= channels
            r["types"] |= types
            r["sent"] += sent
            r["received"] += received
            r["encrypted"] += encrypted
            r["hint"] = max(r["hint"], hint)
            r["last"] = ts
            if rssi is not None:
                r["rssi"], r["lqi"] = rssi, lqi
        for pan, addr, roles, eui in o.get("detail") or []:
            r = self.radios.get((pan, addr))
            if r is None:
                continue
            r["roles"] |= roles
            if eui:
                r["eui"] = eui
                if r["vendor"] is None:   # a short address has no maker; the 64-bit address the radio announced in its network header does
                    r["vendor"] = self._vendor(store, eui)
        for pan, addr, roles, caps in o.get("more") or []:
            r = self.radios.get((pan, addr))
            if r is None:
                continue
            r["roles"] |= roles
            if caps is not None:
                r["caps"] = caps
        self.pending = True

    def flush(self, store, c):
        if not self.pending:
            return
        for (ext_pan, pan, channel), n in self.networks.items():
            row = c.execute("SELECT routers FROM zigbee_networks WHERE ext_pan=? AND pan=? AND channel=?",
                            (ext_pan, pan, channel)).fetchone()
            routers = n["routers"] | set(json.loads(row[0] or "[]") if row else [])
            c.execute(
                "INSERT INTO zigbee_networks(ext_pan, pan, channel, permit_join, stack_profile, update_id, lqi, rssi, routers, vendor, "
                "first_seen, last_seen, sightings, protocol, name, version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(ext_pan, pan, channel) DO UPDATE "
                "SET permit_join=excluded.permit_join, stack_profile=excluded.stack_profile, update_id=excluded.update_id, "
                "lqi=excluded.lqi, rssi=excluded.rssi, routers=excluded.routers, vendor=COALESCE(excluded.vendor, vendor), "
                "last_seen=excluded.last_seen, sightings=sightings+excluded.sightings, protocol=excluded.protocol, "
                "name=COALESCE(excluded.name, name), version=COALESCE(excluded.version, version)",
                (ext_pan, pan, channel, int(n["permit_join"]), n.get("stack_profile"), n.get("update_id"), n["lqi"], n["rssi"],
                 json.dumps(sorted(routers)), n["vendor"], n["first"], n["last"], n["sightings"], n.get("protocol", "zigbee"),
                 n.get("name"), n.get("version")))
        c.executemany(
            "INSERT INTO zigbee_radios(pan, addr, channels, sent, received, encrypted, hint, types, rssi, lqi, vendor, first_seen, last_seen, roles, eui, caps) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(pan, addr) DO UPDATE SET roles=roles|excluded.roles, eui=COALESCE(excluded.eui, eui), "
            "caps=COALESCE(excluded.caps, caps), "
            "channels=channels|excluded.channels, sent=sent+excluded.sent, received=received+excluded.received, "
            "encrypted=encrypted+excluded.encrypted, hint=MAX(hint, excluded.hint), types=types|excluded.types, "
            "rssi=COALESCE(excluded.rssi, rssi), lqi=COALESCE(excluded.lqi, lqi), "
            "vendor=COALESCE(excluded.vendor, vendor), last_seen=excluded.last_seen",
            [(pan, addr, r["channels"], r["sent"], r["received"], r["encrypted"], r["hint"], r["types"], r["rssi"], r["lqi"],
              r["vendor"], r["first"], r["last"], r["roles"], r["eui"], r.get("caps")) for (pan, addr), r in self.radios.items()])
        c.executemany("INSERT INTO zigbee_channels VALUES(?,?,?) ON CONFLICT(minute, channel) DO UPDATE SET "
                      "frames=frames+excluded.frames", [(m, ch, n) for (m, ch), n in self.channels.items()])
        c.executemany("INSERT OR REPLACE INTO zigbee_energy VALUES(?,?,?)",
                      [(m, ch, rssi) for (m, ch), rssi in self.energy.items()])
        c.executemany("INSERT OR IGNORE INTO radio_seen VALUES(?, 'zigbee', ?)", list(self.seen))
        self.seen.clear()
        self.networks.clear()
        self.radios.clear()
        self.channels.clear()
        self.energy.clear()
        self.pending = False

    def prune(self, store, c, cutoff):
        cutoff = cutoff_for(self.ctx, "zigbee", cutoff)
        c.execute("DELETE FROM zigbee_networks WHERE last_seen < ?", (cutoff,))
        c.execute("DELETE FROM zigbee_radios WHERE last_seen < ?", (cutoff,))
        c.execute("DELETE FROM zigbee_channels WHERE minute < ?", (cutoff,))
        c.execute("DELETE FROM zigbee_energy WHERE minute < ?", (cutoff,))
        c.execute("DELETE FROM radio_seen WHERE kind='zigbee' AND slot < ?", (cutoff,))


def _channels(mask):
    return [c for c in ALL_CHANNELS if mask >> c & 1]


class ZigbeeConfig(BaseModel):
    channels: Optional[str] = None          # None / "" = the sensor's own ZIGBEE_CHANNELS
    hop_interval: Optional[float] = None
    scan_interval: Optional[float] = None
    sniff: Optional[bool] = None            # None = the sensor's own ZIGBEE_SNIFF


def routes(ctx):
    r = APIRouter()

    # ---- which channels each stick listens on (this server's and the remote sensors')
    def sticks(target):
        out = []
        for s in status.snapshot():
            if s.get("type") != "zigbee" or (target == "local") != (s.get("remote") is None) or (target != "local" and s.get("remote") != target):
                continue
            out.append({k: s.get(k) for k in ("iface", "name", "state", "error", "channel", "zb_channels", "zb_rev", "warning", "packets", "firmware")})
        return sorted(out, key=lambda a: a["iface"] or "")

    def zb_target(target, name, online):
        cfg_all = ctx.settings.get("zigbee")
        entry = (cfg_all["local"] if target == "local" else cfg_all["sensors"].get(target)) or None
        boards = sticks(target)
        rev = (entry or {}).get("rev") or 0
        return {"id": target, "name": name, "online": online, "config": ({k: entry.get(k) for k in ("rev",) + OVERRIDE_KEYS} if entry else None),
                "sticks": boards, "applied": bool(boards) and all((b.get("zb_rev") or 0) == rev for b in boards) if online else None,
                "too_old": target != "local" and online and bool(boards) and any(b.get("zb_rev") is None for b in boards)}

    def zb_check(target):
        if target != "local" and not ctx.one("SELECT 1 FROM sensors WHERE id=?", (target,)):
            raise HTTPException(404, "No such sensor")

    def zb_store(target, override):
        cfg_all = ctx.settings.get("zigbee")
        old = (cfg_all["local"] if target == "local" else cfg_all["sensors"].get(target)) or {}
        new = {"rev": (old.get("rev") or 0) + 1, **{k: override[k] for k in OVERRIDE_KEYS}}
        if target == "local":
            cfg_all["local"] = new
        else:
            cfg_all["sensors"][target] = new
        ctx.settings.set("zigbee", cfg_all)  # on_change applies it to this server's sticks
        return new

    @r.get("/api/zigbee-settings")
    def get_zigbee_settings(_=Depends(require_admin)):
        now = time.time()
        out = [zb_target("local", "This server", True)]
        for s in ctx.rows("SELECT id, name, last_seen FROM sensors WHERE id != 'local' ORDER BY name"):
            out.append(zb_target(s["id"], s["name"], (s["last_seen"] or 0) > now - 60))
        return {"targets": out, "defaults": {"channels": ",".join(map(str, ctx.cfg.zigbee_channels)), "hop_interval": ctx.cfg.zigbee_hop_interval,
                                             "scan_interval": ctx.cfg.zigbee_scan_interval, "sniff": ctx.cfg.zigbee_sniff}}

    @r.put("/api/zigbee-settings/{target}")
    def put_zigbee_settings(target: str, body: ZigbeeConfig, _=Depends(require_admin)):
        zb_check(target)
        try:
            override = clean_override(body.model_dump())
        except ValueError as e:
            raise HTTPException(400, str(e))
        return {"ok": True, "config": zb_store(target, override)}

    @r.delete("/api/zigbee-settings/{target}")
    def reset_zigbee_settings(target: str, _=Depends(require_admin)):
        """Back to the sensor's own settings (ZIGBEE_CHANNELS and the like)."""
        zb_check(target)
        return {"ok": True, "config": zb_store(target, clean_override({}))}

    @r.get("/api/export/zigbee-radios.csv")
    def export_radios(_=Depends(current_user)):
        cols = ["pan", "addr", "channels", "sent", "received", "encrypted", "hint", "types", "rssi", "lqi", "vendor", "first_seen", "last_seen", "roles", "eui", "caps"]
        return csv_response("zigbee-radios.csv", cols, ctx.rows("SELECT * FROM zigbee_radios ORDER BY last_seen DESC LIMIT 100000"))

    @r.get("/api/export/zigbee-networks.csv")
    def export_networks(_=Depends(current_user)):
        cols = ["protocol", "name", "version", "ext_pan", "pan", "channel", "permit_join", "stack_profile", "update_id", "lqi", "rssi", "first_seen", "last_seen", "sightings"]
        return csv_response("zigbee-networks.csv", cols, ctx.rows("SELECT * FROM zigbee_networks ORDER BY last_seen DESC LIMIT 10000"))

    @r.get("/api/zigbee")
    def overview(hours: float = 24, _=Depends(current_user)):
        now = time.time()
        since = now - hours * 3600
        networks = ctx.rows("SELECT * FROM zigbee_networks WHERE last_seen >= ? ORDER BY last_seen DESC, lqi DESC LIMIT 200",
                            (since,))
        # Thread border routers (a LAN device that announces the network in mDNS) name their network exactly: extended PAN ID, name, maker, model
        border = {}
        for b in ctx.rows("SELECT mac, name, ip, json_extract(extra, '$.fp.lan.mdns.meshcop') mc FROM devices WHERE kind NOT IN ('ble', 'bt_classic') "
                          "AND extra LIKE '%meshcop%' LIMIT 500"):
            try:
                mc = json.loads(b["mc"] or "null") or {}
            except ValueError:
                continue
            if mc.get("xp"):
                border.setdefault(mc["xp"], []).append({"mac": b["mac"], "name": b["name"], "ip": b["ip"], "maker": mc.get("vn"), "model": mc.get("mn"),
                                                        "network": mc.get("nn"), "version": mc.get("tv")})
        for n in networks:
            n["routers"] = json.loads(n["routers"] or "[]")
            n["permit_join"] = bool(n["permit_join"])
            n["border_routers"] = border.get(n["ext_pan"], [])
            if not n.get("name") and n["border_routers"]:
                n["name"] = next((b["network"] for b in n["border_routers"] if b["network"]), None)
        radios = ctx.rows("SELECT * FROM zigbee_radios WHERE last_seen >= ? ORDER BY sent+received DESC LIMIT 500", (since,))
        watched = watch_map(ctx, "zigbee")
        for d in radios:
            w = watched.get((str(d["pan"]), d["addr"]))
            d["given_name"], d["watch"], d["silent_min"], d["watch_state"] = (w["label"], bool(w["watch"]), w["silent_min"], w["state"]) if w else (None, False, 60, None)
            d["pan"] = None if d["pan"] < 0 else d["pan"]
            d["channels"] = _channels(d["channels"])
            d["types"] = [name for i, name in enumerate(TYPE_NAMES) if d["types"] >> i & 1]
            d["hint"] = HINTS[d["hint"]] if 0 <= d["hint"] < len(HINTS) else "unknown"
            d["hint_label"] = HINT_LABELS[d["hint"]]
            d["role"] = role_of(d["roles"] or 0)
            d["behaviour"] = [label for bit, label in ROLE_LABELS if (d["roles"] or 0) & bit]
            d["power"] = capability_labels(d.get("caps"))
            d["device"] = device_guess(d["addr"], d["roles"] or 0, d.get("caps"), d["hint"])
        frames = {x["channel"]: x["frames"] for x in ctx.rows(
            "SELECT channel, SUM(frames) frames FROM zigbee_channels WHERE minute >= ? GROUP BY channel", (since,))}
        energy = {x["channel"]: x for x in ctx.rows(
            "SELECT channel, rssi, MAX(minute) minute FROM zigbee_energy WHERE minute >= ? GROUP BY channel", (since,))}
        channels = [{"channel": c, "frames": frames.get(c, 0), "rssi": energy[c]["rssi"] if c in energy else None}
                    for c in ALL_CHANNELS]
        sensors = [s for s in status.snapshot() if s.get("type") == "zigbee"]
        return {"since": since, "now": now, "networks": networks, "radios": radios, "channels": channels, "sensors": sensors,
                "total_frames": sum(frames.values()), "configured": bool(sensors) or ctx.cfg.demo}

    return r
