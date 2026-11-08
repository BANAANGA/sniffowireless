"""Zigbee / IEEE 802.15.4 monitoring through a USB coordinator stick: the sensor thread, a store plugin and the API.

Between network scans the sensor listens passively to all 802.15.4 traffic on one or more channels, which also picks
up systems other than Zigbee. It never transmits. See zigbee_radio.py for the protocol side.
"""
import json
import logging
import os
import threading
import time

from fastapi import APIRouter, Depends

from . import status
from .auth import current_user
from .zigbee_radio import ALL_CHANNELS, HINTS, TYPE_NAMES, FrameBatch, NoCaptureMode, ZigbeeError, detect

log = logging.getLogger("sniffowireless.zigbee")

SCHEMA = """
CREATE TABLE IF NOT EXISTS zigbee_networks(
  ext_pan TEXT NOT NULL, pan INTEGER NOT NULL, channel INTEGER NOT NULL, permit_join INTEGER, stack_profile INTEGER,
  update_id INTEGER, lqi INTEGER, rssi INTEGER, routers TEXT, vendor TEXT, first_seen REAL, last_seen REAL,
  sightings INTEGER DEFAULT 0, PRIMARY KEY(ext_pan, pan, channel)) WITHOUT ROWID;
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


class ZigbeeSensor:
    def __init__(self, device, cfg, sink, link_factory=SerialLink):
        self.device, self.cfg, self.sink, self.link_factory = device, cfg, sink, link_factory
        self.name = f"zigbee:{os.path.basename(device)}"
        self.stop = None
        self.no_capture = False
        self.packets = 0
        status.register(self.name, type="zigbee", iface=device)

    def start(self, stop):
        self.stop = stop
        threading.Thread(target=self._loop, daemon=True, name=self.name).start()

    def _loop(self):
        while not self.stop.is_set():
            link = None
            try:
                link = self.link_factory(self.device)
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
            self.stop.wait(RETRY_INTERVAL)

    def run(self, link):
        family, next_scan = None, 0.0
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
            if time.monotonic() >= next_scan:
                self.scan(driver)
                next_scan = time.monotonic() + self.cfg.zigbee_scan_interval
                if not (self.cfg.zigbee_sniff and driver.can_capture and not self.no_capture):
                    continue  # the next pass waits below; EZSP restarts cleanly when it comes round again
            if self.cfg.zigbee_sniff and driver.can_capture and not self.no_capture:
                try:
                    self.capture(driver, next_scan)
                except NoCaptureMode as e:
                    log.warning("%s: %s", self.name, e)
                    self.no_capture = True
                    status.update(self.name, warning=str(e))
            else:
                status.update(self.name, state="idle", channel=None)
                self.stop.wait(max(0.0, next_scan - time.monotonic()))

    def scan(self, driver):
        status.update(self.name, state="scanning", channel=None)
        now = time.time()
        energy = []
        driver.scan(lambda n: self.sink.put({"t": "zb_network", "ts": now, "mac": "-", **n}),
                    lambda ch, rssi: energy.append([ch, rssi]), self.stop)
        if energy:
            self.sink.put({"t": "zb_energy", "ts": now, "mac": "-", "readings": energy})

    def capture(self, driver, next_scan):
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
            return self.stop.is_set() or now >= next_scan

        status.update(self.name, state="capturing", error=None)
        try:
            driver.capture(self.cfg.zigbee_channels, self.cfg.zigbee_hop_interval, until,
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
        """Only a hint: many coordinators pick a random extended PAN ID, and short addresses have no vendor."""
        if not address or address.startswith("0x") or int(address[:2], 16) & 2:
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

    def _network(self, store, o):
        key = (o["ext_pan"], o["pan"], o["channel"])
        mac = f"zb:{o['pan']:04x}"
        if key not in self.known_nets and len(self.known_nets) < 10_000:
            self.known_nets.add(key)
            store._event(o["ts"], mac, "zigbee_new_network", f"ext:{o['ext_pan']}",
                         f"New Zigbee network: PAN 0x{o['pan']:04x} on channel {o['channel']}, extended ID {o['ext_pan']}", always=True)
        if o.get("permit_join") and key not in self.open_nets:
            self.open_nets.add(key)
            store._event(o["ts"], mac, "zigbee_permit_join", f"ext:{o['ext_pan']}",
                         f"Zigbee network PAN 0x{o['pan']:04x} (channel {o['channel']}) is accepting new devices", always=True)
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
        n["vendor"] = self._vendor(store, o["ext_pan"])
        n["sightings"] += 1
        self.pending = True

    def _frames(self, store, o):
        ts = o["ts"]
        minute = int(ts // 60) * 60
        for ch, frames in (o.get("channels") or {}).items():
            k = (minute, int(ch))
            self.channels[k] = self.channels.get(k, 0) + frames
        for pan, addr, channels, sent, received, encrypted, hint, types, rssi, lqi in o.get("radios") or []:
            if len(self.seen) < 100_000:
                self.seen.add((int(ts // SEEN_SLOT) * SEEN_SLOT, f"{pan}:{addr}"))
            r = self.radios.get((pan, addr))
            if r is None:
                self.radios[(pan, addr)] = {
                    "channels": channels, "sent": sent, "received": received, "encrypted": encrypted, "hint": hint,
                    "types": types, "rssi": rssi, "lqi": lqi, "vendor": self._vendor(store, addr), "first": ts, "last": ts}
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
        self.pending = True

    def flush(self, store, c):
        if not self.pending:
            return
        for (ext_pan, pan, channel), n in self.networks.items():
            row = c.execute("SELECT routers FROM zigbee_networks WHERE ext_pan=? AND pan=? AND channel=?",
                            (ext_pan, pan, channel)).fetchone()
            routers = n["routers"] | set(json.loads(row[0] or "[]") if row else [])
            c.execute(
                "INSERT INTO zigbee_networks VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(ext_pan, pan, channel) DO UPDATE "
                "SET permit_join=excluded.permit_join, stack_profile=excluded.stack_profile, update_id=excluded.update_id, "
                "lqi=excluded.lqi, rssi=excluded.rssi, routers=excluded.routers, vendor=COALESCE(excluded.vendor, vendor), "
                "last_seen=excluded.last_seen, sightings=sightings+excluded.sightings",
                (ext_pan, pan, channel, int(n["permit_join"]), n.get("stack_profile"), n.get("update_id"), n["lqi"], n["rssi"],
                 json.dumps(sorted(routers)), n["vendor"], n["first"], n["last"], n["sightings"]))
        c.executemany(
            "INSERT INTO zigbee_radios VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(pan, addr) DO UPDATE SET "
            "channels=channels|excluded.channels, sent=sent+excluded.sent, received=received+excluded.received, "
            "encrypted=encrypted+excluded.encrypted, hint=MAX(hint, excluded.hint), types=types|excluded.types, "
            "rssi=COALESCE(excluded.rssi, rssi), lqi=COALESCE(excluded.lqi, lqi), "
            "vendor=COALESCE(excluded.vendor, vendor), last_seen=excluded.last_seen",
            [(pan, addr, r["channels"], r["sent"], r["received"], r["encrypted"], r["hint"], r["types"], r["rssi"], r["lqi"],
              r["vendor"], r["first"], r["last"]) for (pan, addr), r in self.radios.items()])
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
        c.execute("DELETE FROM zigbee_networks WHERE last_seen < ?", (cutoff,))
        c.execute("DELETE FROM zigbee_radios WHERE last_seen < ?", (cutoff,))
        c.execute("DELETE FROM zigbee_channels WHERE minute < ?", (cutoff,))
        c.execute("DELETE FROM zigbee_energy WHERE minute < ?", (cutoff,))
        c.execute("DELETE FROM radio_seen WHERE kind='zigbee' AND slot < ?", (cutoff,))


def _channels(mask):
    return [c for c in ALL_CHANNELS if mask >> c & 1]


def routes(ctx):
    r = APIRouter()

    @r.get("/api/zigbee")
    def overview(hours: float = 24, _=Depends(current_user)):
        now = time.time()
        since = now - hours * 3600
        networks = ctx.rows("SELECT * FROM zigbee_networks WHERE last_seen >= ? ORDER BY last_seen DESC, lqi DESC LIMIT 200",
                            (since,))
        for n in networks:
            n["routers"] = json.loads(n["routers"] or "[]")
            n["permit_join"] = bool(n["permit_join"])
        radios = ctx.rows("SELECT * FROM zigbee_radios WHERE last_seen >= ? ORDER BY sent+received DESC LIMIT 500", (since,))
        for d in radios:
            d["pan"] = None if d["pan"] < 0 else d["pan"]
            d["channels"] = _channels(d["channels"])
            d["types"] = [name for i, name in enumerate(TYPE_NAMES) if d["types"] >> i & 1]
            d["hint"] = HINTS[d["hint"]] if 0 <= d["hint"] < len(HINTS) else "unknown"
            d["hint_label"] = HINT_LABELS[d["hint"]]
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
