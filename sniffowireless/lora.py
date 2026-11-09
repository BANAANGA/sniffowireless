"""LoRa monitoring through a receive-only sniffer on a USB serial port (a Heltec WiFi LoRa 32 V3 running firmware/lora-sniffer):
the sensor thread, a store plugin that recognises each frame's protocol, and the API.

The sniffer firmware listens with whatever LoRa settings the host sets, one set at a time, and prints each received frame. The
sensor here hops between the configured profiles (see lora_protocols.py), and forwards raw frames to the store, where the
protocol is worked out and only metadata is kept: who sent it, for whom, how it was routed, how strongly it was heard. Payloads
are not stored and encrypted ones are never decrypted. The sensor never transmits.
"""
import json
import logging
import os
import re
import threading
import time
from collections import deque
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import adapters, status
from .auth import current_user, require_admin
from . import meshtastic
from .lora_protocols import AIR_PREAMBLE, LORAWAN_PLANS, PROFILES, PROTOCOLS, airtime_ms, classify, parse_profiles

from .modules import cutoff_for
from .radiowatch import watch_map
from .web_util import csv_response

log = logging.getLogger("sniffowireless.lora")

SCHEMA = """
CREATE TABLE IF NOT EXISTS lora_packets(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, protocol TEXT NOT NULL, kind TEXT, src TEXT, dst TEXT, hops INTEGER,
  confidence INTEGER, profile TEXT, freq REAL, bw REAL, sf INTEGER, sync INTEGER, rssi REAL, snr REAL, bytes INTEGER, sensor TEXT, info TEXT);
CREATE INDEX IF NOT EXISTS idx_lora_packets_ts ON lora_packets(ts);
CREATE TABLE IF NOT EXISTS lora_nodes(
  protocol TEXT NOT NULL, addr TEXT NOT NULL, name TEXT, kind TEXT, packets INTEGER DEFAULT 0, rssi REAL, best_rssi REAL, snr REAL,
  profile TEXT, first_seen REAL, last_seen REAL, lat REAL, lon REAL, PRIMARY KEY(protocol, addr)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_lora_nodes_last ON lora_nodes(last_seen);
CREATE TABLE IF NOT EXISTS radio_seen(
  slot INTEGER NOT NULL, kind TEXT NOT NULL, addr TEXT NOT NULL, PRIMARY KEY(slot, kind, addr)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS lora_stats(
  minute INTEGER NOT NULL, protocol TEXT NOT NULL, profile TEXT NOT NULL, packets INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0,
  rssi_sum REAL DEFAULT 0, air_ms REAL DEFAULT 0, PRIMARY KEY(minute, protocol, profile)) WITHOUT ROWID;
"""
BAUD_RATE = 115200
RETRY_INTERVAL = 30
HANDSHAKE_TRIES = 4
CONFIG_TIMEOUT = 3.0
SILENCE_LIMIT = 45   # the firmware prints a STAT line every 10 s: this long without any line means the stick is gone
MAX_PENDING = 50_000
SEEN_SLOT = 300  # radio_seen granularity, seconds
# Behaviour worth an alert (events, so alert rules can pick them up). Fixed thresholds: frames are only heard while the radio
# listens on that profile, so these are lower bounds of what is really on the air.
FLOOD_PACKETS, FLOOD_WINDOW = 40, 300      # one node sending this many frames in this many seconds
JOIN_FLOOD, JOIN_WINDOW = 8, 600           # one LoRaWAN device sending this many join requests
FCNT_BACK = 16                             # a LoRaWAN frame counter going back by more than this (and not a wrap)
TRACK_MAX = 5000


class LoraError(Exception):
    pass


class LineLink:
    """The sniffer on a serial port: lines in, lines out."""

    def __init__(self, path):
        import serial
        self.port = serial.Serial(path, BAUD_RATE, timeout=0.2, rtscts=False, dsrdtr=False, xonxoff=False)
        self.buf = b""

    def write_line(self, text):
        self.port.write(text.encode("ascii") + b"\n")

    def read_line(self, timeout):
        """One line (without its newline), or None when none arrived within `timeout` seconds."""
        end = time.monotonic() + timeout
        while True:
            i = self.buf.find(b"\n")
            if i >= 0:
                line, self.buf = self.buf[:i], self.buf[i + 1:]
                return line.decode("ascii", "replace").strip()
            left = end - time.monotonic()
            if left <= 0:
                return None
            self.port.timeout = min(left, 0.2)
            self.buf += self.port.read(max(1, self.port.in_waiting))
            if len(self.buf) > 4096 and b"\n" not in self.buf:
                self.buf = b""  # noise without a line end (another firmware's output): don't grow for ever

    def close(self):
        self.port.close()


def parse_rx(line):
    """`RX,<ms>,<freq MHz>,<bw kHz>,<sf>,<sync>,<rssi>,<snr>,<freq error Hz>,<length>,<hex>` as a dict, or None if it isn't one."""
    f = line.split(",")
    if len(f) != 11 or f[0] != "RX":
        return None
    try:
        out = {"freq": float(f[2]), "bw": float(f[3]), "sf": int(f[4]), "sync": int(f[5], 0), "rssi": float(f[6]), "snr": float(f[7]),
               "ferr": float(f[8]), "hex": f[10].lower()}
        n = int(f[9])
        raw = bytes.fromhex(out["hex"])
    except ValueError:
        return None
    return out if n == len(raw) and 1 <= n <= 255 else None


OVERRIDE_KEYS = ("profiles", "hop_interval")
MAX_PROFILES = 64
HOP_MIN, HOP_MAX = 0.5, 600.0


def clean_override(o):
    """Only the known keys with their values checked (ValueError saying what is wrong): {profiles: spec or None, hop_interval}."""
    o = o if isinstance(o, dict) else {}
    out = {"profiles": None, "hop_interval": None}
    spec = o.get("profiles")
    if spec not in (None, ""):
        if not isinstance(spec, str) or len(spec) > 1000:
            raise ValueError("The profile list is too long")
        found = parse_profiles(spec.strip())  # ValueError names the item that is wrong
        if not found:
            raise ValueError("The profile list is empty")
        if len(found) > MAX_PROFILES:
            raise ValueError(f"That is {len(found)} profiles; the most is {MAX_PROFILES}")
        out["profiles"] = spec.strip()
    if o.get("hop_interval") not in (None, ""):
        try:
            hop = float(o["hop_interval"])
        except (TypeError, ValueError):
            raise ValueError("The hop time is a number of seconds")
        if not HOP_MIN <= hop <= HOP_MAX:
            raise ValueError(f"The time on each profile must be between {HOP_MIN:g} and {HOP_MAX:g} seconds")
        out["hop_interval"] = hop
    return out


class LoraControl:
    """Which profiles the LoRa boards of this process hop over, and for how long on each. Starts from LORA_PROFILES /
    LORA_REGION / LORA_HOP_INTERVAL and takes an override on top while running: set in the web UI (settings key "lora")
    for this server, or sent in the ingest reply for a remote sensor, which reports the revision it runs (status `lora_rev`)."""

    def __init__(self, cfg, override=None, rev=0):
        self.cfg, self.rev = cfg, rev
        self.override = clean_override(override) if override else None
        self.lock = threading.Lock()
        self.sensors = []
        self._rejected_rev = None

    def effective(self):
        """(profiles, seconds per profile) as they stand now."""
        o = self.override or {}
        try:
            profiles = parse_profiles(o["profiles"]) if o.get("profiles") else list(self.cfg.lora_profiles)
        except ValueError:  # cannot happen for a checked override; never leave the radio without a plan
            profiles = list(self.cfg.lora_profiles)
        return profiles, float(o.get("hop_interval") or self.cfg.lora_hop_interval)

    def apply(self, override, rev):
        """Switch to new settings (ValueError, nothing changed, if they are not valid). The boards pick them up at their next hop."""
        override = clean_override(override) if override else None
        if override and not any(override.values()):
            override = None
        with self.lock:
            self.override, self.rev = override, rev
        profiles, _ = self.effective()
        for s in list(self.sensors):
            status.update(s.name, profiles=[p.name for p in profiles], lora_rev=rev)

    def apply_local(self, settings):
        entry = (settings.get("local") or {}) if isinstance(settings, dict) else {}
        rev = entry.get("rev") or 0
        if rev != self.rev:
            try:
                self.apply({k: entry.get(k) for k in OVERRIDE_KEYS}, rev)
            except ValueError as e:
                log.warning("Ignoring the LoRa settings: %s", e)

    def apply_remote(self, conf):
        """A remote sensor, with the entry the server sent in its ingest reply."""
        if not isinstance(conf, dict) or not isinstance(conf.get("rev"), int) or conf["rev"] == self.rev or conf["rev"] == self._rejected_rev:
            return
        try:
            self.apply({k: conf.get(k) for k in OVERRIDE_KEYS}, conf["rev"])
            log.info("LoRa settings from the server applied (revision %d)", conf["rev"])
        except ValueError as e:
            self._rejected_rev = conf["rev"]
            log.warning("Ignoring LoRa settings from the server (revision %d): %s", conf["rev"], e)


def attach(ctx):
    """The server's own LoRa control, started from the saved settings and kept in step with later changes."""
    entry = ctx.settings.get("lora")["local"] or {}
    try:
        ctx.lora_control = LoraControl(ctx.cfg, {k: entry.get(k) for k in OVERRIDE_KEYS} if entry else None, entry.get("rev") or 0)
    except ValueError as e:
        log.warning("Ignoring the saved LoRa settings (%s); using the environment", e)
        ctx.lora_control = LoraControl(ctx.cfg)
    ctx.settings.on_change(lambda k: ctx.lora_control.apply_local(ctx.settings.get("lora")) if k == "lora" else None)
    return ctx.lora_control


def decode_enabled(ctx):
    """Whether messages and positions on the public Meshtastic channel are read (settings "lora".decode_public, else LORA_DECODE_PUBLIC)."""
    v = ctx.settings.get("lora").get("decode_public")
    return ctx.cfg.lora_decode_public if v is None else bool(v)


class LoraSensor:
    def __init__(self, device, cfg, sink, link_factory=LineLink, control=None):
        self.device, self.cfg, self.sink, self.link_factory = device, cfg, sink, link_factory
        self.control = control or LoraControl(cfg)
        self.control.sensors.append(self)
        self.name = f"lora:{os.path.basename(device)}"
        self.stop = None
        self.packets = 0
        self.profile = None
        self.link, self.reset_requested = None, threading.Event()
        self.flashing, self.port_lock = threading.Event(), threading.Lock()  # a firmware update has the port: the loop stays away
        adapters.REGISTRY[self.name] = self
        status.register(self.name, type="lora", iface=device, profiles=[p.name for p in self.control.effective()[0]], lora_rev=self.control.rev)

    def start(self, stop):
        self.stop = stop
        threading.Thread(target=self._loop, daemon=True, name=self.name).start()

    def _loop(self):
        while not self.stop.is_set():
            link = None
            with self.port_lock:
                try:
                    if self.flashing.is_set():
                        raise LoraError("firmware update in progress")
                    link = self.link = self.link_factory(self.device)
                    self.run(link)
                except Exception as e:  # serial errors depend on the platform; a replug must not end the thread
                    if not self.flashing.is_set():
                        log.warning("%s: %s", self.name, e)
                        status.update(self.name, state="error", error=str(e)[:200])
                finally:
                    if link is not None:
                        try:
                            link.close()
                        except Exception:
                            pass
            self._retry_wait()

    def flash(self, image, progress=None, flasher=None):
        """Write a firmware image to the board on this port, then let the loop find it again. Raises espflash.FlashError.
        The read loop is stopped first (it holds the port) and kept away until the board has restarted."""
        from . import espflash
        if self.flashing.is_set():
            raise espflash.FlashError("a firmware update of this board is already running")
        self.flashing.set()
        try:
            end = time.monotonic() + 30
            while not self.port_lock.acquire(timeout=1):  # the loop gives the port up once its link is closed
                self.reset()
                if time.monotonic() > end:
                    raise espflash.FlashError("could not take over the serial port from the capture loop")
            try:
                status.update(self.name, state="updating", error=None, warning=None, note="Updating the firmware: starting")

                def report(f):
                    status.update(self.name, note=f"Updating the firmware: {int(f * 100)}%")
                    if progress:
                        progress(f)
                (flasher or espflash.flash)(self.device, image, progress=report)
                status.update(self.name, note=f"Firmware updated at {time.strftime('%H:%M')}")
            finally:
                self.port_lock.release()
        finally:
            self.flashing.clear()
            self.reset_requested.set()  # reconnect now: the handshake reads the new version

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

    # ------------------------------------------------------------------ talking to the sniffer
    def handshake(self, link):
        status.update(self.name, state="connecting", error=None)
        for _ in range(HANDSHAKE_TRIES):
            link.write_line("PING")
            end = time.monotonic() + 2.0
            while time.monotonic() < end and not self.stop.is_set():
                line = link.read_line(0.5)
                if line and (line == "PONG" or line.startswith("READY,lora-sniffer")):
                    return line
        raise LoraError("This device did not answer as the lora-sniffer firmware. It may run other firmware (flash "
                        "firmware/lora-sniffer), or another program may be using the port")

    def read_version(self, link):
        """The firmware version the board reports in INFO (1 for boards flashed before that field existed), or None."""
        link.write_line("INFO")
        end = time.monotonic() + 1.5
        while time.monotonic() < end and not self.stop.is_set():
            line = link.read_line(0.3)
            if line and line.startswith("INFO,lora-sniffer"):
                f = line.split(",")
                return int(f[12]) if len(f) > 12 and f[12].isdigit() else 1
        return None

    def configure(self, link, profile):
        """Tell the sniffer to listen with a profile's settings; False if it refused them (frames that arrive meanwhile are kept)."""
        link.write_line(f"CFG,{profile.freq:g},{profile.bw:g},{profile.sf},{profile.cr},0x{profile.sync:02X},{profile.preamble}")
        end = time.monotonic() + CONFIG_TIMEOUT
        while time.monotonic() < end and not self.stop.is_set():
            line = link.read_line(0.5)
            if line is None:
                continue
            if line.startswith("OK,CFG"):
                return True
            if line.startswith("ERR,CFG"):
                return False
            self.handle_line(line)
        raise LoraError("The sniffer did not answer a settings change")

    def handle_line(self, line):
        rx = parse_rx(line)
        if rx:
            self.packets += 1
            self.sink.put({"t": "lora_frame", "ts": time.time(), "mac": "-", "profile": self.match(rx), **rx})
            return
        if line.startswith("STAT,"):
            f = line.split(",")
            if len(f) == 4 and f[3].isdigit():
                status.update(self.name, packets=self.packets, crc_errors=int(f[3]))

    def match(self, rx):
        """The profile a frame was heard on, from the settings the sniffer reports with it (not from what was asked a moment ago)."""
        for p in list(self.control.effective()[0]) + list(PROFILES.values()):
            if abs(p.freq - rx["freq"]) < 0.002 and p.sf == rx["sf"] and abs(p.bw - rx["bw"]) < 0.5 and p.sync == rx["sync"]:
                return p.name
        return self.profile.name if self.profile else "custom"

    def run(self, link):
        first = self.handshake(link)
        firmware = "lora-sniffer"
        status.update(self.name, state="listening", error=None, firmware=firmware, warning=None, fw_version=self.read_version(link))
        log.info("%s: sniffer answered (%s)", self.name, first)
        refused, i, seen_rev = [], 0, self.control.rev
        last_heard = time.monotonic()
        while not self.stop.is_set():
            profiles, hop = self.control.effective()  # re-read at every hop: a change in the web UI applies within one dwell
            if self.control.rev != seen_rev:
                refused, i, seen_rev = [], 0, self.control.rev
            self.profile = profiles[i % len(profiles)]
            i += 1
            if not self.configure(link, self.profile):
                if self.profile.name not in refused:
                    refused.append(self.profile.name)
                    log.warning("%s: the sniffer refused %s (%s)", self.name, self.profile.name, self.profile.describe())
                status.update(self.name, warning="The sniffer refused " + ", ".join(refused) + ": the frequency may be outside its band")
                if len(refused) >= len(profiles):
                    raise LoraError("The sniffer refused every profile; check the LoRa profiles against the board's frequency band")
                continue
            if refused:
                status.update(self.name, warning="The sniffer refused " + ", ".join(refused) + ": the frequency may be outside its band")
            else:
                status.update(self.name, warning=None)
            status.update(self.name, channel=f"{self.profile.freq:g} MHz SF{self.profile.sf}", profile=self.profile.name)
            dwell_end = time.monotonic() + (hop if len(profiles) > 1 else 10 ** 9)
            while not self.stop.is_set() and time.monotonic() < dwell_end and self.control.rev == seen_rev:
                line = link.read_line(1.0)
                now = time.monotonic()
                if line is not None:
                    last_heard = now
                    self.handle_line(line)
                elif now - last_heard > SILENCE_LIMIT:
                    raise LoraError("The sniffer stopped sending (replugged, or reset?)")


# ------------------------------------------------------------------------------------------------ store plugin
class LoraMonitor:
    """Store plugin (writer thread): recognises each frame's protocol and keeps its metadata."""

    def __init__(self, ctx):
        self.ctx = ctx
        ctx.store.conn.executescript(SCHEMA)
        self.packets = []
        self.nodes = {}
        self.stats = {}
        self.seen = set()
        try:  # databases from before the airtime figures
            ctx.store.conn.execute("ALTER TABLE lora_stats ADD COLUMN air_ms REAL DEFAULT 0")
        except Exception:
            pass
        for col in ("lat", "lon"):  # databases from before positions were read
            try:
                ctx.store.conn.execute(f"ALTER TABLE lora_nodes ADD COLUMN {col} REAL")
            except Exception:
                pass
        self.custom, self._dec, self._dec_at = {}, True, -10.0   # profiles chosen in the web UI; whether the public channel is read
        self.known = set()          # (protocol, addr) nodes seen before, for "new node" events
        self.rate = {}              # node -> recent frame times, for flood detection
        self.joins = {}             # LoRaWAN DevEUI -> recent join request times
        self.fcnt = {}              # LoRaWAN DevAddr -> last frame counter
        try:
            self.known = {(p, a) for p, a in ctx.store.conn.execute("SELECT protocol, addr FROM lora_nodes LIMIT 200000")}
        except Exception:
            pass
        self.pending = False

    def reset(self, module):
        """Forget what is remembered about what Settings -> Clear data deleted (new nodes raise events again)."""
        if module == "lora":
            self.packets, self.nodes, self.stats, self.seen, self.pending = [], {}, {}, set(), False
            self.known, self.rate, self.joins, self.fcnt = set(), {}, {}, {}

    def _events(self, store, ts, protocol, addr, node, r):
        """New nodes, floods and LoRaWAN counter resets as events (see the thresholds above)."""
        mac, kind = f"lora:{addr}", node[2] if node else None
        key = (protocol, addr)
        if key not in self.known and len(self.known) < 200_000:
            self.known.add(key)
            if kind != "hash" and protocol != "unknown":
                label = PROTOCOLS.get(protocol, protocol)
                name = f" “{node[1]}”" if node[1] else ""
                store._event(ts, mac, "lora_new_node", protocol, f"New {label} node {addr}{name}" + (f" ({kind})" if kind else ""), always=True)
        if kind == "hash":
            return  # a one-byte hash is shared by many nodes: rates and counters per hash mean nothing
        q = self.rate.setdefault(key, deque())
        q.append(ts)
        while q and ts - q[0] > FLOOD_WINDOW:
            q.popleft()
        if len(q) == FLOOD_PACKETS:
            store._event(ts, mac, "lora_flood", protocol, f"{PROTOCOLS.get(protocol, protocol)} node {addr} sent {FLOOD_PACKETS} frames in "
                         f"{int(ts - q[0]) or 1} s (heard here only part of the time)", always=True)
        if len(self.rate) > TRACK_MAX:
            self.rate.clear()
        info = r.get("info") or {}
        if protocol == "lorawan" and info.get("dev_eui") and r["kind"] == "join request":
            j = self.joins.setdefault(info["dev_eui"], deque())
            j.append(ts)
            while j and ts - j[0] > JOIN_WINDOW:
                j.popleft()
            if len(j) == JOIN_FLOOD:
                store._event(ts, mac, "lora_join_flood", protocol, f"LoRaWAN device {info['dev_eui']} sent {JOIN_FLOOD} join requests in "
                             f"{int(ts - j[0]) or 1} s: it cannot join, or someone is probing", always=True)
            if len(self.joins) > TRACK_MAX:
                self.joins.clear()
        elif protocol == "lorawan" and info.get("fcnt") is not None:
            last, cur = self.fcnt.get(addr), info["fcnt"]
            self.fcnt[addr] = cur
            ahead = (cur - last) % 65536 if last is not None else 0  # forward distance; a wrap past 65535 is still forward
            if ahead >= 32768 and 65536 - ahead > FCNT_BACK:
                store._event(ts, mac, "lora_fcnt_reset", protocol, f"LoRaWAN device {addr}: frame counter went back from {last} to {cur} "
                             "(the device restarted, or old frames are being replayed; two devices sharing an address look the same)", always=True)
            if len(self.fcnt) > TRACK_MAX:
                self.fcnt.clear()

    def observe(self, store, o, dev):
        if o["t"] != "lora_frame":
            return
        try:
            payload = bytes.fromhex(o.get("hex") or "")
        except ValueError:
            return
        if not payload:
            return
        profile = self.profile_named(o.get("profile") or "")
        r = classify(payload, o.get("sync"), profile.hint if profile else None)
        ts, protocol = o["ts"], r["protocol"]
        if protocol == "meshtastic" and r["confidence"] >= 50 and self.decoding():
            self._decode_public(r, payload)
        rssi, snr = o.get("rssi"), o.get("snr")
        if len(self.packets) < MAX_PENDING:
            self.packets.append((ts, protocol, r["kind"], r["src"], r["dst"], r["hops"], r["confidence"], o.get("profile"), o.get("freq"),
                                 o.get("bw"), o.get("sf"), o.get("sync"), rssi, snr, len(payload), o.get("sensor") or "local",
                                 json.dumps(r["info"]) if r["info"] else None))
        key = (int(ts // 60) * 60, protocol, o.get("profile") or "")
        s = self.stats.setdefault(key, [0, 0, 0.0, 0.0])
        s[0] += 1
        s[1] += len(payload)
        s[2] += rssi or 0
        try:  # time on air, with the coding rate of the profile it was heard on (frames do not say) and the preamble the protocol sends
            s[3] += airtime_ms(len(payload), int(o["sf"]), float(o["bw"]), profile.cr if profile else 5, AIR_PREAMBLE.get(protocol, 8))
        except (KeyError, TypeError, ValueError, ZeroDivisionError):
            pass
        node = r.get("node")
        if node:
            self._events(store, ts, protocol, node[0], node, r)
        if node and len(self.nodes) < MAX_PENDING:
            addr, name, kind = node
            self.seen.add((int(ts // SEEN_SLOT) * SEEN_SLOT, f"{protocol}:{addr}"))
            n = self.nodes.get((protocol, addr))
            if n is None:
                self.nodes[(protocol, addr)] = {"name": name, "kind": kind, "packets": 1, "rssi": rssi, "best": rssi, "snr": snr,
                                                "profile": o.get("profile"), "first": ts, "last": ts, "pos": r.get("pos")}
            else:
                n["packets"] += 1
                n["name"] = name or n["name"]
                if kind != "hash":
                    n["kind"] = kind
                n["rssi"], n["snr"], n["last"], n["profile"] = rssi, snr, ts, o.get("profile")
                n["pos"] = r.get("pos") or n.get("pos")
                if rssi is not None and (n["best"] is None or rssi > n["best"]):
                    n["best"] = rssi
        self.pending = True

    def profile_named(self, name):
        """A profile by the name frames carry: the built-in ones, this server's, or one chosen in the web UI for any sensor."""
        if name in PROFILES:
            return PROFILES[name]
        found = next((p for p in self.ctx.cfg.lora_profiles if p.name == name), None)
        if found:
            return found
        if name not in self.custom:
            self.custom = {}
            lora = self.ctx.settings.get("lora")
            for entry in [lora.get("local") or {}] + list((lora.get("sensors") or {}).values()):
                try:
                    self.custom.update({p.name: p for p in parse_profiles(entry.get("profiles") or "")})
                except ValueError:
                    pass
            self.custom.setdefault(name, None)
        return self.custom.get(name)

    def decoding(self):
        now = time.monotonic()
        if now - self._dec_at > 2:
            self._dec, self._dec_at = decode_enabled(self.ctx), now
        return self._dec

    @staticmethod
    def _decode_public(r, payload):
        """Read what the public default key (or no key) opens, and put it in the frame's result: kind, node name, contents."""
        d = meshtastic.decode(payload)
        if not d:
            return
        info = r["info"]
        info.update(port=d["port_name"], public_key=d["encrypted"])
        r["kind"] = d["port_name"]
        for key in ("text", "position", "user", "telemetry", "waypoint"):
            if key in d:
                info[key] = d[key]
        if "user" in d and r["node"]:
            r["node"] = (r["node"][0], d["user"].get("long_name") or d["user"].get("short_name"), r["node"][2])
            r["name"] = r["node"][1]
        if "position" in d and "lat" in d["position"] and r["node"]:
            r["pos"] = (d["position"]["lat"], d["position"]["lon"])

    def flush(self, store, c):
        if not self.pending:
            return
        c.executemany("INSERT INTO lora_packets(ts, protocol, kind, src, dst, hops, confidence, profile, freq, bw, sf, sync, rssi, snr, bytes, "
                      "sensor, info) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", self.packets)
        c.executemany(
            "INSERT INTO lora_nodes(protocol, addr, name, kind, packets, rssi, best_rssi, snr, profile, first_seen, last_seen, lat, lon) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(protocol, addr) DO UPDATE SET name=COALESCE(excluded.name, name), "
            "kind=CASE WHEN excluded.kind='hash' THEN kind ELSE excluded.kind END, packets=packets+excluded.packets, "
            "rssi=excluded.rssi, best_rssi=MAX(COALESCE(best_rssi, excluded.best_rssi), COALESCE(excluded.best_rssi, best_rssi)), "
            "snr=excluded.snr, profile=excluded.profile, last_seen=excluded.last_seen, lat=COALESCE(excluded.lat, lat), "
            "lon=COALESCE(excluded.lon, lon)",
            [(p, a, n["name"], n["kind"], n["packets"], n["rssi"], n["best"], n["snr"], n["profile"], n["first"], n["last"],
              n["pos"][0] if n.get("pos") else None, n["pos"][1] if n.get("pos") else None)
             for (p, a), n in self.nodes.items()])
        c.executemany("INSERT INTO lora_stats(minute, protocol, profile, packets, bytes, rssi_sum, air_ms) VALUES(?,?,?,?,?,?,?) "
                      "ON CONFLICT(minute, protocol, profile) DO UPDATE SET packets=packets+excluded.packets, bytes=bytes+excluded.bytes, "
                      "rssi_sum=rssi_sum+excluded.rssi_sum, air_ms=air_ms+excluded.air_ms",
                      [(m, p, prof, s[0], s[1], s[2], s[3]) for (m, p, prof), s in self.stats.items()])
        c.executemany("INSERT OR IGNORE INTO radio_seen VALUES(?, 'lora', ?)", list(self.seen))
        self.packets, self.nodes, self.stats, self.pending = [], {}, {}, False
        self.seen = set()

    def prune(self, store, c, cutoff):
        cutoff = cutoff_for(self.ctx, "lora", cutoff)
        c.execute("DELETE FROM lora_packets WHERE ts < ?", (cutoff,))
        c.execute("DELETE FROM lora_nodes WHERE last_seen < ?", (cutoff,))
        c.execute("DELETE FROM lora_stats WHERE minute < ?", (cutoff,))
        c.execute("DELETE FROM radio_seen WHERE kind='lora' AND slot < ?", (cutoff,))


# ------------------------------------------------------------------------------------------------ API
FIRMWARE_DIR = Path(__file__).parent / "firmware"


def firmware_manifest():
    """The firmware image the web flasher offers (built by scripts/build_firmware.py), or None."""
    try:
        m = json.loads((FIRMWARE_DIR / "firmware.json").read_text())
        return m if (FIRMWARE_DIR / m["file"]).is_file() else None
    except (OSError, ValueError, KeyError):
        return None


def _flash_local(name, image):
    try:
        adapters.flash_lora(name, image)
    except Exception as e:
        log.warning("Firmware update of %s failed: %s", name, e)


class LoraConfig(BaseModel):
    profiles: Optional[str] = Field(None, max_length=1000)   # None / "" = the sensor's own LORA_PROFILES
    hop_interval: Optional[float] = None


class LoraDecode(BaseModel):
    decode_public: Optional[bool] = None                       # None = LORA_DECODE_PUBLIC


def routes(ctx):
    r = APIRouter()

    @r.get("/api/export/lora-nodes.csv")
    def export_nodes(_=Depends(current_user)):
        cols = ["protocol", "addr", "name", "kind", "packets", "rssi", "best_rssi", "snr", "profile", "first_seen", "last_seen"]
        return csv_response("lora-nodes.csv", cols, ctx.rows("SELECT * FROM lora_nodes ORDER BY last_seen DESC LIMIT 100000"))

    @r.get("/api/export/lora-packets.csv")
    def export_packets(hours: float = 24, _=Depends(current_user)):
        cols = ["ts", "protocol", "kind", "src", "dst", "hops", "confidence", "profile", "freq", "bw", "sf", "sync", "rssi", "snr", "bytes", "sensor"]
        return csv_response("lora-packets.csv", cols, ctx.rows("SELECT * FROM lora_packets WHERE ts >= ? ORDER BY id DESC LIMIT 200000",
                                                             (time.time() - max(1 / 60, min(hours, 24 * 365)) * 3600,)))

    @r.get("/api/lora/firmware")
    def firmware(_=Depends(require_admin)):
        m = firmware_manifest()
        if not m:
            raise HTTPException(404, "This build has no firmware image")
        return {**m, "url": "/api/lora/firmware.bin"}

    @r.get("/api/ingest/firmware")
    def firmware_for_sensor(request: Request):
        """The same image for a remote sensor, which updates its own LoRa board when an admin asks (sensor tokens only)."""
        u = request.state.user
        if not u or getattr(u, "scope", None) != "sensor":
            raise HTTPException(401, "sensor token required")
        m = firmware_manifest()
        if not m:
            raise HTTPException(404, "This build has no firmware image")
        return FileResponse(FIRMWARE_DIR / m["file"], media_type="application/octet-stream")

    class FlashBody(BaseModel):
        sensor: str = Field("local", max_length=64)   # "local" or a remote sensor's id
        name: str = Field(max_length=120)             # lora:<device> as the sensor names it

    @r.post("/api/lora/flash")
    def flash(body: FlashBody, _=Depends(require_admin)):
        m = firmware_manifest()
        if not m:
            raise HTTPException(404, "This build has no firmware image")
        if not re.fullmatch(r"lora:[\w./:@+-]{1,100}", body.name):
            raise HTTPException(400, "Unknown interface")
        if body.sensor != "local":
            entry = status.SENSORS.get(f"{body.sensor}/{body.name}")
            if not entry:
                raise HTTPException(404, "That sensor does not report such a board")
            if entry.get("state") == "updating":
                raise HTTPException(409, "That board is already being updated")
            adapters.queue_flash(body.sensor, body.name, m)
            return {"done": False, "queued": True, "version": m["version"]}
        sensor = adapters.REGISTRY.get(body.name)
        if sensor is None or not hasattr(sensor, "flash"):
            raise HTTPException(404, "This server has no such LoRa board")
        if sensor.flashing.is_set():
            raise HTTPException(409, "That board is already being updated")
        image = (FIRMWARE_DIR / m["file"]).read_bytes()
        threading.Thread(target=lambda: _flash_local(body.name, image), daemon=True, name="lora-flash").start()
        return {"done": False, "started": True, "version": m["version"]}

    @r.get("/api/lora/firmware.bin")
    def firmware_bin(_=Depends(require_admin)):
        m = firmware_manifest()
        if not m:
            raise HTTPException(404, "This build has no firmware image")
        return FileResponse(FIRMWARE_DIR / m["file"], media_type="application/octet-stream", filename=m["file"])

    # ---- which profiles each board listens on (this server's and the remote sensors')
    def lora_boards(target):
        out = []
        for s in status.snapshot():
            if s.get("type") != "lora" or (target == "local") != (s.get("remote") is None) or (target != "local" and s.get("remote") != target):
                continue
            out.append({k: s.get(k) for k in ("iface", "name", "state", "error", "profile", "profiles", "channel", "lora_rev", "warning", "packets", "fw_version")})
        return sorted(out, key=lambda a: a["iface"] or "")

    def lora_target(target, name, online):
        cfg_all = ctx.settings.get("lora")
        entry = (cfg_all["local"] if target == "local" else cfg_all["sensors"].get(target)) or None
        boards = lora_boards(target)
        rev = (entry or {}).get("rev") or 0
        return {"id": target, "name": name, "online": online,
                "config": ({k: entry.get(k) for k in ("rev",) + OVERRIDE_KEYS} if entry else None), "boards": boards,
                "applied": bool(boards) and all((b.get("lora_rev") or 0) == rev for b in boards) if online else None,
                "too_old": target != "local" and online and bool(boards) and any(b.get("lora_rev") is None for b in boards),
                "own": ([{"name": p.name, "describe": p.describe()} for p in ctx.cfg.lora_profiles] if target == "local" else None)}

    @r.get("/api/lora-settings")
    def get_lora_settings(_=Depends(require_admin)):
        now = time.time()
        out = [lora_target("local", "This server", True)]
        for s in ctx.rows("SELECT id, name, last_seen FROM sensors WHERE id != 'local' ORDER BY name"):
            out.append(lora_target(s["id"], s["name"], (s["last_seen"] or 0) > now - 60))
        groups = [{"token": p.name, "label": p.label, "protocol": p.hint or "custom", "describe": p.describe()} for p in PROFILES.values()]
        groups += [{"token": f"lorawan:{reg.lower()}:{lo}-{hi}", "label": f"LoRaWAN {reg}: all {len(freqs)} default channels, SF{lo}-{hi}", "protocol": "lorawan",
                    "describe": f"{len(freqs) * (hi - lo + 1)} profiles, {freqs[0]:g}-{freqs[-1]:g} MHz"}
                   for reg, (freqs, (lo, hi)) in LORAWAN_PLANS.items()]
        groups += [{"token": f"lorawan:{reg.lower()}", "label": f"LoRaWAN {reg}: default channels, SF7", "protocol": "lorawan",
                    "describe": f"{len(freqs)} profiles, {freqs[0]:g}-{freqs[-1]:g} MHz"} for reg, (freqs, _sf) in LORAWAN_PLANS.items()]
        return {"targets": out, "known": groups, "decode_public": decode_enabled(ctx), "decode_env": ctx.cfg.lora_decode_public,
                "hop_default": ctx.cfg.lora_hop_interval, "protocols": PROTOCOLS}

    def _lora_check(target):
        if target != "local" and not ctx.one("SELECT 1 FROM sensors WHERE id=?", (target,)):
            raise HTTPException(404, "No such sensor")

    def _lora_store(target, override):
        cfg_all = ctx.settings.get("lora")
        old = (cfg_all["local"] if target == "local" else cfg_all["sensors"].get(target)) or {}
        new = {"rev": (old.get("rev") or 0) + 1, **{k: override[k] for k in OVERRIDE_KEYS}}
        if target == "local":
            cfg_all["local"] = new
        else:
            cfg_all["sensors"][target] = new
        ctx.settings.set("lora", cfg_all)  # on_change applies it to this server's boards
        return new

    @r.put("/api/lora-settings/{target}")
    def put_lora_settings(target: str, body: LoraConfig, _=Depends(require_admin)):
        _lora_check(target)
        try:
            override = clean_override(body.model_dump())
            count = len(parse_profiles(override["profiles"])) if override["profiles"] else None
        except ValueError as e:
            raise HTTPException(400, str(e))
        res = {"ok": True, "config": _lora_store(target, override), "profiles": count}
        if count and count > 1:
            hop = override["hop_interval"] or ctx.cfg.lora_hop_interval
            res["cycle_seconds"] = round(count * hop)  # one full round of the profiles
        return res

    @r.delete("/api/lora-settings/{target}")
    def reset_lora_settings(target: str, _=Depends(require_admin)):
        """Back to the sensor's own settings (LORA_PROFILES / LORA_REGION)."""
        _lora_check(target)
        return {"ok": True, "config": _lora_store(target, clean_override({}))}

    @r.put("/api/lora-settings")
    def put_lora_decode(body: LoraDecode, _=Depends(require_admin)):
        cfg_all = ctx.settings.get("lora")
        cfg_all["decode_public"] = body.decode_public
        ctx.settings.set("lora", cfg_all)
        return {"ok": True, "decode_public": decode_enabled(ctx)}

    @r.get("/api/lora")
    def overview(hours: float = 24, _=Depends(current_user)):
        now = time.time()
        hours = max(1 / 6, min(hours, 24 * 30))
        since = now - hours * 3600
        protocols = ctx.rows(
            "SELECT protocol, COUNT(*) packets, SUM(bytes) bytes, COUNT(DISTINCT src) senders, MAX(ts) last_seen, AVG(rssi) rssi, "
            "AVG(snr) snr FROM lora_packets WHERE ts >= ? GROUP BY protocol ORDER BY packets DESC", (since,))
        for p in protocols:
            p["label"] = PROTOCOLS.get(p["protocol"], p["protocol"])
        bucket = max(60, int(hours * 3600 / 120) // 60 * 60)
        series = {}
        for row in ctx.rows("SELECT (minute / ?) * ? t, protocol, SUM(packets) n FROM lora_stats WHERE minute >= ? GROUP BY t, protocol",
                            (bucket, bucket, int(since // bucket * bucket))):
            series.setdefault(row["protocol"], {})[row["t"]] = row["n"]
        start = int(since // bucket * bucket)
        ts = list(range(start, int(now), bucket))
        nodes = ctx.rows("SELECT * FROM lora_nodes WHERE last_seen >= ? ORDER BY last_seen DESC LIMIT 300", (since,))
        watched = watch_map(ctx, "lora")
        for n in nodes:
            n["label"] = PROTOCOLS.get(n["protocol"], n["protocol"])
            w = watched.get((n["protocol"], n["addr"]))
            n["given_name"], n["watch"], n["silent_min"], n["watch_state"] = (w["label"], bool(w["watch"]), w["silent_min"], w["state"]) if w else (None, False, 60, None)
        recent = ctx.rows("SELECT * FROM lora_packets WHERE ts >= ? ORDER BY id DESC LIMIT 100", (since,))
        for p in recent:
            p["label"] = PROTOCOLS.get(p["protocol"], p["protocol"])
            p["info"] = json.loads(p["info"]) if p["info"] else {}
        messages = ctx.rows("SELECT ts, protocol, src, rssi, info, sensor FROM lora_packets WHERE ts >= ? AND kind = 'text message' AND info IS NOT NULL "
                            "ORDER BY id DESC LIMIT 50", (since,))
        names = {n["addr"]: n["name"] for n in nodes if n["protocol"] == "meshtastic"}
        for m in messages:
            m["text"] = (json.loads(m.pop("info")) or {}).get("text")
            m["from"] = names.get(m["src"])
        profiles = ctx.rows("SELECT profile, protocol, SUM(packets) packets, SUM(air_ms) / 1000.0 air_s FROM lora_stats WHERE minute >= ? "
                            "GROUP BY profile, protocol ORDER BY packets DESC", (int(since),))
        sensors = [s for s in status.snapshot() if s.get("type") == "lora"]
        # Channel use while listening: airtime heard / time spent on that profile. A hopping radio sits on each of its
        # profiles 1/N of the time, so that is the denominator (an estimate: other sensors, or a recent start, change it).
        span = hours * 3600
        started = [s["since"] for s in sensors if s.get("since")]
        if started:
            span = min(span, max(60, now - min(started)))
        local, _ = ctx.lora_control.effective() if ctx.lora_control else (ctx.cfg.lora_profiles, 0)
        share = 1 / len(local) if len(local) > 1 else 1
        air = {}
        for p in profiles:
            air[p["profile"]] = air.get(p["profile"], 0) + (p["air_s"] or 0)
        use = {name: round(min(1.0, s / (span * share)), 4) for name, s in air.items()}
        return {"now": now, "since": since, "bucket": bucket, "t": ts, "protocols": protocols, "profiles": profiles, "nodes": nodes,
                "recent": recent, "messages": messages, "decode_public": decode_enabled(ctx), "series": {k: [v.get(t, 0) for t in ts] for k, v in series.items()}, "sensors": sensors,
                "configured": bool(sensors) or ctx.cfg.demo or bool(ctx.cfg.lora_devices),
                "firmware_latest": (firmware_manifest() or {}).get("version"),
                "listening": [{"name": p.name, "label": p.label, "describe": p.describe(), "hint": p.hint, "air_s": round(air.get(p.name, 0), 2),
                               "use": use.get(p.name, 0.0)} for p in local],
                "known_profiles": [{"name": p.name, "label": p.label, "describe": p.describe()} for p in PROFILES.values()],
                "protocol_labels": PROTOCOLS}

    return r
