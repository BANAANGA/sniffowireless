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
import threading
import time
from collections import deque
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from . import status
from .auth import current_user, require_admin
from .lora_protocols import AIR_PREAMBLE, PROFILES, PROTOCOLS, airtime_ms, classify

from .modules import cutoff_for

log = logging.getLogger("sniffowireless.lora")

SCHEMA = """
CREATE TABLE IF NOT EXISTS lora_packets(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, protocol TEXT NOT NULL, kind TEXT, src TEXT, dst TEXT, hops INTEGER,
  confidence INTEGER, profile TEXT, freq REAL, bw REAL, sf INTEGER, sync INTEGER, rssi REAL, snr REAL, bytes INTEGER, sensor TEXT, info TEXT);
CREATE INDEX IF NOT EXISTS idx_lora_packets_ts ON lora_packets(ts);
CREATE TABLE IF NOT EXISTS lora_nodes(
  protocol TEXT NOT NULL, addr TEXT NOT NULL, name TEXT, kind TEXT, packets INTEGER DEFAULT 0, rssi REAL, best_rssi REAL, snr REAL,
  profile TEXT, first_seen REAL, last_seen REAL, PRIMARY KEY(protocol, addr)) WITHOUT ROWID;
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


class LoraSensor:
    def __init__(self, device, cfg, sink, link_factory=LineLink):
        self.device, self.cfg, self.sink, self.link_factory = device, cfg, sink, link_factory
        self.name = f"lora:{os.path.basename(device)}"
        self.stop = None
        self.packets = 0
        self.profile = None
        status.register(self.name, type="lora", iface=device, profiles=[p.name for p in cfg.lora_profiles])

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
        for p in list(self.cfg.lora_profiles) + list(PROFILES.values()):
            if abs(p.freq - rx["freq"]) < 0.002 and p.sf == rx["sf"] and abs(p.bw - rx["bw"]) < 0.5 and p.sync == rx["sync"]:
                return p.name
        return self.profile.name if self.profile else "custom"

    def run(self, link):
        first = self.handshake(link)
        firmware = "lora-sniffer"
        status.update(self.name, state="listening", error=None, firmware=firmware, warning=None, fw_version=self.read_version(link))
        log.info("%s: sniffer answered (%s)", self.name, first)
        profiles = list(self.cfg.lora_profiles)
        refused = []
        i = 0
        last_heard = time.monotonic()
        while not self.stop.is_set():
            self.profile = profiles[i % len(profiles)]
            i += 1
            if not self.configure(link, self.profile):
                if self.profile.name not in refused:
                    refused.append(self.profile.name)
                    log.warning("%s: the sniffer refused %s (%s)", self.name, self.profile.name, self.profile.describe())
                status.update(self.name, warning="The sniffer refused " + ", ".join(refused) + ": the frequency may be outside its band")
                if len(refused) >= len(profiles):
                    raise LoraError("The sniffer refused every profile; check LORA_PROFILES against the board's frequency band")
                continue
            status.update(self.name, channel=f"{self.profile.freq:g} MHz SF{self.profile.sf}", profile=self.profile.name)
            dwell_end = time.monotonic() + (self.cfg.lora_hop_interval if len(profiles) > 1 else 10 ** 9)
            while not self.stop.is_set() and time.monotonic() < dwell_end:
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
        profile = PROFILES.get(o.get("profile") or "") or next((p for p in self.ctx.cfg.lora_profiles if p.name == o.get("profile")), None)
        r = classify(payload, o.get("sync"), profile.hint if profile else None)
        ts, protocol = o["ts"], r["protocol"]
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
                                                "profile": o.get("profile"), "first": ts, "last": ts}
            else:
                n["packets"] += 1
                n["name"] = name or n["name"]
                if kind != "hash":
                    n["kind"] = kind
                n["rssi"], n["snr"], n["last"], n["profile"] = rssi, snr, ts, o.get("profile")
                if rssi is not None and (n["best"] is None or rssi > n["best"]):
                    n["best"] = rssi
        self.pending = True

    def flush(self, store, c):
        if not self.pending:
            return
        c.executemany("INSERT INTO lora_packets(ts, protocol, kind, src, dst, hops, confidence, profile, freq, bw, sf, sync, rssi, snr, bytes, "
                      "sensor, info) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", self.packets)
        c.executemany(
            "INSERT INTO lora_nodes(protocol, addr, name, kind, packets, rssi, best_rssi, snr, profile, first_seen, last_seen) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(protocol, addr) DO UPDATE SET name=COALESCE(excluded.name, name), "
            "kind=CASE WHEN excluded.kind='hash' THEN kind ELSE excluded.kind END, packets=packets+excluded.packets, "
            "rssi=excluded.rssi, best_rssi=MAX(COALESCE(best_rssi, excluded.best_rssi), COALESCE(excluded.best_rssi, best_rssi)), "
            "snr=excluded.snr, profile=excluded.profile, last_seen=excluded.last_seen",
            [(p, a, n["name"], n["kind"], n["packets"], n["rssi"], n["best"], n["snr"], n["profile"], n["first"], n["last"])
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


def routes(ctx):
    r = APIRouter()

    @r.get("/api/lora/firmware")
    def firmware(_=Depends(require_admin)):
        m = firmware_manifest()
        if not m:
            raise HTTPException(404, "This build has no firmware image")
        return {**m, "url": "/api/lora/firmware.bin"}

    @r.get("/api/lora/firmware.bin")
    def firmware_bin(_=Depends(require_admin)):
        m = firmware_manifest()
        if not m:
            raise HTTPException(404, "This build has no firmware image")
        return FileResponse(FIRMWARE_DIR / m["file"], media_type="application/octet-stream", filename=m["file"])

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
        for n in nodes:
            n["label"] = PROTOCOLS.get(n["protocol"], n["protocol"])
        recent = ctx.rows("SELECT * FROM lora_packets WHERE ts >= ? ORDER BY id DESC LIMIT 100", (since,))
        for p in recent:
            p["label"] = PROTOCOLS.get(p["protocol"], p["protocol"])
            p["info"] = json.loads(p["info"]) if p["info"] else {}
        profiles = ctx.rows("SELECT profile, protocol, SUM(packets) packets, SUM(air_ms) / 1000.0 air_s FROM lora_stats WHERE minute >= ? "
                            "GROUP BY profile, protocol ORDER BY packets DESC", (int(since),))
        sensors = [s for s in status.snapshot() if s.get("type") == "lora"]
        # Channel use while listening: airtime heard / time spent on that profile. A hopping radio sits on each of its
        # profiles 1/N of the time, so that is the denominator (an estimate: other sensors, or a recent start, change it).
        span = hours * 3600
        started = [s["since"] for s in sensors if s.get("since")]
        if started:
            span = min(span, max(60, now - min(started)))
        share = 1 / len(ctx.cfg.lora_profiles) if len(ctx.cfg.lora_profiles) > 1 else 1
        air = {}
        for p in profiles:
            air[p["profile"]] = air.get(p["profile"], 0) + (p["air_s"] or 0)
        use = {name: round(min(1.0, s / (span * share)), 4) for name, s in air.items()}
        return {"now": now, "since": since, "bucket": bucket, "t": ts, "protocols": protocols, "profiles": profiles, "nodes": nodes,
                "recent": recent, "series": {k: [v.get(t, 0) for t in ts] for k, v in series.items()}, "sensors": sensors,
                "configured": bool(sensors) or ctx.cfg.demo or bool(ctx.cfg.lora_devices),
                "firmware_latest": (firmware_manifest() or {}).get("version"),
                "listening": [{"name": p.name, "label": p.label, "describe": p.describe(), "hint": p.hint, "air_s": round(air.get(p.name, 0), 2),
                               "use": use.get(p.name, 0.0)} for p in ctx.cfg.lora_profiles],
                "known_profiles": [{"name": p.name, "label": p.label, "describe": p.describe()} for p in PROFILES.values()],
                "protocol_labels": PROTOCOLS}

    return r
