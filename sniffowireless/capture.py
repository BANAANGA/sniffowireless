"""Record what the radios hear, exactly as they hear it, and play it back through the parsers.

Identification rules are written from published frame layouts. To check them against real devices, and to keep samples that later
changes can be tested against, the raw input of every radio can be recorded to a file:

    Wi-Fi       the frame with its radiotap header (data frames: headers only, never their contents)
    Bluetooth   the HCI event from the controller
    Zigbee      the 802.15.4 frame, with channel and signal
    LoRa        the line the sniffer board printed

A recording is a gzip file of JSON lines, one per frame: {"ts", "radio", "src", "raw" (hex), ...}. It holds real addresses and names,
whatever the privacy settings are, so recording is refused while MAC address privacy is on, is admin-only, is limited in time and
size, and stops by itself.

Playing it back (`python -m sniffowireless replay FILE`) runs every frame through the same parsers and the same store as live
capture, into a temporary database, and prints what was identified. Nothing is transmitted and the real database is not touched.
"""
import gzip
import json
import logging
import os
import re
import sys
import tempfile
import threading
import time

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .auth import require_admin

log = logging.getLogger("sniffowireless.capture")

RADIOS = ("wifi", "bt", "zigbee", "lora")
MAX_SECONDS = 3600
MAX_BYTES = 64 * 1024 * 1024      # of frames written (before compression)
MAX_FILES = 20
NAME = re.compile(r"^capture-\d{8}-\d{6}\.jsonl\.gz$")


def trim_wifi(raw):
    """A data frame cut down to its radiotap and 802.11 headers: the parsers only read addresses from it, and its contents are
    somebody's traffic. Management and control frames are kept whole."""
    if len(raw) < 4:
        return raw
    rt = int.from_bytes(raw[2:4], "little")
    if len(raw) > rt + 1 and (raw[rt] >> 2) & 3 == 2:
        fc0, fc1 = raw[rt], raw[rt + 1]
        header = 24 + (6 if fc1 & 3 == 3 else 0)           # a fourth address when both to-DS and from-DS are set
        if fc0 & 0x80:                                      # QoS data: QoS control, and HT control when the order bit is set
            header += 2 + (4 if fc1 & 0x80 else 0)
        return raw[:rt + header]
    return raw


class Recorder:
    def __init__(self):
        self.lock = threading.Lock()
        self.active = False
        self.file = self.path = None
        self.radios, self.until, self.started = set(), 0.0, 0.0
        self.frames, self.size = 0, 0
        self.counts = {}

    def start(self, directory, seconds, radios=RADIOS):
        seconds = max(1, min(int(seconds), MAX_SECONDS))
        os.makedirs(directory, exist_ok=True)
        with self.lock:
            if self.active:
                raise RuntimeError("A recording is already running")
            now = time.time()
            self.path = os.path.join(directory, time.strftime("capture-%Y%m%d-%H%M%S.jsonl.gz", time.localtime(now)))
            self.file = gzip.open(self.path, "wt", encoding="ascii")
            self.radios, self.started, self.until = set(radios) & set(RADIOS), now, now + seconds
            self.frames = self.size = 0
            self.counts = {}
            self.active = True
        threading.Thread(target=self._watch, daemon=True, name="capture").start()
        log.info("Recording %s to %s for %d s", ", ".join(sorted(self.radios)), self.path, seconds)
        return self.state()

    def _watch(self):  # a quiet radio never calls record(): the clock has to stop the recording too
        while self.active:
            if time.time() >= self.until:
                self.stop()
            time.sleep(0.5)

    def stop(self):
        with self.lock:
            if not self.active:
                return None
            self.active = False
            try:
                self.file.close()
            finally:
                self.file = None
        log.info("Recording stopped: %d frames in %s", self.frames, self.path)
        return self.path

    def record(self, radio, src, raw, **meta):
        """Called by the sensors for every frame; cheap when nothing is being recorded."""
        if not self.active or radio not in self.radios:
            return
        if radio == "wifi":
            raw = trim_wifi(raw)
        line = json.dumps({"ts": round(time.time(), 6), "radio": radio, "src": src, "raw": bytes(raw).hex(), **meta}, separators=(",", ":"))
        done = False
        with self.lock:
            if not self.active:
                return
            self.file.write(line + "\n")
            self.frames += 1
            self.counts[radio] = self.counts.get(radio, 0) + 1
            self.size += len(line) + 1
            done = self.size >= MAX_BYTES or time.time() >= self.until
        if done:
            self.stop()

    def state(self):
        if not self.active:
            return None
        return {"name": os.path.basename(self.path), "started": self.started, "until": self.until, "radios": sorted(self.radios),
                "frames": self.frames, "counts": dict(self.counts), "bytes": self.size}


RECORDER = Recorder()


def directory(cfg):
    return os.path.join(cfg.data_dir, "captures")


def start_from_env(cfg):
    """CAPTURE_AT_START=<seconds> records from the moment the process starts: the way to record on a remote sensor, which has no
    web interface of its own. The file is written to <data dir>/captures on that machine."""
    seconds = os.environ.get("CAPTURE_AT_START", "").strip()
    if seconds.isdigit() and int(seconds) > 0:
        RECORDER.start(directory(cfg), int(seconds))


def read(path):
    """The frames of a recording, in order; a line that is not a frame is skipped."""
    with gzip.open(path, "rt", encoding="ascii", errors="replace") as f:
        for line in f:
            try:
                rec = json.loads(line)
                rec["raw"] = bytes.fromhex(rec["raw"])
            except (ValueError, KeyError, TypeError):
                continue
            if rec.get("radio") in RADIOS:
                yield rec


class _Direct:
    """Stands in for the store's queue during a replay: every observation is processed at once, in order."""

    def __init__(self, store):
        self.store = store

    def put(self, o):
        self.store.process(o)


def replay(path, ctx):
    """Run a recording through the parsers into ctx's store, as if it were heard now (the recorded times only give the order).
    Returns {"frames": per radio, "observations": per radio}."""
    from scapy.layers.dot11 import RadioTap

    from .bluetooth import BluetoothSensor, parse_event
    from .lora import LoraSensor
    from .wifi import AttrGates, FingerprintGate, parse_frame
    from .zigbee_radio import FrameBatch

    store, sink = ctx.store, _Direct(ctx.store)
    frames, seen = {}, {"n": 0}
    counted = type("Counted", (), {"put": lambda self, o: (seen.__setitem__("n", seen["n"] + 1), sink.put(o))})()
    fp_gate, gates, batch = FingerprintGate(), AttrGates(), FrameBatch()
    bt, lora = {}, {}
    obs = {}
    for rec in read(path):
        radio, raw, now = rec["radio"], rec["raw"], time.time()
        src = str(rec.get("src") or radio)
        frames[radio] = frames.get(radio, 0) + 1
        before = seen["n"]
        try:
            if radio == "wifi":
                pkt = RadioTap(raw)
                pkt.time = now
                for o in parse_frame(pkt, fp_gate, rec.get("tuned"), gates, True):
                    counted.put(o)
            elif radio == "bt":
                if src not in bt:
                    bt[src] = BluetoothSensor(f"hci{90 + len(bt)}", ctx.cfg, counted)
                for ev in parse_event(raw):
                    bt[src]._handle(ev, now)
            elif radio == "zigbee":
                if not isinstance(rec.get("channel"), int) or not 11 <= rec["channel"] <= 26:
                    continue  # no usable channel: not a frame a stick delivered
                batch.add({"channel": rec.get("channel"), "rssi": rec.get("rssi"), "lqi": rec.get("lqi"), "data": raw})
                seen["n"] += 1
            elif radio == "lora":
                if src not in lora:
                    lora[src] = LoraSensor(f"replay{len(lora)}", ctx.cfg, counted)
                lora[src].handle_line(raw.decode("ascii", "replace"))
        except Exception:
            log.debug("Replay: a %s frame could not be parsed", radio, exc_info=True)
        obs[radio] = obs.get(radio, 0) + seen["n"] - before
    o = batch.drain(time.time())
    if o:
        store.process(o)
    store.flush()
    return {"frames": frames, "observations": obs}


def identified(ctx):
    """What a replay left in the database, for people and for tests: one dict per device, Zigbee radio and LoRa node."""
    from .zigbee import HINTS, device_guess
    from .zigbee_radio import role_of
    out = {"devices": [], "zigbee": [], "lora": []}
    for d in ctx.rows("SELECT mac, kind, vendor, name, ssid, brand, model, dev_type, os, randomized, json_extract(ident, '$.label') label "
                      "FROM devices ORDER BY kind, mac"):
        out["devices"].append({k: v for k, v in d.items() if v not in (None, "", 0)})
    for r in ctx.rows("SELECT pan, addr, hint, roles, caps, vendor FROM zigbee_radios ORDER BY pan, addr"):
        hint = HINTS[r["hint"]] if 0 <= (r["hint"] or 0) < len(HINTS) else "unknown"
        row = {"pan": r["pan"], "addr": r["addr"], "protocol": hint, "role": role_of(r["roles"] or 0),
               "device": device_guess(r["addr"], r["roles"] or 0, r["caps"], hint), "vendor": r["vendor"]}
        out["zigbee"].append({k: v for k, v in row.items() if v is not None})
    for n in ctx.rows("SELECT protocol, addr, name, kind FROM lora_nodes ORDER BY protocol, addr"):
        out["lora"].append({k: v for k, v in n.items() if v is not None})
    return out


def replay_cli(argv):
    """python -m sniffowireless replay FILE [--json]"""
    import dataclasses

    from . import status
    from .config import Config
    from .main import build
    as_json = "--json" in argv
    files = [a for a in argv if not a.startswith("--")]
    if len(files) != 1:
        print("usage: python -m sniffowireless replay FILE [--json]", file=sys.stderr)
        return 2
    root = logging.getLogger("sniffowireless")
    level = root.level
    root.setLevel(logging.ERROR)  # only the result is printed, not the start-up messages of a throw-away database
    try:
        with tempfile.TemporaryDirectory(prefix="sniffowireless-replay-") as tmp:
            status.SENSORS.clear()
            ctx = build(dataclasses.replace(Config.from_env(), db_path=os.path.join(tmp, "replay.db"), data_dir=tmp, demo=False))
            counts = replay(files[0], ctx)
            found = identified(ctx)
    finally:
        root.setLevel(level)
    if as_json:
        print(json.dumps({**counts, **found}, indent=1))
        return 0
    print("Frames read:    " + (", ".join(f"{k} {v}" for k, v in sorted(counts["frames"].items())) or "none"))
    print("Parsed into:    " + (", ".join(f"{k} {v}" for k, v in sorted(counts["observations"].items())) or "nothing"))
    print(f"\nDevices ({len(found['devices'])})")
    for d in found["devices"]:
        what = " · ".join(str(d[k]) for k in ("label", "brand", "model", "dev_type", "os", "vendor", "name", "ssid") if k in d)
        print(f"  {d['kind']:<12} {d['mac']}  {what or '(not identified)'}")
    if found["zigbee"]:
        print(f"\nZigbee / Thread radios ({len(found['zigbee'])})")
        for r in found["zigbee"]:
            print(f"  {r['addr']:<14} pan {r['pan']}  {' · '.join(str(r[k]) for k in ('protocol', 'role', 'device', 'vendor') if k in r)}")
    if found["lora"]:
        print(f"\nLoRa nodes ({len(found['lora'])})")
        for n in found["lora"]:
            print(f"  {n['protocol']:<11} {n['addr']}  {' · '.join(str(n[k]) for k in ('name', 'kind') if k in n)}")
    return 0


class StartBody(BaseModel):
    seconds: int = Field(60, ge=5, le=MAX_SECONDS)
    radios: list[str] = Field(default_factory=lambda: list(RADIOS), max_length=4)


def routes(ctx):
    r = APIRouter()
    folder = directory(ctx.cfg)

    def files():
        try:
            names = sorted((n for n in os.listdir(folder) if NAME.match(n)), reverse=True)
        except OSError:
            return []
        current = os.path.basename(RECORDER.path) if RECORDER.active else None
        return [{"name": n, "size": os.path.getsize(os.path.join(folder, n)), "created": os.path.getmtime(os.path.join(folder, n))}
                for n in names if n != current]

    def path_of(name):
        if not NAME.match(name) or not os.path.isfile(os.path.join(folder, name)):
            raise HTTPException(404, "No such recording")
        return os.path.join(folder, name)

    @r.get("/api/captures")
    def listing(_=Depends(require_admin)):
        from . import macprivacy
        return {"active": RECORDER.state(), "files": files(), "max_seconds": MAX_SECONDS, "max_files": MAX_FILES,
                "blocked": "MAC address privacy is on: a recording would hold the real addresses" if macprivacy.is_active() else None}

    @r.post("/api/captures")
    def start(body: StartBody, _=Depends(require_admin)):
        from . import macprivacy
        if macprivacy.is_active():
            raise HTTPException(409, "MAC address privacy is on. A recording holds real addresses, so switch privacy off first or record on a test setup.")
        radios = [x for x in body.radios if x in RADIOS]
        if not radios:
            raise HTTPException(400, "Choose at least one radio")
        if len(files()) >= MAX_FILES:
            raise HTTPException(409, f"There are {MAX_FILES} recordings already. Delete some first.")
        try:
            return RECORDER.start(folder, body.seconds, radios)
        except RuntimeError as e:
            raise HTTPException(409, str(e))

    @r.post("/api/captures/stop")
    def stop(_=Depends(require_admin)):
        RECORDER.stop()
        return {"ok": True}

    @r.get("/api/captures/{name}")
    def download(name: str, _=Depends(require_admin)):
        return FileResponse(path_of(name), media_type="application/gzip", filename=name)

    @r.delete("/api/captures/{name}")
    def delete(name: str, _=Depends(require_admin)):
        os.remove(path_of(name))
        return {"ok": True}

    return r
