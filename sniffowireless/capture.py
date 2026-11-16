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
import zlib

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .auth import require_admin
from . import dissect as dis  # a module import: dissect.py imports lora.py, which imports this module
from .framefilter import FilterError, compile_filter

log = logging.getLogger("sniffowireless.capture")

RADIOS = ("wifi", "bt", "zigbee", "lora")
MAX_SECONDS = 3600
MAX_BYTES = 64 * 1024 * 1024      # of frames written (before compression)
MAX_FILES = 20
NAME = re.compile(r"^capture-\d{8}-\d{6}(?:-([a-z0-9][a-z0-9-]{0,31}))?\.jsonl\.gz$")  # the suffix: a remote sensor's id
REMOTE_UPLOAD_MAX = 48 * 1024 * 1024   # a remote sensor's recording as it arrives (gzip); httpsec.BODY_LIMITS has the same
REMOTE_START_WAIT = 90     # seconds for a sensor to say it started (it hears of the request with its next batch, every 2 s)
REMOTE_UPLOAD_WAIT = 600   # and after the recording should have ended, to deliver the file
RAW_MAX = 4096             # bytes of one frame in an uploaded recording


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


# ------------------------------------------------------------------ remote sensors
# On a remote sensor: the recording the server asked for, reported with every batch until it has been delivered.
SENSOR_JOB = {}


def record_for_server(cmd, folder, upload):
    """On a remote sensor: record what the server asked for, then upload the file with this sensor's token and remove it here."""
    rid = cmd.get("id")
    if not isinstance(rid, str) or not re.fullmatch(r"[0-9a-f]{16}", rid):
        return
    try:
        seconds = max(1, min(int(cmd.get("seconds") or 60), MAX_SECONDS))
    except (TypeError, ValueError):
        seconds = 60
    radios = [r for r in (cmd.get("radios") or RADIOS) if r in RADIOS] or list(RADIOS)

    def work():
        SENSOR_JOB.clear()
        SENSOR_JOB.update(id=rid, state="recording", frames=0, error=None)
        try:
            RECORDER.start(folder, seconds, radios)
            path = RECORDER.path
            while RECORDER.active and RECORDER.path == path:
                SENSOR_JOB["frames"] = RECORDER.frames
                time.sleep(1)
            SENSOR_JOB.update(state="uploading", frames=RECORDER.frames)
            for attempt in range(4):
                try:
                    upload(path, rid)
                    break
                except Exception as e:
                    if attempt == 3:
                        raise
                    log.warning("Uploading the recording to the server failed (%s); trying again", e)
                    time.sleep(10 * (attempt + 1))
            os.remove(path)
            SENSOR_JOB.clear()   # delivered: the server knows it from the upload
        except Exception as e:
            log.warning("The recording the server asked for failed: %s", e)
            SENSOR_JOB.update(state="failed", error=str(e)[:200])
    threading.Thread(target=work, daemon=True, name="capture-for-server").start()


# On the server: the recording asked of each remote sensor, {sensor id: {...}}, kept until the next one.
REMOTE = {}
REMOTE_LOCK = threading.Lock()


def remote_progress(sid, report):
    """A batch from a remote sensor said how its recording is going: {"id", "state", "frames", "error"}."""
    if not isinstance(report, dict):
        return
    with REMOTE_LOCK:
        job = REMOTE.get(sid)
        if not job or report.get("id") != job["id"] or job["state"] in ("done", "failed"):
            return
        state = report.get("state")
        if state in ("recording", "uploading"):
            if job["state"] == "requested":
                job["started"] = time.time()
            job["state"] = state
        elif state == "failed":
            job.update(state="failed", error=str(report.get("error") or "The sensor could not record")[:200])
        frames = report.get("frames")
        if isinstance(frames, int) and not isinstance(frames, bool) and 0 <= frames < 10 ** 9:
            job["frames"] = frames


def remote_jobs():
    """The remote recordings with a state that is up to date: one that took too long has failed."""
    now = time.time()
    with REMOTE_LOCK:
        for job in REMOTE.values():
            if job["state"] == "requested" and now - job["requested"] > REMOTE_START_WAIT:
                job.update(state="failed", error="The sensor did not start recording. It may be offline, or run a version older than 33.2 "
                                                 "(the Android app: older than 1.3.0). Update it, or use CAPTURE_AT_START on that machine.")
            elif job["state"] in ("recording", "uploading") and now - job.get("started", job["requested"]) > job["seconds"] + REMOTE_UPLOAD_WAIT:
                job.update(state="failed", error="The recording did not arrive from the sensor.")
        return {sid: dict(job) for sid, job in REMOTE.items()}


def clean_upload(data, dest):
    """Check a recording a remote sensor uploaded and write it again, line by line, keeping only what a recording holds. Returns how
    many frames it holds. Raises ValueError for anything that is not a recording."""
    import io
    out = gzip.open(dest + ".part", "wt", encoding="ascii")
    n = size = 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
            for line in f:
                size += len(line)
                if size > MAX_BYTES * 2:
                    raise ValueError("the recording is larger than a recording can be")
                try:
                    rec = json.loads(line)
                    raw = bytes.fromhex(rec["raw"])
                except (ValueError, KeyError, TypeError):
                    raise ValueError("the file is not a recording") from None
                if not isinstance(rec, dict) or rec.get("radio") not in RADIOS or len(raw) > RAW_MAX:
                    raise ValueError("the file is not a recording")
                ts = rec.get("ts")
                clean = {"ts": round(float(ts), 6) if isinstance(ts, (int, float)) and not isinstance(ts, bool) and 0 < ts < 4e9 else 0,
                         "radio": rec["radio"], "src": "".join(ch for ch in str(rec.get("src") or "")[:64] if ch.isprintable()), "raw": raw.hex()}
                for key, lo, hi in (("channel", 0, 300), ("rssi", -200, 50), ("lqi", 0, 255), ("tuned", 0, 100000)):
                    v = rec.get(key)
                    if isinstance(v, (int, float)) and not isinstance(v, bool) and lo <= v <= hi:
                        clean[key] = v
                out.write(json.dumps(clean, separators=(",", ":")) + "\n")
                n += 1
        out.close()
        os.replace(dest + ".part", dest)
        return n
    except (OSError, EOFError, zlib.error) as e:
        raise ValueError(f"the file is not a readable recording ({e})") from None
    finally:
        if not out.closed:
            out.close()
        if os.path.exists(dest + ".part"):
            os.remove(dest + ".part")

VIEW_MAX = 200_000   # frames of one recording shown in the inspector (a 64 MB recording holds about 100,000 to 300,000)
SUMMARY_KEYS = ("no", "time", "radio", "src", "dst", "proto", "len", "info", "rssi", "channel", "color", "type", "ssid", "name", "company", "bssid",
                "sensor", "pan", "epid", "network")


class Loaded:
    def __init__(self, key, frames, summaries, truncated, incomplete):
        self.key, self.frames, self.summaries = key, frames, summaries
        self.truncated, self.incomplete = truncated, incomplete
        self.first_ts = frames[0]["ts"] if frames else None
        self.counts = {}
        for f in frames:
            self.counts[f["radio"]] = self.counts.get(f["radio"], 0) + 1


class Views:
    """The recording open in the inspector: its frames and their summaries, read once (in the background: a big recording takes a
    while) and kept until another file is opened or the file changes; and the frames that passed the last few filters, so paging
    through them does not filter again."""

    def __init__(self):
        self.lock = threading.Lock()
        self.current = None
        self.filtered = {}
        self.job = None

    def get(self, path, vendor=None, wait=2.0):
        """(Loaded, None) when the recording is read, else (None, job) with job["read"] frames so far. Waits up to `wait` seconds
        (None: until it is done), so a small recording is answered at once."""
        st = os.stat(path)
        key = (path, st.st_mtime, st.st_size)
        with self.lock:
            if self.current and self.current.key == key:
                return self.current, None
            if not self.job or self.job["key"] != key:
                self.current, self.filtered = None, {}   # let go of the previous recording before reading the next
                self.job = {"key": key, "done": threading.Event(), "read": 0, "error": None}
                threading.Thread(target=self._read, args=(self.job, path, vendor), daemon=True, name="frames").start()
            job = self.job
        job["done"].wait(wait)
        with self.lock:
            if self.current and self.current.key == key:
                return self.current, None
        return None, job

    def load(self, path, vendor=None):
        loaded, job = self.get(path, vendor, wait=None)
        if loaded is None:
            raise ValueError(job["error"] or "The recording could not be read")
        return loaded

    def _read(self, job, path, vendor):
        frames, summaries, truncated, incomplete = [], [], False, False
        try:
            first = None
            try:
                for rec in read(path):
                    if len(frames) >= VIEW_MAX:
                        truncated = True
                        break
                    first = (rec.get("ts") or 0) if first is None else first
                    s = dis.summarize(rec, vendor)
                    s.update(no=len(frames) + 1, time=round((rec.get("ts") or first) - first, 6), radio=rec["radio"], sensor=rec.get("src"))
                    summaries.append({k: s[k] for k in SUMMARY_KEYS if s.get(k) not in (None, "")})
                    frames.append(rec)
                    job["read"] = len(frames)
                    if self.job is not job:   # another recording was opened meanwhile
                        return
            except (EOFError, OSError, zlib.error):  # still being written, or cut short: show what is there
                incomplete = True
            loaded = Loaded(job["key"], frames, summaries, truncated, incomplete)
            with self.lock:
                if self.job is job:
                    self.current, self.filtered, self.job = loaded, {}, None
        except Exception as e:
            log.exception("Could not read the recording %s", path)
            job["error"] = f"The recording could not be read: {e}"
        finally:
            job["done"].set()

    def matching(self, loaded, text):
        """Indexes of the frames that pass the filter (all of them for an empty one)."""
        text = (text or "").strip()
        with self.lock:
            hit = self.filtered.get(text) if self.current is loaded else None
        if hit is not None:
            return hit
        pred = compile_filter(text)
        out = list(range(len(loaded.summaries))) if pred is None else [i for i, s in enumerate(loaded.summaries) if pred(s)]
        with self.lock:
            if self.current is loaded:
                if len(self.filtered) > 8:
                    self.filtered.clear()
                self.filtered[text] = out
        return out


VIEWS = Views()


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
    sensor: str = Field("local", max_length=32)   # "local" (this server's radios) or a remote sensor's id


def routes(ctx):
    r = APIRouter()
    folder = directory(ctx.cfg)

    def files():
        try:
            names = sorted((n for n in os.listdir(folder) if NAME.match(n)), reverse=True)
        except OSError:
            return []
        current = os.path.basename(RECORDER.path) if RECORDER.active else None
        return [{"name": n, "size": os.path.getsize(os.path.join(folder, n)), "created": os.path.getmtime(os.path.join(folder, n)),
                 "sensor": NAME.match(n).group(1)} for n in names if n != current]

    def remote_sensors():
        now = time.time()
        return [{"id": x["id"], "name": x["name"] or x["id"], "online": bool(x["last_seen"] and now - x["last_seen"] < 120)}
                for x in ctx.rows("SELECT id, name, last_seen FROM sensors WHERE id != 'local' ORDER BY name")]

    def path_of(name):
        if not NAME.match(name) or not os.path.isfile(os.path.join(folder, name)):
            raise HTTPException(404, "No such recording")
        return os.path.join(folder, name)

    @r.get("/api/captures")
    def listing(_=Depends(require_admin)):
        from . import macprivacy
        sensors = remote_sensors()
        names = {x["id"]: x["name"] for x in sensors}
        out = files()
        for f in out:
            f["sensor_name"] = names.get(f["sensor"], f["sensor"]) if f["sensor"] else None
        remote = [{"sensor": sid, "sensor_name": names.get(sid, sid), **{k: v for k, v in job.items() if k != "id"}}
                  for sid, job in remote_jobs().items()]
        return {"active": RECORDER.state(), "files": out, "max_seconds": MAX_SECONDS, "max_files": MAX_FILES, "sensors": sensors, "remote": remote,
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
        if body.sensor != "local":   # a remote sensor: it hears of it with its next batch, records, and uploads the file
            from . import adapters
            sensor = next((x for x in remote_sensors() if x["id"] == body.sensor), None)
            if not sensor:
                raise HTTPException(404, "No such sensor")
            if not sensor["online"]:
                raise HTTPException(409, f"{sensor['name']} is offline")
            busy = remote_jobs().get(body.sensor)
            if busy and busy["state"] in ("requested", "recording", "uploading"):
                raise HTTPException(409, f"{sensor['name']} is recording already")
            import secrets
            rid = secrets.token_hex(8)
            with REMOTE_LOCK:
                REMOTE[body.sensor] = {"id": rid, "state": "requested", "requested": time.time(), "seconds": body.seconds, "radios": radios,
                                       "frames": 0, "error": None, "file": None}
            if ctx.cfg.demo:   # the demo's sensors are simulated: act out what a real one does
                from .demo import fake_remote_recording
                fake_remote_recording(ctx.cfg, body.sensor, rid, body.seconds)
            else:
                adapters.queue_capture(body.sensor, rid, body.seconds, radios)
            return {"queued": True, "sensor": body.sensor}
        try:
            return RECORDER.start(folder, body.seconds, radios)
        except RuntimeError as e:
            raise HTTPException(409, str(e))

    @r.post("/api/ingest/capture")
    async def upload(request: Request, id: str = ""):
        """A remote sensor delivers the recording the server asked for (sensor tokens only, and only the one asked for)."""
        u = request.state.user
        if not u or getattr(u, "scope", None) != "sensor" or not u.sensor_id:
            raise HTTPException(401, "sensor token required")
        sid = u.sensor_id
        with REMOTE_LOCK:
            job = REMOTE.get(sid)
            if not job or job["id"] != id or job["state"] in ("done", "failed"):
                raise HTTPException(409, "No recording was asked of this sensor")
            job["state"] = "uploading"
        data = await request.body()
        if len(data) > REMOTE_UPLOAD_MAX:
            raise HTTPException(413, "The recording is too large")
        name = time.strftime("capture-%Y%m%d-%H%M%S", time.localtime(job["requested"])) + f"-{sid}.jsonl.gz"
        os.makedirs(folder, exist_ok=True)
        try:
            from starlette.concurrency import run_in_threadpool
            n = await run_in_threadpool(clean_upload, data, os.path.join(folder, name))
        except ValueError as e:
            with REMOTE_LOCK:
                job.update(state="failed", error=f"The sensor sent a file that could not be used: {e}")
            raise HTTPException(400, str(e))
        with REMOTE_LOCK:
            job.update(state="done", file=name, frames=n)
        log.info("Received a recording of %d frames from sensor %s", n, sid)
        return {"ok": True, "frames": n}

    @r.post("/api/captures/stop")
    def stop(_=Depends(require_admin)):
        RECORDER.stop()
        return {"ok": True}

    @r.get("/api/captures/{name}")
    def download(name: str, _=Depends(require_admin)):
        return FileResponse(path_of(name), media_type="application/gzip", filename=name)

    # ------------------------------------------------------------ frame inspector
    def view_blocked():
        from . import anonymize, macprivacy
        if macprivacy.is_active() or any(anonymize.active_settings(ctx)):
            raise HTTPException(409, "MAC address privacy or the anonymised view is on, and a recording shows the real addresses and bytes. "
                                     "Switch it off to inspect recordings, or download the file.")

    vendor = ctx.store.vendors.lookup if ctx.store and getattr(ctx.store, "vendors", None) else None

    @r.get("/api/captures/{name}/frames")
    def frames(name: str, filter: str = "", offset: int = 0, limit: int = 500, _=Depends(require_admin)):
        """The frame list: one summary per frame (as many as `limit` from `offset`) of those that pass the display filter."""
        view_blocked()
        path = path_of(name)
        loaded, job = VIEWS.get(path, vendor)
        if loaded is None:  # a big recording: the page asks again and shows how far reading it has come
            if job["error"]:
                raise HTTPException(400, job["error"])
            return {"loading": True, "read": job["read"]}
        try:
            matched = VIEWS.matching(loaded, filter)
        except FilterError as e:
            raise HTTPException(400, str(e))
        offset, limit = max(0, offset), max(1, min(limit, 1000))  # the query limit (httpsec) allows 1000
        return {"total": len(loaded.summaries), "matched": len(matched), "offset": offset, "truncated": loaded.truncated,
                "incomplete": loaded.incomplete, "first_ts": loaded.first_ts, "counts": loaded.counts,
                "items": [loaded.summaries[i] for i in matched[offset:offset + limit]]}

    @r.get("/api/captures/{name}/frames/{number}")
    def frame(name: str, number: int, _=Depends(require_admin)):
        """One frame taken apart: its summary, the tree of fields with the bytes each came from, and the bytes."""
        view_blocked()
        loaded, job = VIEWS.get(path_of(name), vendor, wait=10)
        if loaded is None:
            raise HTTPException(409, job["error"] or "The recording is still being read")
        if not 1 <= number <= len(loaded.frames):
            raise HTTPException(404, "No such frame")
        s, tree, shown = dis.dissect(loaded.frames[number - 1], number, loaded.first_ts, vendor)
        return {"summary": loaded.summaries[number - 1], "tree": tree, "hex": shown.hex()}

    @r.delete("/api/captures/{name}")
    def delete(name: str, _=Depends(require_admin)):
        path = path_of(name)
        os.remove(path)
        with VIEWS.lock:
            if VIEWS.current and VIEWS.current.key[0] == path:  # don't keep a deleted recording in memory
                VIEWS.current, VIEWS.filtered = None, {}
            if VIEWS.job and VIEWS.job["key"][0] == path:  # nor go on reading it
                VIEWS.job = None
        return {"ok": True}

    return r
