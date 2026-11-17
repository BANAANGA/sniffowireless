"""Automatic recording: a frame recording that starts by itself when an event happens, with the seconds before it.

While it is on, the chosen sensors keep the last `pre` seconds of frames of the chosen radios in memory (capture.PREBUF; a remote
sensor is armed with each batch reply). When an event of a chosen type happens (a connection to my network that failed, a slow
roam, a deauthentication flood, ...), each chosen sensor writes that buffer to a new recording and goes on recording for `post`
seconds, so the recording holds what led up to the event and what followed. After that, nothing is started for `cooldown`
seconds. The recording is listed with the others and says which event started it.

Like any recording it holds real addresses, so nothing is armed or recorded while MAC address privacy is on.
"""
import json
import logging
import os
import threading
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from . import capture
from .auth import require_admin

log = logging.getLogger("sniffowireless.triggers")

INDEX = "triggers.json"   # in the recordings folder: which event started which recording
TRIGGERABLE = ["connection_failed", "roam_slow", "deauth_flood", "deauth_broadcast", "handshake_attack", "rogue_ap", "karma_ap",
               "interference", "dfs_radar", "ap_restart", "disconnected", "mac_duplicate", "probe_scan"]


def settings(ctx):
    return ctx.settings.get("triggers")


def privacy_on(ctx=None):
    """MAC address privacy is on, or switched on just now (the setting is checked too: its own handler may not have run yet)."""
    from . import macprivacy
    if macprivacy.is_active():
        return True
    try:
        return bool(ctx and (ctx.settings.get("privacy") or {}).get("macs"))
    except Exception:
        return False


def arm_request(ctx, sid):
    """What a remote sensor's batch reply says when automatic recording includes it: the radios and seconds to keep."""
    t = settings(ctx)
    if not t.get("enabled") or sid not in t.get("sensors", []) or privacy_on(ctx):
        return None
    return {"radios": t["radios"], "seconds": t["pre"]}


def arm_local(ctx):
    """Keep (or stop keeping) the last seconds of this server's own radios."""
    t = settings(ctx)
    if t.get("enabled") and "local" in t.get("sensors", []) and not privacy_on(ctx):
        capture.PREBUF.arm(t["radios"], t["pre"])
    elif capture.PREBUF.radios:
        capture.PREBUF.disarm()


def index_path(ctx):
    return os.path.join(capture.directory(ctx.cfg), INDEX)


def read_index(ctx):
    try:
        with open(index_path(ctx)) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def note(ctx, name, ev):
    """Remember which event started recording `name` (the newest 200)."""
    d = read_index(ctx)
    d[name] = {"type": ev["type"], "mac": ev.get("mac"), "detail": ev.get("detail"), "ts": ev["ts"]}
    d = dict(sorted(d.items(), key=lambda kv: kv[1].get("ts") or 0)[-200:])
    os.makedirs(os.path.dirname(index_path(ctx)), exist_ok=True)
    tmp = index_path(ctx) + ".part"
    with open(tmp, "w") as f:
        json.dump(d, f)
    os.replace(tmp, index_path(ctx))


class TriggerWatcher:
    """Listens to the events the store commits and starts the recordings."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.last = 0.0
        self.fired = []   # the newest first: {ts, type, mac, detail, recordings: [...], skipped}
        self.lock = threading.Lock()
        ctx.store.listeners.append(self.on_events)
        ctx.settings.on_change(lambda k: arm_local(ctx) if k in ("triggers", "privacy") else None)
        arm_local(ctx)

    def on_events(self, events):
        t = settings(self.ctx)
        if not t.get("enabled"):
            return
        for ev in events:
            if ev.get("type") in t["events"]:
                self.fire(ev, t)

    def fire(self, ev, t):
        with self.lock:
            now = time.time()
            if now - self.last < t["cooldown"]:
                return
            self.last = now
        entry = {"ts": now, "type": ev["type"], "mac": ev.get("mac"), "detail": ev.get("detail"), "recordings": [], "skipped": []}
        if privacy_on(self.ctx):
            entry["skipped"].append("MAC address privacy is on")
        else:
            folder = capture.directory(self.ctx.cfg)
            for sid in t["sensors"]:
                try:
                    name = self.record(sid, t, folder)
                    entry["recordings"].append(name)
                    note(self.ctx, name, ev)
                except Exception as e:
                    entry["skipped"].append(f"{sid}: {e}")
        log.info("Event %s started automatic recording: %s%s", ev["type"], ", ".join(entry["recordings"]) or "none",
                 f" ({'; '.join(entry['skipped'])})" if entry["skipped"] else "")
        self.fired = [entry] + self.fired[:19]

    def record(self, sid, t, folder):
        names = [n for n in os.listdir(folder) if capture.NAME.match(n)] if os.path.isdir(folder) else []
        if len(names) >= capture.MAX_FILES:
            raise RuntimeError(f"there are {capture.MAX_FILES} recordings already")
        if sid == "local":
            if self.ctx.cfg.demo:   # the demo's radios are simulated: a made-up recording stands in
                from . import sample_frames
                name = time.strftime("capture-%Y%m%d-%H%M%S.jsonl.gz")
                sample_frames.write_recording(os.path.join(folder, name), count=300, start=time.time() - t["pre"])
                return name
            if capture.RECORDER.active:
                raise RuntimeError("a recording is running already")
            pre = capture.PREBUF.since(time.time() - t["pre"])
            capture.RECORDER.start(folder, t["post"], t["radios"], pre=pre)
            return os.path.basename(capture.RECORDER.path)
        sensor = self.ctx.one("SELECT last_seen FROM sensors WHERE id=?", (sid,))
        if not sensor or not sensor["last_seen"] or time.time() - sensor["last_seen"] > 120:
            raise RuntimeError("offline")
        return capture.ask_remote(self.ctx, sid, t["post"], t["radios"], pre=t["pre"])


class TriggerBody(BaseModel):
    enabled: bool = False
    events: list[str] = Field(default_factory=list, max_length=len(TRIGGERABLE))
    sensors: list[str] = Field(default_factory=lambda: ["local"], max_length=50)
    radios: list[str] = Field(default_factory=lambda: ["wifi"], max_length=4)
    pre: int = Field(30, ge=0, le=120)
    post: int = Field(60, ge=10, le=600)
    cooldown: int = Field(600, ge=60, le=86400)


def routes(ctx):
    r = APIRouter()

    @r.get("/api/captures/triggers")
    def get_triggers(_=Depends(require_admin)):
        from .alerts import EVENT_TYPES
        sensors = [{"id": "local", "name": "This server"}] + [{"id": x["id"], "name": x["name"] or x["id"]}
                                                              for x in ctx.rows("SELECT id, name FROM sensors WHERE id != 'local' ORDER BY name")]
        w = getattr(ctx, "triggers", None)
        return {"settings": settings(ctx), "events": {k: EVENT_TYPES[k] for k in TRIGGERABLE if k in EVENT_TYPES}, "sensors": sensors,
                "fired": w.fired if w else [], "armed": capture.PREBUF.active, "buffered": len(capture.PREBUF.items),
                "blocked": "MAC address privacy is on: nothing is recorded" if privacy_on(ctx) else None}

    @r.put("/api/captures/triggers")
    def put_triggers(body: TriggerBody, _=Depends(require_admin)):
        events = [e for e in body.events if e in TRIGGERABLE]
        radios = [x for x in body.radios if x in capture.RADIOS]
        known = {"local"} | {x["id"] for x in ctx.rows("SELECT id FROM sensors")}
        sensors = [s for s in body.sensors if s in known]
        if body.enabled and not (events and radios and sensors):
            raise HTTPException(400, "Choose at least one event, one radio and one sensor")
        ctx.settings.set("triggers", {"enabled": body.enabled, "events": events, "sensors": sensors, "radios": radios,
                                      "pre": body.pre, "post": body.post, "cooldown": body.cooldown})
        return {"ok": True}

    return r
