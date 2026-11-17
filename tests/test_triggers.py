"""Automatic recording (release 35): a recording that starts by itself when an event happens, with the seconds before it."""
import gzip
import json
import os
import time

import pytest
from fastapi.testclient import TestClient
from test_hardening import client, ctx  # noqa: F401  (ctx is a fixture)

from sniffowireless import adapters, capture, sample_frames as sf, triggers
from sniffowireless.sensors import Forwarder
from sniffowireless.web import create_app

CL, AP1, AP2 = "aa:bb:cc:00:00:01", "24:a4:3c:10:00:01", "24:a4:3c:10:00:02"


@pytest.fixture(autouse=True)
def clean():
    capture.PREBUF.disarm()
    capture.REMOTE.clear()
    adapters.PENDING.clear()
    yield
    capture.PREBUF.disarm()
    if capture.RECORDER.active:
        capture.RECORDER.stop()


def test_the_buffer_keeps_the_last_seconds():
    assert not capture.tapping()
    capture.PREBUF.arm(["wifi"], 30)
    assert capture.tapping()
    capture.RECORDER.record("wifi", "wifi:wlan0mon", sf.qos_data() + b"secret" * 10)
    capture.RECORDER.record("bt", "bt:hci0", sf.le_adv())   # not armed for Bluetooth
    assert len(capture.PREBUF.items) == 1 and b"secret" not in capture.PREBUF.items[0]["raw"]
    capture.PREBUF.items[0]["ts"] -= 31
    capture.RECORDER.record("wifi", "wifi:wlan0mon", sf.beacon())
    assert len(capture.PREBUF.items) == 1   # the old one went
    assert capture.PREBUF.since(time.time() - 5)[0]["raw"] == sf.beacon()
    capture.PREBUF.disarm()
    assert not capture.tapping() and not capture.PREBUF.items


def test_a_recording_starts_with_the_frames_before(tmp_path):
    pre = [{"ts": time.time() - 3, "radio": "wifi", "src": "wifi:wlan0mon", "raw": sf.beacon(), "tuned": 2437},
           {"ts": time.time() - 2, "radio": "bt", "src": "bt:hci0", "raw": sf.le_adv()}]
    capture.RECORDER.start(str(tmp_path), 60, ["wifi"], pre=pre)
    capture.RECORDER.record("wifi", "wifi:wlan0mon", sf.probe_request())
    path = capture.RECORDER.stop()
    recs = list(capture.read(path))
    assert [r["raw"] for r in recs] == [sf.beacon(), sf.probe_request()] and recs[0]["tuned"] == 2437


def steps(ctx, items):
    t = time.time()
    for dt, step, extra in items:
        ctx.store.process({"t": "join", "ts": t + dt, "mac": CL, "step": step, "from_ap": extra.pop("from_ap", False), **extra})
    ctx.store.flush()
    return [dict(r) for r in ctx.rows("SELECT type, detail FROM events WHERE type IN ('connection_failed', 'roam_slow')")]


def mine(ctx):
    ctx.settings.set("networks", {"ssids": ["Home"], "trusted_bssids": []})
    for ap in (AP1, AP2):
        ctx.execute("INSERT INTO devices(mac, kind, ssid, last_seen, first_seen) VALUES(?, 'ap', 'Home', ?, 0)", (ap, time.time()))


def test_events_of_failed_connections_and_slow_roams(ctx):
    mine(ctx)
    ev = steps(ctx, [(0, "auth", {"bssid": AP1, "algo": 0, "seq": 1, "code": 0}), (0.01, "assoc", {"bssid": AP1}),
                     (0.02, "assoc_resp", {"bssid": AP1, "code": 0, "from_ap": True}), (0.03, "m1", {"bssid": AP1, "from_ap": True}),
                     (0.04, "m2", {"bssid": AP1}), (1.0, "m1", {"bssid": AP1, "from_ap": True}), (1.01, "m2", {"bssid": AP1}),
                     (3.0, "deauth", {"bssid": AP1, "code": 15, "from_ap": True})])
    assert ev == [{"type": "connection_failed", "detail": "4-way handshake timed out (often a wrong password)"}]
    ctx.execute("DELETE FROM events")
    ev = steps(ctx, [(10, "auth", {"bssid": AP1, "algo": 0, "seq": 1, "code": 0}), (10.01, "assoc", {"bssid": AP1}),
                     (10.02, "assoc_resp", {"bssid": AP1, "code": 0, "from_ap": True}), (10.03, "m1", {"bssid": AP1, "from_ap": True}),
                     (10.04, "m4", {"bssid": AP1}),   # connected
                     (60, "auth", {"bssid": AP2, "algo": 0, "seq": 1, "code": 0}), (60.01, "reassoc", {"bssid": AP2, "detail": AP1}),
                     (60.02, "reassoc_resp", {"bssid": AP2, "code": 0, "from_ap": True}), (60.3, "m4", {"bssid": AP2}),   # 300 ms
                     (120, "auth", {"bssid": AP1, "algo": 2, "seq": 1, "code": 0}), (120.005, "reassoc", {"bssid": AP1, "detail": AP2}),
                     (120.012, "reassoc_resp", {"bssid": AP1, "code": 0, "from_ap": True})])   # 12 ms, 802.11r: not slow
    assert len(ev) == 1 and ev[0]["type"] == "roam_slow" and ev[0]["detail"].startswith("300 ms from 24:a4:3c:10:00:01")


def test_only_my_networks(ctx):
    mine(ctx)
    ev = steps(ctx, [(0, "assoc_resp", {"bssid": "dd:dd:dd:00:00:01", "code": 17, "from_ap": True})])
    assert ev == []
    assert steps(ctx, [(0, "assoc_resp", {"bssid": AP1, "code": 17, "from_ap": True})])[0]["detail"].startswith("association refused")


def arm(ctx, **kw):
    ctx.settings.set("triggers", {"enabled": True, "events": ["connection_failed"], "sensors": ["local"], "radios": ["wifi"], "pre": 30,
                                  "post": 60, "cooldown": 600, **kw})


def test_an_event_starts_a_recording_with_the_seconds_before(ctx):
    w = triggers.TriggerWatcher(ctx)
    arm(ctx)
    assert capture.PREBUF.active   # this server's radios keep the last seconds now
    capture.RECORDER.record("wifi", "wifi:wlan0mon", sf.beacon())
    w.on_events([{"ts": time.time(), "mac": CL, "type": "disconnected", "detail": "x"}])   # not chosen
    assert not capture.RECORDER.active
    w.on_events([{"ts": time.time(), "mac": CL, "type": "connection_failed", "detail": "association refused"}])
    assert capture.RECORDER.active
    name = os.path.basename(capture.RECORDER.path)
    capture.RECORDER.stop()
    first = json.loads(gzip.open(os.path.join(capture.directory(ctx.cfg), name), "rt").readline())
    assert bytes.fromhex(first["raw"]) == sf.beacon()
    w.on_events([{"ts": time.time(), "mac": CL, "type": "connection_failed", "detail": "again"}])
    assert not capture.RECORDER.active   # cooling down
    assert w.fired[0]["recordings"] == [name]
    listing = client(create_app(ctx), "admin").get("/api/captures").json()["files"]
    assert next(f for f in listing if f["name"] == name)["trigger"]["type"] == "connection_failed"


def test_a_remote_sensor_is_armed_and_asked(ctx):
    tid, token = ctx.auth.create_token("sensor office", "sensor", "office")
    ctx.execute("INSERT INTO sensors(id, name, token_id, created, last_seen) VALUES('office', 'Office', ?, 0, ?)", (tid, time.time()))
    w = triggers.TriggerWatcher(ctx)
    arm(ctx, sensors=["office"], pre=20)
    assert not capture.PREBUF.active   # not this server's radios
    app = create_app(ctx)
    sensor = TestClient(app, base_url="http://sniffowireless.test", headers={"authorization": "Bearer " + token})
    reply = sensor.post("/api/ingest", content=json.dumps({"sent_at": time.time(), "obs": []})).json()
    assert reply["arm"] == {"radios": ["wifi"], "seconds": 20}
    w.on_events([{"ts": time.time(), "mac": CL, "type": "connection_failed", "detail": "x"}])
    cmd = adapters.PENDING["office"][-1]
    assert cmd["action"] == "capture" and cmd["pre"] == 20 and cmd["seconds"] == 60
    assert w.fired[0]["recordings"][0].endswith("-office.jsonl.gz")


def test_the_sensor_side(tmp_path):
    from sniffowireless.config import Config
    f = Forwarder.__new__(Forwarder)
    f.cfg = Config(data_dir=str(tmp_path))
    f._arm_config({"radios": ["wifi", "sdr"], "seconds": 999})
    assert capture.PREBUF.active and capture.PREBUF.radios == {"wifi"} and capture.PREBUF.seconds == 120
    capture.RECORDER.record("wifi", "wifi:wlan0", sf.beacon())
    got = {}
    capture.record_for_server({"id": "0123456789abcdef", "seconds": 1, "radios": ["wifi"], "pre": 30}, str(tmp_path / "c"),
                              lambda path, rid: got.update(recs=list(capture.read(path))))
    for _ in range(400):
        if "recs" in got:
            break
        time.sleep(0.02)
    assert got["recs"][0]["raw"] == sf.beacon()
    f._arm_config(None)
    assert not capture.PREBUF.active


def test_nothing_while_addresses_are_private(ctx):
    w = triggers.TriggerWatcher(ctx)
    arm(ctx)
    p = ctx.settings.get("privacy")
    ctx.settings.set("privacy", {**p, "macs": True})
    assert not capture.PREBUF.active
    w.on_events([{"ts": time.time(), "mac": CL, "type": "connection_failed", "detail": "x"}])
    assert not capture.RECORDER.active and "privacy" in w.fired[0]["skipped"][0]


def test_settings_route(ctx):
    admin = client(create_app(ctx), "admin")
    d = admin.get("/api/captures/triggers").json()
    assert "connection_failed" in d["events"] and d["sensors"][0]["id"] == "local" and not d["settings"]["enabled"]
    assert admin.put("/api/captures/triggers", json={"enabled": True, "events": [], "sensors": ["local"], "radios": ["wifi"]}).status_code == 400
    assert admin.put("/api/captures/triggers", json={"enabled": True, "events": ["roam_slow", "rm -rf"], "sensors": ["local", "attic"],
                                                     "radios": ["wifi"], "pre": 10, "post": 30, "cooldown": 120}).status_code == 200
    assert ctx.settings.get("triggers")["events"] == ["roam_slow"] and ctx.settings.get("triggers")["sensors"] == ["local"]
    assert admin.put("/api/captures/triggers", json={"pre": 500}).status_code == 422
    assert client(create_app(ctx), "view").get("/api/captures/triggers").status_code == 403
