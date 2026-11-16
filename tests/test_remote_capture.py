"""Frame recording on a remote sensor (release 33.2): the server asks with its reply to a batch, the sensor records its own radios,
reports how it goes with its batches and uploads the file, which is checked, rewritten and listed with the sensor's name."""
import gzip
import io
import json
import os
import threading
import time

import pytest
from fastapi.testclient import TestClient
from test_hardening import client, ctx  # noqa: F401  (ctx is a fixture)

from sniffowireless import adapters, capture, sample_frames as sf
from sniffowireless.web import create_app


@pytest.fixture
def setup(ctx, tmp_path):
    tid, token = ctx.auth.create_token("sensor office", "sensor", "office")
    ctx.execute("INSERT INTO sensors(id, name, token_id, created, last_seen) VALUES('office', 'Office', ?, 0, ?)", (tid, time.time()))
    capture.REMOTE.clear()
    capture.SENSOR_JOB.clear()
    adapters.PENDING.clear()
    app = create_app(ctx)
    sensor = TestClient(app, base_url="http://sniffowireless.test", headers={"authorization": "Bearer " + token})
    yield ctx, app, client(app, "admin"), sensor, str(tmp_path / "sensor-captures")
    if capture.RECORDER.active:
        capture.RECORDER.stop()


def batch(sensor, **extra):
    r = sensor.post("/api/ingest", content=json.dumps({"sent_at": time.time(), "obs": [], **extra}))
    assert r.status_code == 200
    return r.json()


def test_a_remote_sensor_records_and_uploads(setup):
    ctx, app, admin, sensor, sensor_dir = setup
    r = admin.post("/api/captures", json={"sensor": "office", "seconds": 5, "radios": ["wifi", "bt"]})
    assert r.status_code == 200 and r.json()["queued"]
    assert admin.post("/api/captures", json={"sensor": "office", "seconds": 5}).status_code == 409   # one at a time
    listing = admin.get("/api/captures").json()
    assert listing["remote"][0]["state"] == "requested" and listing["sensors"] == [{"id": "office", "name": "Office", "online": True}]

    cmd = next(c for c in batch(sensor)["commands"] if c["action"] == "capture")
    assert cmd["radios"] == ["wifi", "bt"] and cmd["seconds"] == 5

    def upload(path, rid):  # what the sensor's Forwarder does, through the test client
        with open(path, "rb") as f:
            res = sensor.post(f"/api/ingest/capture?id={rid}", content=f.read(), headers={"content-type": "application/gzip"})
        assert res.status_code == 200, res.text
    capture.record_for_server({**cmd, "seconds": 1}, sensor_dir, upload)
    for _ in range(50):
        if capture.RECORDER.active:
            break
        time.sleep(0.02)
    capture.RECORDER.record("wifi", "wifi:wlan0mon", sf.beacon(), tuned=2437)
    capture.RECORDER.record("bt", "bt:hci0", sf.le_adv())
    capture.RECORDER.record("zigbee", "zigbee:ttyUSB0", sf.zb_ack(), channel=15)   # not asked for: not recorded
    batch(sensor, capture=dict(capture.SENSOR_JOB))
    assert admin.get("/api/captures").json()["remote"][0]["state"] in ("recording", "uploading", "done")
    for _ in range(100):
        if not capture.SENSOR_JOB:
            break
        time.sleep(0.05)
    assert not capture.SENSOR_JOB and os.listdir(sensor_dir) == []   # delivered, and gone from the sensor

    listing = admin.get("/api/captures").json()
    job = listing["remote"][0]
    assert job["state"] == "done" and job["frames"] == 2 and job["file"].endswith("-office.jsonl.gz")
    f = next(x for x in listing["files"] if x["name"] == job["file"])
    assert f["sensor"] == "office" and f["sensor_name"] == "Office"
    frames = admin.get(f"/api/captures/{job['file']}/frames").json()
    assert [x["proto"] for x in frames["items"]] == ["802.11", "LE ADV"]
    assert admin.get(f"/api/captures/{job['file']}/frames/1").json()["tree"][0]["v"].endswith("wifi:wlan0mon")
    assert sensor.post(f"/api/ingest/capture?id={cmd['id']}", content=b"x").status_code == 409   # only once


def gz(lines):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as f:
        for line in lines:
            f.write((line if isinstance(line, str) else json.dumps(line)).encode() + b"\n")
    return buf.getvalue()


def ask(admin, sensor):
    assert admin.post("/api/captures", json={"sensor": "office", "seconds": 5}).status_code == 200
    return next(c for c in batch(sensor)["commands"] if c["action"] == "capture")["id"]


def test_an_upload_is_checked_and_rewritten(setup):
    ctx, app, admin, sensor, _ = setup
    rid = ask(admin, sensor)
    data = gz([{"ts": 5.5, "radio": "wifi", "src": "wifi:wlan0\x1b[31m", "raw": sf.beacon().hex(), "tuned": 2437, "evil": "<script>",
                "rssi": "loud"}])
    assert sensor.post(f"/api/ingest/capture?id={rid}", content=data).status_code == 200
    name = capture.REMOTE["office"]["file"]
    rec = json.loads(gzip.open(os.path.join(capture.directory(ctx.cfg), name), "rt").readline())
    assert rec == {"ts": 5.5, "radio": "wifi", "src": "wifi:wlan0[31m", "raw": sf.beacon().hex(), "tuned": 2437}


@pytest.mark.parametrize("data", [b"not gzip", gz(["not json"]), gz([{"radio": "sdr", "raw": "00"}]), gz([{"radio": "wifi", "raw": "zz"}]),
                                  gz([{"radio": "wifi", "raw": "00" * 5000}])])
def test_a_bad_upload_fails_the_recording(setup, data):
    ctx, app, admin, sensor, _ = setup
    rid = ask(admin, sensor)
    assert sensor.post(f"/api/ingest/capture?id={rid}", content=data).status_code == 400
    job = admin.get("/api/captures").json()["remote"][0]
    assert job["state"] == "failed" and "could not be used" in job["error"]
    assert not [n for n in os.listdir(capture.directory(ctx.cfg)) if n.endswith(".part")]


def test_uploads_need_the_sensor_token_and_a_request(setup):
    ctx, app, admin, sensor, _ = setup
    assert sensor.post("/api/ingest/capture?id=0123456789abcdef", content=gz([])).status_code == 409   # nothing was asked
    rid = ask(admin, sensor)
    assert sensor.post("/api/ingest/capture?id=ffffffffffffffff", content=gz([])).status_code == 409   # not this one
    anon = TestClient(app, base_url="http://sniffowireless.test")
    assert anon.post(f"/api/ingest/capture?id={rid}", content=gz([])).status_code == 401
    assert admin.post(f"/api/ingest/capture?id={rid}", content=gz([])).status_code == 401   # an admin session is not a sensor
    assert sensor.post(f"/api/ingest/capture?id={rid}", content=gz([])).status_code == 200


def test_sensors_that_cannot_record(setup):
    ctx, app, admin, sensor, _ = setup
    assert admin.post("/api/captures", json={"sensor": "attic", "seconds": 5}).status_code == 404
    ctx.execute("UPDATE sensors SET last_seen=? WHERE id='office'", (time.time() - 3600,))
    r = admin.post("/api/captures", json={"sensor": "office", "seconds": 5})
    assert r.status_code == 409 and "offline" in r.json()["detail"]


def test_a_sensor_that_never_starts_is_given_up_on(setup):
    ctx, app, admin, sensor, _ = setup
    ask(admin, sensor)
    capture.REMOTE["office"]["requested"] -= capture.REMOTE_START_WAIT + 1
    job = admin.get("/api/captures").json()["remote"][0]
    assert job["state"] == "failed" and "33.2" in job["error"]
    assert admin.post("/api/captures", json={"sensor": "office", "seconds": 5}).status_code == 200   # and may be asked again


def test_a_failure_on_the_sensor_is_shown(setup):
    ctx, app, admin, sensor, _ = setup
    rid = ask(admin, sensor)
    batch(sensor, capture={"id": rid, "state": "failed", "error": "A recording is already running"})
    job = admin.get("/api/captures").json()["remote"][0]
    assert job["state"] == "failed" and job["error"] == "A recording is already running"


def test_the_sensor_carries_out_the_command(monkeypatch):
    got = threading.Event()
    adapters.run_commands([{"action": "capture", "name": "capture", "id": "0123456789abcdef", "seconds": 5}], record=lambda c: got.set())
    assert got.wait(2)
