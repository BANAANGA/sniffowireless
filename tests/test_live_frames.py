"""Live frames on the Frames page (release 33.3): this server's radios or a remote sensor's, as they are heard, for a minute
unless chosen otherwise and an hour at most, stopping by themselves when the page stops asking; and deleting all recordings."""
import json
import os
import time

import pytest
from fastapi.testclient import TestClient
from test_hardening import client, ctx  # noqa: F401  (ctx is a fixture)

from sniffowireless import capture, sample_frames as sf
from sniffowireless.config import Config
from sniffowireless.sensors import Forwarder
from sniffowireless.web import create_app


@pytest.fixture
def live(ctx):
    capture.LIVE.close()
    capture.LIVE_CAPTURES.clear()
    app = create_app(ctx)
    yield ctx, app, client(app, "admin")
    capture.LIVE.close()
    capture.LIVE_CAPTURES.clear()


def frames(admin, source="local", after=0, f=""):
    r = admin.get(f"/api/frames/live?source={source}&after={after}&filter={f}")
    assert r.status_code == 200, r.text
    return r.json()


def test_this_servers_radios_live(live):
    ctx, app, admin = live
    assert not capture.tapping()
    assert admin.post("/api/frames/live", json={"radios": ["wifi", "bt"]}).status_code == 200
    assert capture.tapping()   # the radios hand their frames over now
    cap = capture.LIVE_CAPTURES["local"]
    assert round(cap.until - cap.started) == capture.LIVE_DEFAULT == 60
    capture.RECORDER.record("wifi", "wifi:wlan0mon", sf.beacon(), tuned=2437)   # what wifi.py does for every frame
    capture.RECORDER.record("bt", "bt:hci0", sf.le_adv())
    capture.RECORDER.record("zigbee", "zigbee:ttyUSB0", sf.zb_ack(), channel=15)   # not chosen
    d = frames(admin)
    assert d["open"] and d["total"] == 2 and d["last"] == 2 and d["radios"] == ["wifi", "bt"]
    assert [(x["no"], x["proto"]) for x in d["items"]] == [(1, "802.11"), (2, "LE ADV")]
    assert frames(admin, after=1)["items"][0]["no"] == 2
    assert [x["no"] for x in frames(admin, f="ble")["items"]] == [2]
    assert admin.get("/api/frames/live?filter=rssi%20%3E").status_code == 400
    one = admin.get("/api/frames/live/1?source=local").json()
    assert one["tree"][0]["n"] == "Frame 1" and "Beacon" in one["summary"]["info"] and bytes.fromhex(one["hex"])
    assert admin.get("/api/frames/live/99?source=local").status_code == 404


def test_data_frames_are_cut_to_their_headers_live_too(live):
    ctx, app, admin = live
    admin.post("/api/frames/live", json={"radios": ["wifi"]})
    capture.RECORDER.record("wifi", "wifi:wlan0mon", sf.qos_data() + b"secret payload" * 10)
    hexed = admin.get("/api/frames/live/1?source=local").json()["hex"]
    assert b"secret" not in bytes.fromhex(hexed) and len(bytes.fromhex(hexed)) == len(sf.qos_data())


def test_how_long_it_runs(live):
    ctx, app, admin = live
    assert admin.post("/api/frames/live", json={"radios": ["wifi"], "seconds": 3601}).status_code == 422   # an hour at most
    assert admin.post("/api/frames/live", json={"radios": ["wifi"], "seconds": 5}).status_code == 422
    assert admin.post("/api/frames/live", json={"radios": ["wifi"], "seconds": 3600}).status_code == 200
    assert admin.post("/api/frames/live", json={"radios": []}).status_code == 400
    cap = capture.LIVE_CAPTURES["local"]
    cap.until = time.time() - 1   # the time is up
    assert not frames(admin)["open"] and not capture.tapping()


def test_it_stops_when_the_page_stops_asking(live):
    ctx, app, admin = live
    admin.post("/api/frames/live", json={"radios": ["bt"], "seconds": 600})
    cap = capture.LIVE_CAPTURES["local"]
    assert capture.LIVE.until - time.time() <= capture.LIVE_IDLE + 1   # the radios are only asked for as long as the page keeps asking
    cap.seen -= capture.LIVE_IDLE + 1
    capture.LIVE.until = time.time() - 1
    capture.RECORDER.record("bt", "bt:hci0", sf.le_adv())
    d = frames(admin)
    assert not d["open"] and d["total"] == 0 and not capture.tapping()


def test_stop_keeps_what_was_heard_and_it_can_be_saved(live):
    ctx, app, admin = live
    admin.post("/api/frames/live", json={"radios": ["wifi", "bt", "zigbee", "lora"]})
    for radio, src, raw, meta in sf.samples():
        capture.RECORDER.record(radio, src, raw, **meta)
    assert admin.delete("/api/frames/live?source=local").status_code == 200
    capture.RECORDER.record("bt", "bt:hci0", sf.le_adv())   # after the stop: not kept
    d = frames(admin)
    assert not d["open"] and d["total"] == len(sf.samples())
    r = admin.post("/api/frames/live/save?source=local").json()
    assert r["frames"] == len(sf.samples()) and r["name"] in [f["name"] for f in admin.get("/api/captures").json()["files"]]
    assert admin.get(f"/api/captures/{r['name']}/frames").json()["total"] == len(sf.samples())


def test_a_remote_sensor_live(live):
    ctx, app, admin = live
    tid, token = ctx.auth.create_token("sensor office", "sensor", "office")
    ctx.execute("INSERT INTO sensors(id, name, token_id, created, last_seen) VALUES('office', 'Office', ?, 0, ?)", (tid, time.time()))
    sensor = TestClient(app, base_url="http://sniffowireless.test", headers={"authorization": "Bearer " + token})

    def batch(**extra):
        return sensor.post("/api/ingest", content=json.dumps({"sent_at": time.time(), "obs": [], **extra})).json()
    assert "live" not in batch()
    assert admin.post("/api/frames/live", json={"source": "office", "radios": ["wifi"]}).status_code == 200
    assert not capture.tapping()   # this server's own radios are not asked for
    req = batch()["live"]
    assert req["radios"] == ["wifi"] and 0 < req["seconds"] <= capture.LIVE_REMOTE_HOLD
    sent = [{"ts": time.time(), "radio": "wifi", "src": "wifi:wlan1", "raw": sf.beacon().hex(), "tuned": 2437, "evil": "x"},
            {"radio": "sdr", "raw": "00"}, {"radio": "wifi", "raw": "zz"}, "nonsense"]
    batch(frames=sent, frames_dropped=12)
    d = frames(admin, "office")
    assert d["total"] == 1 and d["dropped"] == 12 and d["items"][0]["sensor"] == "wifi:wlan1"
    assert admin.get("/api/frames/live/1?source=office").status_code == 200
    capture.LIVE_CAPTURES["office"].until = time.time() - 1
    assert "live" not in batch()   # time is up: the sensor is no longer asked
    assert admin.post("/api/frames/live", json={"source": "attic", "radios": ["wifi"]}).status_code == 404


def test_the_sensor_side(tmp_path):
    capture.LIVE.close()
    f = Forwarder.__new__(Forwarder)
    f.cfg = Config(data_dir=str(tmp_path))
    from collections import deque
    f.live, f.live_dropped = deque(maxlen=3), 0
    assert f._live_batch() == {}
    f._live_config({"radios": ["bt", "sdr"], "seconds": 999})
    assert capture.LIVE.active and capture.LIVE.radios == {"bt"} and capture.LIVE.until - time.time() <= capture.LIVE_REMOTE_HOLD
    for _ in range(5):
        capture.RECORDER.record("bt", "bt:hci0", sf.le_adv())
    capture.RECORDER.record("wifi", "wifi:wlan0", sf.beacon())   # not asked for
    b = f._live_batch()
    assert len(b["frames"]) == 3 and b["frames_dropped"] == 2 and b["frames"][0]["raw"] == sf.le_adv().hex()
    json.dumps(b)   # it goes into the batch as it is
    f._live_config(None)   # the server stopped asking
    assert not capture.LIVE.active and not f.live


def test_no_live_capture_while_addresses_are_private(live):
    ctx, app, admin = live
    p = ctx.settings.get("privacy")
    ctx.settings.set("privacy", {**p, "macs": True})
    assert admin.post("/api/frames/live", json={"radios": ["wifi"]}).status_code == 409


def test_only_admins(live):
    ctx, app, admin = live
    viewer = client(app, "view")
    assert viewer.post("/api/frames/live", json={"radios": ["wifi"]}).status_code == 403
    assert viewer.get("/api/frames/live").status_code == 403
    assert TestClient(app, base_url="http://sniffowireless.test").get("/api/frames/live").status_code == 401


def test_delete_all_recordings(live):
    ctx, app, admin = live
    folder = capture.directory(ctx.cfg)
    for i in range(3):
        sf.write_recording(os.path.join(folder, f"capture-20261116-12000{i}.jsonl.gz"), count=5)
    capture.RECORDER.start(folder, 60, ["wifi"])   # the one being made is left alone
    try:
        assert client(app, "view").delete("/api/captures").status_code == 403
        assert admin.delete("/api/captures").json() == {"deleted": 3}
        assert os.listdir(folder) == [os.path.basename(capture.RECORDER.path)]
    finally:
        capture.RECORDER.stop()


def test_the_demo_makes_up_live_frames(tmp_path):
    from sniffowireless.demo import fake_live
    cap = capture.LiveCapture("office", ["bt", "lora"], 60)
    capture.LIVE_CAPTURES["office"] = cap
    try:
        fake_live(cap)
        for _ in range(100):
            if cap.seq:
                break
            time.sleep(0.02)
        assert cap.seq and {e[1]["radio"] for e in cap.items} <= {"bt", "lora"}
    finally:
        capture.LIVE_CAPTURES.clear()
