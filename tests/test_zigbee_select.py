"""Choosing Zigbee channels, hop / scan time and passive listening from the web UI, on this server and on remote sensors."""
import threading
import time

import pytest

from sniffowireless import status
from sniffowireless.config import Config
from sniffowireless.zigbee import ZigbeeControl, ZigbeeSensor, clean_override, parse_channels

from tests.test_lora import ctx  # noqa: F401
from tests.test_lora_select import admin_client
from tests.test_zigbee import SimEzsp


def test_parse_channels():
    assert parse_channels("15, 20-22,15") == [15, 20, 21, 22]
    for bad in ("", "10", "27", "abc", "22-20", "11-30"):
        with pytest.raises(ValueError):
            parse_channels(bad)


def test_clean_override():
    o = clean_override({"channels": "20-22,15", "hop_interval": "1.5", "scan_interval": 120, "sniff": False, "junk": 1})
    assert o == {"channels": "20,21,22,15", "hop_interval": 1.5, "scan_interval": 120, "sniff": False}
    assert clean_override({}) == {"channels": None, "hop_interval": None, "scan_interval": None, "sniff": None}
    assert clean_override({"channels": "", "hop_interval": ""})["channels"] is None
    for bad in ({"channels": "40"}, {"hop_interval": 0.01}, {"hop_interval": "x"}, {"scan_interval": 5}, {"scan_interval": 10 ** 7}, {"channels": 15}):
        with pytest.raises(ValueError):
            clean_override(bad)


def test_control_starts_from_the_environment_and_takes_an_override():
    cfg = Config(zigbee_channels=[15], zigbee_hop_interval=2.0, zigbee_scan_interval=600, zigbee_sniff=True)
    c = ZigbeeControl(cfg)
    assert c.effective() == {"channels": [15], "hop_interval": 2.0, "scan_interval": 600, "sniff": True}
    c.apply({"channels": "20-21", "sniff": False}, 3)
    assert c.rev == 3 and c.effective() == {"channels": [20, 21], "hop_interval": 2.0, "scan_interval": 600, "sniff": False}
    c.apply({}, 4)  # all empty: back on the environment
    assert c.effective()["channels"] == [15] and c.effective()["sniff"] is True
    with pytest.raises(ValueError):
        c.apply({"channels": "99"}, 5)
    assert c.rev == 4
    # a remote sensor ignores a bad or a repeated revision
    c.apply_remote({"rev": 6, "channels": "99"})
    assert c.rev == 4
    c.apply_remote({"rev": 6, "channels": "99"})  # not tried again
    c.apply_remote({"rev": 7, "channels": "25"})
    assert c.rev == 7 and c.effective()["channels"] == [25]
    c.apply_remote("nonsense")
    c.apply_remote({"rev": 7, "channels": "11"})
    assert c.effective()["channels"] == [25]


def test_running_stick_switches_channels_when_the_setting_changes():
    cfg = Config(zigbee_channels=[15], zigbee_hop_interval=0.1, zigbee_scan_interval=600)
    control = ZigbeeControl(cfg)
    stop, sink = threading.Event(), []

    class Sink:
        put = staticmethod(sink.append)

    link = SimEzsp()
    sensor = ZigbeeSensor("/dev/ttyZSEL1", cfg, Sink, link_factory=lambda _: link, control=control)
    sensor.stop = stop
    t = threading.Thread(target=sensor.run, args=(link,))
    t.start()

    def channel():
        return next((s.get("channel") for s in status.snapshot() if s["name"] == "zigbee:ttyZSEL1"), None)

    def wait(want, secs=10):
        end = time.monotonic() + secs
        while time.monotonic() < end and channel() != want:
            time.sleep(0.05)
        return channel() == want

    try:
        assert wait("15")
        st = next(s for s in status.snapshot() if s["name"] == "zigbee:ttyZSEL1")
        assert st["zb_channels"] == [15] and st["zb_rev"] == 0
        control.apply({"channels": "20"}, 1)
        assert wait("20")
        st = next(s for s in status.snapshot() if s["name"] == "zigbee:ttyZSEL1")
        assert st["zb_channels"] == [20] and st["zb_rev"] == 1
        control.apply({"sniff": False}, 2)  # scans only: no channel is tuned any more
        assert wait(None)
    finally:
        stop.set()
        t.join(8)
        status.SENSORS.pop("zigbee:ttyZSEL1", None)
    assert not t.is_alive()


def test_zigbee_settings_api(ctx):
    from fastapi.testclient import TestClient
    from sniffowireless.web import create_app
    from sniffowireless.zigbee import attach
    attach(ctx)
    c = admin_client(ctx)
    ctx.execute("INSERT INTO sensors(id, name, created, last_seen) VALUES('garden', 'Garden', ?, ?)", (time.time(), time.time()))
    d = c.get("/api/zigbee-settings").json()
    assert [t["id"] for t in d["targets"]] == ["local", "garden"] and d["defaults"]["sniff"] is True
    r = c.put("/api/zigbee-settings/garden", json={"channels": "15,20-25", "hop_interval": 3, "scan_interval": 300, "sniff": True}).json()
    assert r["config"] == {"rev": 1, "channels": "15,20,21,22,23,24,25", "hop_interval": 3.0, "scan_interval": 300, "sniff": True}
    assert c.put("/api/zigbee-settings/garden", json={"channels": "15"}).json()["config"]["rev"] == 2
    assert c.put("/api/zigbee-settings/garden", json={"channels": "5"}).status_code == 400
    assert c.put("/api/zigbee-settings/ghost", json={"channels": "15"}).status_code == 404
    c.put("/api/zigbee-settings/local", json={"channels": "25"})
    assert ctx.zigbee_control.effective()["channels"] == [25] and ctx.zigbee_control.rev == 1
    assert c.delete("/api/zigbee-settings/local").status_code == 200
    assert ctx.zigbee_control.effective()["channels"] == list(ctx.cfg.zigbee_channels)
    v = TestClient(create_app(ctx), base_url="http://sniffowireless.test")
    assert v.get("/api/zigbee-settings").status_code == 401
    assert v.post("/api/auth/login", json={"username": "view", "password": "correct-horse-battery"}).status_code == 200
    assert v.get("/api/zigbee-settings").status_code == 403
    assert v.put("/api/zigbee-settings/local", headers={"x-sniffowireless": "1"}, json={}).status_code == 403


def test_ingest_reply_carries_the_sensors_zigbee_settings(ctx):
    from fastapi.testclient import TestClient
    from sniffowireless.web import create_app
    c = admin_client(ctx)
    tok = c.post("/api/sensors", json={"name": "Shed", "room": None}).json()
    c.put(f"/api/zigbee-settings/{tok['id']}", json={"channels": "25", "sniff": False})
    s = TestClient(create_app(ctx), base_url="http://sniffowireless.test")
    h = {"Authorization": f"Bearer {tok['token']}", "x-sniffowireless": "1"}
    reply = s.post("/api/ingest", headers=h, json={"observations": [], "status": []}).json()
    assert reply["zigbee_config"] == {"rev": 1, "channels": "25", "hop_interval": None, "scan_interval": None, "sniff": False}
    # the sensor reports the revision and channels it runs
    s.post("/api/ingest", headers=h, json={"observations": [], "status": [{"name": "zigbee:ttyUSB0", "type": "zigbee", "iface": "/dev/ttyUSB0",
                                                                           "zb_rev": 1, "zb_channels": [25, 99, "x"]}]})
    t = next(t for t in c.get("/api/zigbee-settings").json()["targets"] if t["id"] == tok["id"])
    assert t["sticks"] and t["sticks"][0]["zb_rev"] == 1 and t["sticks"][0]["zb_channels"] == [25] and t["applied"] is True
    assert c.delete(f"/api/sensors/{tok['id']}").status_code == 200
    assert tok["id"] not in ctx.settings.get("zigbee")["sensors"]
