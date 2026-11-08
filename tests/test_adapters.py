import threading
import time

import pytest
from fastapi.testclient import TestClient

from sniffowireless import adapters, sanitize, sensors, status
from sniffowireless.auth import hash_password
from sniffowireless.config import Config
from sniffowireless.lora import LoraSensor
from sniffowireless.main import build
from sniffowireless.web import create_app

PW = "correct-horse-battery"


@pytest.fixture
def ctx(tmp_path):
    status.SENSORS.clear()
    adapters.PENDING.clear()
    c = build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))
    with c.wdb() as w:
        for name, role in (("admin", "admin"), ("view", "viewer")):
            w.execute("INSERT INTO users(username, pw_hash, role, created) VALUES(?, ?, ?, 0)", (name, hash_password(PW, iterations=1000), role))
    return c


def client(ctx, user="admin"):
    c = TestClient(create_app(ctx), base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    assert c.post("/api/auth/login", json={"username": user, "password": PW}).status_code == 200
    return c


def test_wifi_reset_brings_the_interface_down_and_up(ctx, monkeypatch):
    import sniffowireless.wifi as wifi
    calls = []
    monkeypatch.setattr(wifi, "run_cmd", lambda *a: (calls.append(a), (0, ""))[1])
    status.register("wifi:wlan9", type="wifi", iface="wlan9", mon="wlan9mon")
    r = client(ctx).post("/api/adapters/reset", json={"name": "wifi:wlan9"})
    assert r.status_code == 200 and r.json()["done"] and r.json()["steps"][-1].startswith("monitor mode")
    assert set(calls[:2]) == {("ip", "link", "set", "wlan9", "down"), ("ip", "link", "set", "wlan9mon", "down")} and calls[-1] == ("ip", "link", "set", "wlan9", "up")
    assert status.SENSORS["wifi:wlan9"]["note"].startswith("Reset at ")


def test_wifi_reset_can_reset_the_usb_device_too(ctx, monkeypatch):
    import sniffowireless.wifi as wifi
    monkeypatch.setattr(wifi, "run_cmd", lambda *a: (0, ""))
    seen = []
    monkeypatch.setattr(adapters, "usb_reset", lambda path: (seen.append(path), "USB device 1-1.2 reset")[1])
    monkeypatch.setattr(adapters, "_wait_for", lambda path, s: True)
    status.register("wifi:wlan9", type="wifi", iface="wlan9")
    steps = client(ctx).post("/api/adapters/reset", json={"name": "wifi:wlan9", "usb": True}).json()["steps"]
    assert seen == ["/sys/class/net/wlan9/device"] and "USB device 1-1.2 reset" in steps


def test_bluetooth_reset_uses_the_hci_ioctls(ctx, monkeypatch):
    done = []

    class FakeSock:
        def fileno(self):
            return 3

        def close(self):
            done.append("close")
    import types
    monkeypatch.setattr(adapters, "socket", types.SimpleNamespace(socket=lambda *a: FakeSock(), AF_BLUETOOTH=31, SOCK_RAW=3, BTPROTO_HCI=1))
    monkeypatch.setattr(adapters, "fcntl", types.SimpleNamespace(ioctl=lambda fd, req, arg: done.append((req, arg))))
    status.register("bt:hci1", type="bluetooth", iface="hci1")
    steps = client(ctx).post("/api/adapters/reset", json={"name": "bt:hci1"}).json()["steps"]
    assert done == [(adapters.HCIDEVDOWN, 1), (adapters.HCIDEVRESET, 1), (adapters.HCIDEVUP, 1), "close"] and steps == ["hci1 down", "hci1 reset", "hci1 up"]


def test_serial_sticks_are_reconnected_at_once(ctx):
    closed = []

    class Link:
        def close(self):
            closed.append(1)
    s = LoraSensor("/dev/ttyUSB9", Config(), None)
    s.stop = threading.Event()
    s.link = Link()
    r = client(ctx).post("/api/adapters/reset", json={"name": "lora:ttyUSB9"})
    assert r.status_code == 200 and closed == [1] and s.reset_requested.is_set()
    t0 = time.monotonic()
    s._retry_wait()                                    # would take 30 s without the request
    assert time.monotonic() - t0 < 2 and not s.reset_requested.is_set()


def test_only_known_interfaces_can_be_reset_and_only_by_admins(ctx):
    a, v = client(ctx), client(ctx, "view")
    assert a.post("/api/adapters/reset", json={"name": "wifi:wlan0"}).status_code == 400            # not one of this server's interfaces
    assert a.post("/api/adapters/reset", json={"name": "wifi:wlan0; rm -rf /"}).status_code == 400
    assert a.post("/api/adapters/reset", json={"name": "eth:eth0"}).status_code == 400              # no reset for Ethernet
    status.register("wifi:wlan9", type="wifi", iface="wlan9")
    assert v.post("/api/adapters/reset", json={"name": "wifi:wlan9"}).status_code == 403
    assert a.post("/api/adapters/reset", json={"sensor": "nobody", "name": "wifi:wlan9"}).status_code == 404
    with pytest.raises(ValueError):
        adapters.reset("wifi:wlan9/../x")


def test_a_remote_sensor_gets_the_request_with_its_next_upload(ctx):
    a = client(ctx)
    status.replace_remote("garage", [{"name": "wifi:wlan1", "type": "wifi", "iface": "wlan1", "state": "error"}], time.time())
    r = a.post("/api/adapters/reset", json={"sensor": "garage", "name": "wifi:wlan1", "usb": True})
    assert r.json() == {"done": False, "queued": True}
    assert adapters.take("garage") == [{"action": "reset", "name": "wifi:wlan1", "usb": True}]
    assert adapters.take("garage") == []                                  # handed over once
    # and the sensor side runs what it is given
    got = []
    adapters.queue("garage", "wifi:wlan1", False)
    assert adapters.take("garage")
    f = sensors.Forwarder.__new__(sensors.Forwarder)
    f.on_channel_config = None
    orig = adapters.run_commands
    adapters.run_commands = lambda cmds: got.append(cmds)
    try:
        f._handle_reply(b'{"accepted": 1, "commands": [{"action": "reset", "name": "wifi:wlan1", "usb": false}]}')
        f._handle_reply(b'{"accepted": 1}')
    finally:
        adapters.run_commands = orig
    assert got == [[{"action": "reset", "name": "wifi:wlan1", "usb": False}]]


def test_a_sensor_ignores_requests_for_what_it_does_not_have(ctx):
    adapters.run_commands([{"action": "format", "name": "wifi:wlan9"}, {"action": "reset", "name": "../../etc"}, {"action": "reset", "name": "wifi:nonexistent", "usb": True},
                           "junk", None])
    time.sleep(0.3)
    assert "wifi:nonexistent" not in status.SENSORS


def test_the_status_a_remote_sensor_reports_keeps_the_lora_fields():
    out = sanitize.remote_status({"name": "lora:ttyUSB0", "type": "lora", "state": "listening", "fw_version": 2, "crc_errors": 3, "profile": "meshcore-eu868",
                                  "note": "Reset at 12:00: ok", "evil": "x", "firmware": "lora-sniffer"})
    assert out["fw_version"] == 2 and out["crc_errors"] == 3 and out["profile"] == "meshcore-eu868" and out["note"].startswith("Reset at") and "evil" not in out
