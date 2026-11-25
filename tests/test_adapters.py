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
    adapters.run_commands = lambda cmds, fetch=None, record=None: got.append(cmds)
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


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def watchdog(after=180):
    clock, calls = Clock(), []
    w = adapters.Watchdog(after, clock=clock, resetter=lambda name, usb: (calls.append((name, usb)), ["USB device 1-1 reset", "wlan9 up"])[1])
    return w, clock, calls


def run_for(w, clock, seconds, step=5):
    end = clock.t + seconds
    while clock.t < end:
        clock.t += step
        w.check()


def test_an_adapter_in_error_for_three_minutes_is_reset_with_its_usb_device():
    status.SENSORS.clear()
    status.register("wifi:wlan9", type="wifi", iface="wlan9")
    status.update("wifi:wlan9", state="error", error="Network is down")
    w, clock, calls = watchdog()
    w.check()
    run_for(w, clock, 170)
    assert calls == []
    run_for(w, clock, 15)
    assert calls == [("wifi:wlan9", True)]
    note = status.SENSORS["wifi:wlan9"]["note"]
    assert note.startswith("Automatic reset at ") and "after 3 min of errors" in note and "USB device 1-1 reset" in note
    run_for(w, clock, 300)                     # still broken: the next try waits twice as long
    assert len(calls) == 1
    run_for(w, clock, 70)
    assert len(calls) == 2 and status.SENSORS["wifi:wlan9"]["auto_resets"] == 2


def test_short_errors_and_flapping_count_but_a_minute_of_working_starts_over():
    status.SENSORS.clear()
    status.register("bt:hci0", type="bt", iface="hci0")
    w, clock, calls = watchdog()
    for _ in range(12):                        # a loop that fails at once: 10 s error, 5 s "scanning", for 3 minutes
        status.update("bt:hci0", state="error")
        run_for(w, clock, 10)
        status.update("bt:hci0", state="scanning")
        run_for(w, clock, 5)
    status.update("bt:hci0", state="error")
    run_for(w, clock, 10)
    assert calls == [("bt:hci0", True)]
    status.update("bt:hci0", state="scanning")
    run_for(w, clock, 65)
    assert "bt:hci0" not in w.track
    status.update("bt:hci0", state="error")
    run_for(w, clock, 120)
    assert len(calls) == 1                     # a fresh error waits the full 3 minutes again


def test_the_watchdog_leaves_remote_entries_and_unknown_sticks_alone():
    status.SENSORS.clear()
    status.replace_remote("pi", [{"name": "wifi:wlan1", "state": "error"}], time.time())
    status.register("zigbee:ttyACM7", type="zigbee")
    status.update("zigbee:ttyACM7", state="error")
    status.register("eth:eth0", type="eth")
    status.update("eth:eth0", state="error")
    w, clock, calls = watchdog()
    run_for(w, clock, 400)
    assert calls == []
    assert adapters.Watchdog(0).after == 0     # AUTO_RESET_AFTER=0 switches it off (start() does nothing)


def test_a_failing_reset_is_noted_and_tried_again_later():
    status.SENSORS.clear()
    status.register("wifi:wlan9", type="wifi", iface="wlan9")
    status.update("wifi:wlan9", state="error")
    clock = Clock()

    def broken(name, usb):
        raise OSError("ip: not found")
    w = adapters.Watchdog(180, clock=clock, resetter=broken)
    w.check()
    run_for(w, clock, 185)
    assert "failed: ip: not found" in status.SENSORS["wifi:wlan9"]["note"] and w.track["wifi:wlan9"]["tries"] == 1
