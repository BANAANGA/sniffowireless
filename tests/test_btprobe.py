"""Reading a device's exact Bluetooth version by connecting to it (on an admin's request), the model lookup and the LE Audio evidence."""
import socket
import struct
import threading
import time

import pytest

from sniffowireless import adapters, bluetooth, btprobe, status
from sniffowireless.bluetooth import BluetoothSensor
from sniffowireless.btversion import MODEL_VERSIONS, derive
from sniffowireless.config import Config

from tests.test_bluetooth6 import Store
from tests.test_btversion import bt, extra_of
from tests.test_lora import ctx  # noqa: F401
from tests.test_lora_select import admin_client

MAC = "c9:22:bb:02:00:02"
HANDLE = 0x41


# ------------------------------------------------------------------ evidence: LE Audio services and the model lookup
def test_le_audio_services_prove_5_2():
    assert derive("ble", {"uuids": ["180f", "184e"]}) == ("5.2+", "LE Audio services")
    assert derive("ble", {"uuids": ["180f"]})[0] == "4.0+"
    assert derive("ble", {"uuids": ["1850"], "encrypted_ad": True})[0] == "5.4+"


def test_model_specifications_are_used_when_credible():
    assert derive("ble", {}, "AirPods Pro (2nd gen)") == ("5.3", "manufacturer's specification for the AirPods Pro (2nd gen)")
    assert derive("ble", {"ext_adv": True}, "AirPods (2nd gen)")[0] == "5.0"
    # a spec lower than what the device does is not credible: the evidence wins; a reported version beats both
    assert derive("ble", {"encrypted_ad": True}, "AirPods (2nd gen)") == ("5.4+", "encrypted advertising data")
    assert derive("ble", {"bt_version": "5.2"}, "AirPods Pro (2nd gen)") == ("5.2", "reported by the device")
    assert derive("ble", {}, "Some unknown model")[0] == "4.0+"
    assert all(v[0][0] in "45" and v[1] for v in MODEL_VERSIONS.values())


def test_the_store_applies_the_model_after_identification(ctx):  # noqa: F811
    m = "4c:11:aa:02:00:01"
    ctx.store.process({"t": "bt", "kind": "ble", "ts": time.time(), "mac": m, "rssi": -60, "name": None, "randomized": False,
                       "extra": {"connectable": True}, "fp": {"ble": {"apple_model": 0x2014}}})
    ctx.store.flush()
    assert extra_of(ctx, m)["bt_ver"] == "5.3" and "AirPods Pro (2nd gen)" in extra_of(ctx, m)["bt_basis"]


# ------------------------------------------------------------------ the HCI exchange, against a simulated controller
class Controller(threading.Thread):
    """Answers like a controller with a device in range. `behaviour` picks what goes wrong."""

    def __init__(self, sock, behaviour="ok", version=11, company=0x0002):
        super().__init__(daemon=True)
        self.sock, self.behaviour, self.version, self.company = sock, behaviour, version, company
        self.ops = []

    def send(self, code, params):
        self.sock.send(bytes([0x04, code, len(params)]) + params)

    def status(self, op, st=0):
        self.send(0x0F, bytes([st, 1]) + struct.pack("<H", op))

    def run(self):
        while True:
            try:
                pkt = self.sock.recv(4096)
            except OSError:
                return
            if not pkt:
                return
            op = struct.unpack("<H", pkt[1:3])[0]
            self.ops.append(op)
            if op == 0x200D:  # LE Create Connection
                if self.behaviour == "legacy_disallowed":
                    self.status(op, 0x0C)
                    continue
                self.status(op)
                self._connect()
            elif op == 0x2043:  # LE Extended Create Connection
                self.status(op)
                self._connect()
            elif op == 0x200E:  # cancel
                self.send(0x3E, bytes([0x01, 0x02]) + bytes(17))   # connection complete: unknown connection id
            elif op == 0x041D:  # Read Remote Version Information
                self.status(op)
                if self.behaviour != "silent":
                    self.send(0x0C, bytes([0]) + struct.pack("<HBHH", HANDLE, self.version, self.company, 1))
            elif op == 0x0406:  # Disconnect
                self.status(op)
                self.send(0x05, bytes([0]) + struct.pack("<HB", HANDLE, 0x16))

    def _connect(self):
        if self.behaviour == "nobody":
            return
        if self.behaviour == "failed":
            self.send(0x3E, bytes([0x01, 0x3E]) + bytes(17))
            return
        self.send(0x3E, bytes([0x01, 0x00]) + struct.pack("<H", HANDLE) + bytes(16))


@pytest.fixture
def controller(monkeypatch):
    made = []

    def make(behaviour="ok", **kw):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        c = Controller(b, behaviour, **kw)
        c.start()
        monkeypatch.setattr(btprobe, "_open_socket", lambda dev_id: a)
        made.append(c)
        return c
    monkeypatch.setattr(btprobe, "CONNECT_TIMEOUT", 0.4)
    monkeypatch.setattr(btprobe, "VERSION_TIMEOUT", 0.4)
    monkeypatch.setattr(btprobe, "DISCONNECT_WAIT", 0.3)
    yield make
    for c in made:
        c.sock.close()


def test_reads_the_version_and_disconnects(controller):
    c = controller()
    assert btprobe.read_version("hci0", MAC, 1) == {"version": "5.2", "company": "Intel"}
    assert c.ops == [0x200D, 0x041D, 0x0406] and not btprobe.PROBING


def test_falls_back_to_the_extended_connect_command(controller):
    c = controller("legacy_disallowed")
    assert btprobe.read_version("hci0", MAC, 0)["version"] == "5.2"
    assert c.ops[:2] == [0x200D, 0x2043]


def test_failures_say_what_went_wrong_and_always_clean_up(controller):
    c = controller("nobody")
    with pytest.raises(btprobe.ProbeError, match="no connection in time"):
        btprobe.read_version("hci0", MAC, 1)
    assert 0x200E in c.ops and not btprobe.PROBING   # the pending connect was cancelled
    controller("failed")
    with pytest.raises(btprobe.ProbeError, match="could not be established"):
        btprobe.read_version("hci0", MAC, 1)
    c = controller("silent")
    with pytest.raises(btprobe.ProbeError, match="did not answer the version request"):
        btprobe.read_version("hci0", MAC, 1)
    assert 0x0406 in c.ops and not btprobe.PROBING   # it still disconnected


# ------------------------------------------------------------------ the sensor: limits, results, not counting it as a link
def sensor(store, **cfg):
    s = BluetoothSensor("hci9", Config(**cfg), store)
    s.stop = threading.Event()
    return s


def wait_for(cond, secs=3):
    end = time.monotonic() + secs
    while time.monotonic() < end and not cond():
        time.sleep(0.02)
    return cond()


def test_request_reports_the_result_as_an_observation(monkeypatch):
    st = Store()
    s = sensor(st)
    monkeypatch.setattr(btprobe, "read_version", lambda iface, mac, t: {"version": "5.0", "company": "Nordic Semiconductor"})
    s.request_probe(MAC.upper(), 1)
    assert wait_for(lambda: len(st) == 1)
    o = st[0]
    assert o["mac"] == MAC and o["extra"]["bt_version"] == "5.0" and o["extra"]["chip"] == "Nordic Semiconductor"
    assert o["extra"]["bt_probe"]["ok"] is True and o["extra"]["bt_probe"]["error"] is None and not s.probe_busy


def test_request_reports_a_failure_and_frees_the_adapter(monkeypatch):
    st = Store()
    s = sensor(st)

    def boom(*a):
        raise btprobe.ProbeError("no connection in time")
    monkeypatch.setattr(btprobe, "read_version", boom)
    s.request_probe(MAC, 0)
    assert wait_for(lambda: len(st) == 1 and not s.probe_busy)
    assert st[0]["extra"]["bt_probe"] == {"ts": st[0]["extra"]["bt_probe"]["ts"], "ok": False, "error": "no connection in time", "adapter": "bt:hci9"}
    assert "bt_version" not in st[0]["extra"]


def test_request_limits_and_checks(monkeypatch):
    s = sensor(Store())
    gate = threading.Event()
    monkeypatch.setattr(btprobe, "read_version", lambda *a: gate.wait(2) and {"version": "5.0", "company": None})
    with pytest.raises(ValueError, match="Not a Bluetooth LE address"):
        s.request_probe("nope", 1)
    with pytest.raises(ValueError, match="Not a Bluetooth LE address"):
        s.request_probe(MAC, 7)
    s.request_probe(MAC, 1)
    with pytest.raises(ValueError, match="busy"):
        s.request_probe(MAC, 1)
    gate.set()
    assert wait_for(lambda: not s.probe_busy)
    with pytest.raises(ValueError, match="few seconds"):
        s.request_probe(MAC, 1)
    s.probe_times = [time.time() - 100] * bluetooth.PROBE_PER_HOUR
    with pytest.raises(ValueError, match="in the last hour"):
        s.request_probe(MAC, 1)
    off = sensor(Store(), bt_active_probe=False)
    with pytest.raises(ValueError, match="switched off"):
        off.request_probe(MAC, 1)


def test_the_probes_own_connection_is_not_recorded_as_a_bluetooth_link():
    st = Store()
    s = sensor(st)
    bluetooth.PROBING.add(MAC)
    try:
        s._handle({"ev": "conn", "handle": HANDLE, "mac": MAC, "le": True, "addr_type": 1}, 1.0)
        s._handle({"ev": "disc", "handle": HANDLE, "reason": 0x16}, 2.0)
    finally:
        bluetooth.PROBING.discard(MAC)
    assert list(st) == []
    s._handle({"ev": "conn", "handle": HANDLE, "mac": MAC, "le": True, "addr_type": 1}, 3.0)  # an ordinary link still is
    assert st and st[0]["t"] == "bt_conn"


def test_a_command_from_the_server_runs_or_reports_the_refusal(monkeypatch):
    st = Store()
    s = sensor(st, bt_active_probe=False)
    monkeypatch.setitem(bluetooth.SENSORS, s.name, s)
    adapters.run_commands([{"action": "btprobe", "name": "bt:hci9", "mac": MAC, "addr_type": 1}])
    assert wait_for(lambda: len(st) == 1)
    assert st[0]["extra"]["bt_probe"]["ok"] is False and "switched off" in st[0]["extra"]["bt_probe"]["error"]
    adapters.run_commands([{"action": "btprobe", "name": "bt:hci77", "mac": MAC, "addr_type": 1}])   # not an adapter here: nothing happens
    adapters.run_commands([{"action": "btprobe", "name": "wifi:wlan0", "mac": MAC, "addr_type": 1}])
    time.sleep(0.2)
    assert len(st) == 1


# ------------------------------------------------------------------ the API
def heard(ctx, mac=MAC, sensor_id=None, age=5, **extra):
    o = bt(mac, time.time() - age, connectable=True, addr_type="random-static", **extra)
    if sensor_id:
        o["sensor"] = sensor_id
    ctx.store.process(o)
    ctx.store.flush()


def test_the_button_endpoint(ctx, monkeypatch):  # noqa: F811
    c = admin_client(ctx)
    asked = []

    class Fake:
        def request_probe(self, mac, addr_type):
            asked.append((mac, addr_type))
    monkeypatch.setattr(bluetooth, "SENSORS", {"bt:hci0": Fake()})
    status.register("bt:hci0", type="bluetooth", iface="hci0", state="scanning")
    heard(ctx)
    r = c.post(f"/api/devices/{MAC}/bt-version")
    assert r.status_code == 200 and r.json() == {"ok": True, "queued": False, "adapter": "bt:hci0"} and asked == [(MAC, 1)]
    assert c.post(f"/api/devices/{MAC}/bt-version").status_code == 429          # once a minute per device
    assert c.post("/api/devices/00:00:00:00:00:99/bt-version").status_code == 404
    # only LE devices, and only ones heard just now
    ctx.store.process(bt("bb:00:00:00:00:01", time.time(), kind="bt_classic"))
    heard(ctx, "aa:00:00:00:00:77", age=600)
    ctx.store.flush()
    assert c.post("/api/devices/bb:00:00:00:00:01/bt-version").status_code == 400
    r = c.post("/api/devices/aa:00:00:00:00:77/bt-version")
    assert r.status_code == 409 and "two minutes" in r.json()["detail"]


def test_the_button_endpoint_queues_it_for_a_remote_sensor(ctx):  # noqa: F811
    c = admin_client(ctx)
    ctx.execute("INSERT INTO sensors(id, name, created, last_seen) VALUES('garden', 'Garden', ?, ?)", (time.time(), time.time()))
    status.register("bt:hci0", type="bluetooth", iface="hci0", state="scanning", remote="garden")
    heard(ctx, sensor_id="garden")
    r = c.post(f"/api/devices/{MAC}/bt-version")
    assert r.status_code == 200 and r.json()["queued"] is True and r.json()["sensor"] == "garden"
    cmds = adapters.take("garden")
    assert cmds == [{"action": "btprobe", "name": "bt:hci0", "mac": MAC, "addr_type": 1}]


def test_the_button_endpoint_is_admin_only_and_can_be_switched_off(ctx, monkeypatch):  # noqa: F811
    from fastapi.testclient import TestClient
    from sniffowireless.web import create_app
    c = admin_client(ctx)
    heard(ctx)
    v = TestClient(create_app(ctx), base_url="http://sniffowireless.test")
    assert v.post(f"/api/devices/{MAC}/bt-version", headers={"x-sniffowireless": "1"}).status_code == 401
    assert v.post("/api/auth/login", json={"username": "view", "password": "correct-horse-battery"}).status_code == 200
    assert v.post(f"/api/devices/{MAC}/bt-version", headers={"x-sniffowireless": "1"}).status_code == 403
    monkeypatch.setattr(ctx.cfg, "bt_active_probe", False)
    r = c.post(f"/api/devices/{MAC}/bt-version")
    assert r.status_code == 403 and "BT_ACTIVE_PROBE=0" in r.json()["detail"]
    status.SENSORS.pop("bt:hci0", None)
