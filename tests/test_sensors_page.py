"""Sensors page: hardware details of each interface (local and remote), and the live signal feed of chosen devices."""
import os
import time

import pytest
from fastapi.testclient import TestClient

from sniffowireless import hwinfo, sanitize, status
from sniffowireless.auth import hash_password
from sniffowireless.config import Config
from sniffowireless.main import build
from sniffowireless.store import FOLLOW_KEEP, FOLLOW_MAX
from sniffowireless.web import create_app

PW = "correct-horse-battery"


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text + "\n")


def link(target, name):
    os.makedirs(os.path.dirname(name), exist_ok=True)
    os.symlink(target, name)


@pytest.fixture
def sysfs(tmp_path, monkeypatch):
    """A small fake /sys: a USB Wi-Fi adapter, a USB Bluetooth dongle, a USB serial stick, and a built-in wired port."""
    root = str(tmp_path / "sys")
    usb = f"{root}/devices/pci0000:00/0000:00:14.0/usb1/1-2"
    for dev, vid, pid, maker, product in ((f"{usb}", "0e8d", "7961", "MediaTek Inc.", "Wireless_Device"),
                                          (f"{root}/devices/pci0000:00/0000:00:14.0/usb1/1-3", "2357", "0604", "TP-Link", "UB500 Plus"),
                                          (f"{root}/devices/pci0000:00/0000:00:14.0/usb1/1-4", "10c4", "ea60", "ITead", "Sonoff Zigbee 3.0 USB Dongle Plus")):
        for k, v in (("idVendor", vid), ("idProduct", pid), ("manufacturer", maker), ("product", product), ("speed", "480")):
            write(f"{dev}/{k}", v)
    os.makedirs(f"{root}/bus/usb/drivers/mt7921u")
    os.makedirs(f"{root}/bus/usb/drivers/btusb")
    os.makedirs(f"{root}/bus/usb-serial/drivers/cp210x")
    os.makedirs(f"{root}/bus/pci/drivers/e1000e")
    for intf, drv, bus in ((f"{usb}/1-2:1.0", "mt7921u", "usb"), (f"{root}/devices/pci0000:00/0000:00:14.0/usb1/1-3/1-3:1.0", "btusb", "usb"),
                           (f"{root}/devices/pci0000:00/0000:00:14.0/usb1/1-4/1-4:1.0/ttyUSB0", "cp210x", "usb-serial")):
        link(f"{root}/bus/{bus}/drivers/{drv}", f"{intf}/driver")
        link(f"{root}/bus/{bus}", f"{intf}/subsystem")
    eth = f"{root}/devices/pci0000:00/0000:00:1f.6"
    link(f"{root}/bus/pci/drivers/e1000e", f"{eth}/driver")
    link(f"{root}/bus/pci", f"{eth}/subsystem")
    link(f"{usb}/1-2:1.0", f"{root}/class/net/wlan1/device")
    write(f"{root}/class/net/wlan1/phy80211/name", "phy1")
    write(f"{root}/class/net/wlan1/speed", "-1")
    link(eth, f"{root}/class/net/eth1/device")
    write(f"{root}/class/net/eth1/speed", "1000")
    link(f"{root}/devices/pci0000:00/0000:00:14.0/usb1/1-3/1-3:1.0", f"{root}/class/bluetooth/hci1/device")
    link(f"{root}/devices/pci0000:00/0000:00:14.0/usb1/1-4/1-4:1.0/ttyUSB0", f"{root}/class/tty/ttyUSB0/device")
    dev = tmp_path / "dev"
    os.makedirs(dev / "serial" / "by-id")
    (dev / "ttyUSB0").write_text("")
    os.symlink(dev / "ttyUSB0", dev / "serial" / "by-id" / "usb-ITead_Sonoff-if00-port0")
    monkeypatch.setattr(hwinfo, "SYSFS", root)
    return tmp_path


def test_hardware_of_each_kind_of_interface(sysfs):
    assert hwinfo.net("wlan1") == {"hw_driver": "mt7921u", "hw_bus": "usb", "hw_usb": "0e8d:7961", "hw_maker": "MediaTek Inc.",
                                   "hw_product": "Wireless_Device", "hw_speed": "480 Mbps", "hw_phy": "phy1"}
    assert hwinfo.bluetooth("hci1")["hw_product"] == "UB500 Plus" and hwinfo.bluetooth(1)["hw_driver"] == "btusb"
    z = hwinfo.serial(str(sysfs / "dev" / "serial" / "by-id" / "usb-ITead_Sonoff-if00-port0"))   # a by-id link is followed
    assert z["hw_driver"] == "cp210x" and z["hw_usb"] == "10c4:ea60" and z["hw_bus"] == "usb"
    assert hwinfo.net("eth1") == {"hw_driver": "e1000e", "hw_bus": "pci", "hw_link": "1 Gbps"}


def test_missing_or_unreadable_hardware_gives_nothing(sysfs):
    assert hwinfo.net("wlan9") == {} and hwinfo.bluetooth("hci7") == {} and hwinfo.serial("/dev/ttyACM9") == {}


def test_a_remote_sensor_reports_its_hardware_and_nothing_else_slips_through():
    got = sanitize.remote_status({"name": "bt:hci0", "type": "bluetooth", "hw_product": "UB500 Plus", "hw_usb": "2357:0604",
                                  "hw_maker": "<script>x</script>" + "a" * 200, "hw_evil": "nope"})
    assert got["hw_product"] == "UB500 Plus" and got["hw_usb"] == "2357:0604"
    assert len(got["hw_maker"]) <= 64 and "hw_evil" not in got


@pytest.fixture
def ctx(tmp_path):
    status.SENSORS.clear()
    c = build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))
    with c.wdb() as w:
        w.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('view', ?, 'viewer', 0)", (hash_password(PW, iterations=1000),))
    return c


def obs(mac, rssi, sensor=None, ts=None):
    o = {"t": "bt", "kind": "ble", "mac": mac, "ts": ts or time.time(), "rssi": rssi}
    if sensor:
        o["sensor"] = sensor
    return o


def test_store_records_readings_only_of_followed_devices(ctx):
    store, now = ctx.store, time.time()
    a, b = "00:11:22:33:44:01", "00:11:22:33:44:02"
    assert store.follow_signal([a], 0, now) == {a: []}
    store.process(obs(a, -60, ts=now))
    store.process(obs(a, -70, "attic", ts=now + 0.5))
    store.process(obs(b, -50, ts=now))                       # not followed: not recorded
    got = store.follow_signal([a, b], 0, now + 1)
    assert [(s, r) for _, s, r in got[a]] == [("local", -60), ("attic", -70)] and got[b] == []
    assert [r for _, _, r in store.follow_signal([a], now + 0.2, now + 1)[a]] == [-70]   # only what is newer than `after`


def test_following_ends_and_old_readings_go(ctx):
    store, now = ctx.store, time.time()
    a = "00:11:22:33:44:01"
    store.follow_signal([a], 0, now)
    store.process(obs(a, -60, ts=now))
    store.follow_signal([], 0, now + 120)                    # nobody asked for a minute: no longer followed
    store.process(obs(a, -61, ts=now + 121))
    assert [r for _, _, r in store.follow_signal([a], 0, now + 122)[a]] == [-60]
    assert store.follow_signal([a], 0, now + FOLLOW_KEEP + 10)[a] == []
    store.follow_signal([], 0, now + 3 * FOLLOW_KEEP)
    assert a not in store.follow_buf


def test_the_number_of_followed_devices_is_bounded(ctx):
    store, now = ctx.store, time.time()
    macs = [f"00:11:22:33:{i // 256:02x}:{i % 256:02x}" for i in range(FOLLOW_MAX + 10)]
    for i in range(0, len(macs), 8):
        store.follow_signal(macs[i:i + 8], 0, now)
    assert len(store.follow) == FOLLOW_MAX


def test_live_endpoint(ctx):
    app = create_app(ctx)
    anon = TestClient(app, base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    assert anon.get("/api/signal/live?mac=00:11:22:33:44:01").status_code in (401, 403)
    c = TestClient(app, base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    assert c.post("/api/auth/login", json={"username": "view", "password": PW}).status_code == 200
    a = "00:11:22:33:44:01"
    first = c.get(f"/api/signal/live?mac={a}&mac=nonsense&mac={a.upper()}").json()
    assert first["macs"] == [a] and first["points"] == {a: []} and first["keep"] == FOLLOW_KEEP
    ctx.store.process(obs(a, -64, ts=time.time()))
    ctx.store.flush()
    r = c.get(f"/api/signal/live?mac={a}").json()
    assert [p[1:] for p in r["points"][a]] == [["local", -64]]
    assert r["devices"][a]["kind"] == "ble" and r["latest"][0]["sensor"] == "local" and r["sensors"]["local"] == "This server"
    many = "&".join(f"mac=00:11:22:33:44:{i:02x}" for i in range(20))
    assert len(c.get(f"/api/signal/live?{many}").json()["macs"]) == 8
    assert c.get("/api/signal/live").json()["points"] == {}
