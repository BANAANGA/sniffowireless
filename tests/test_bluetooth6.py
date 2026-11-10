"""Bluetooth 5.x / 6.0 support: what the controller is, extended + Coded PHY scanning, LE Audio broadcasts, newer HCI events."""
import random
import socket
import struct
import threading

from sniffowireless import sanitize, status
from sniffowireless.bluetooth import (BluetoothSensor, bt_version_label, parse_ad, parse_event, parse_le_features,
                                      parse_local_version)
from sniffowireless.config import Config


def ad(*items):
    """Advertising data from (type, payload) pairs."""
    return b"".join(bytes([len(v) + 1, t]) + v for t, v in items)


def test_version_labels():
    assert [bt_version_label(v) for v in (9, 13, 14)] == ["5.0", "5.4", "6.0"]
    assert bt_version_label(15).startswith(">6.0") and bt_version_label(1).startswith("?") and bt_version_label(None) is None
    v = parse_local_version(bytes([14, 0x34, 0x12, 14, 0x02, 0x00, 0x01, 0x00]))          # 6.0, company 0x0002
    assert v["version"] == "6.0" and v["chip"] == "Intel" and v["hci_version"] == 14
    assert parse_local_version(b"\x0e\x00") is None


def test_le_features():
    bits = (1 << 8) | (1 << 11) | (1 << 12) | (1 << 46)
    assert parse_le_features(bits.to_bytes(8, "little")) == ["2M PHY", "Coded PHY", "Ext. adv", "Channel Sounding"]
    assert parse_le_features(b"\x01" + b"\x00" * 7) == [] and parse_le_features(b"\x01") is None


def test_le_audio_broadcast_and_new_data_types():
    data = ad((0x16, b"\x56\x18\x06"),                       # Public Broadcast Announcement: standard + high quality bits... high wins
              (0x16, b"\x52\x18\xaa\xbb\xcc"),               # Broadcast Audio Announcement, Broadcast_ID cc bb aa
              (0x30, "Gate B12 TV".encode()),
              (0x34, b"\x01"), (0x31, b"\x01\x02\x03"))
    out = parse_ad(data)
    assert out["auracast"] == {"encrypted": False, "quality": "high"} and out["broadcast_id"] == "ccbbaa"
    assert out["broadcast_name"] == "Gate B12 TV" and out["esl"] and out["encrypted_ad"]
    assert out["uuids"] == ["1852", "1856"]
    enc = parse_ad(ad((0x16, b"\x56\x18\x03")))
    assert enc["auracast"] == {"encrypted": True, "quality": "standard"}
    assert parse_ad(ad((0x30, b"\x00 \x00"))) == {}                        # an empty name is nothing


def ext_report(atype=1, addr=b"\x01\x02\x03\x04\x05\x06", prim=3, sec=3, rssi=-60, data=b"", evt=0x0001):
    body = struct.pack("<HB", evt, atype) + addr + bytes([prim, sec, 1, 127, rssi & 0xFF]) + b"\x00\x00" + b"\x00" + b"\x00" * 6 + bytes([len(data)]) + data
    params = bytes([0x0D, 1]) + body
    return bytes([0x04, 0x3E, len(params)]) + params


def test_extended_report_carries_the_phy_and_the_data():
    (e,) = parse_event(ext_report(data=ad((0x30, b"Stage"))))
    assert e["ext"] and e["phy"] == "Coded" and e["rssi"] == -60 and e["ad"]["broadcast_name"] == "Stage" and e["connectable"]
    (e,) = parse_event(ext_report(prim=1, sec=2, evt=0x0010))                # legacy bit set, secondary PHY 2M
    assert e["ext"] is False and e["phy"] == "2M"
    (e,) = parse_event(ext_report(prim=1, sec=0))
    assert e["phy"] == "1M"


def test_remote_version_and_connection_v2_and_command_complete():
    params = bytes([0, 0x41, 0x00, 14, 0x0F, 0x00, 0x01, 0x00])
    (e,) = parse_event(bytes([0x04, 0x0C, len(params)]) + params)
    assert e == {"ev": "peerver", "handle": 0x41, "version": 14, "company": 0x000F}
    assert parse_event(bytes([0x04, 0x0C, 3, 1, 0x41, 0])) == []                 # failed / short: nothing
    # LE Enhanced Connection Complete [v2] (subevent 0x29) is read like the v1 one
    conn = bytes([0x29, 0, 0x40, 0x00, 0, 1]) + bytes([1, 2, 3, 4, 5, 6]) + b"\x00" * 20
    (e,) = parse_event(bytes([0x04, 0x3E, len(conn)]) + conn)
    assert e["ev"] == "conn" and e["le"] and e["handle"] == 0x40 and e["mac"] == "06:05:04:03:02:01"
    cc = bytes([1, 0x01, 0x10, 0x00]) + bytes([0x0E, 0, 0x0E, 0, 0, 0, 0, 0])
    (e,) = parse_event(bytes([0x04, 0x0E, len(cc)]) + cc)
    assert e["opcode"] == 0x1001 and e["status"] == 0 and e["ret"][0] == 14


def test_the_parser_survives_garbage():
    rnd = random.Random(6)
    for _ in range(3000):
        n = rnd.randrange(0, 70)
        body = bytes(rnd.randrange(256) for _ in range(n))
        code = rnd.choice([0x3E, 0x0C, 0x0E, 0x0F, 0x02, 0x22, 0x2F, 0x07, 0x03, 0x05])
        sub = rnd.choice([0x02, 0x0D, 0x01, 0x0A, 0x29, 0x2B, 0x31])
        pkt = bytes([0x04, code, len(body) + 1, sub]) + body if code == 0x3E else bytes([0x04, code, len(body)]) + body
        parse_event(pkt)
        parse_ad(body)


# ------------------------------------------------------------------ the sensor against a simulated controller
class Controller(threading.Thread):
    """The other end of the HCI socket: answers Read Local Version / LE Read Local Supported Features and records every command."""

    def __init__(self, sock, hci_version, features, company=0x0002, refuse=None):
        super().__init__(daemon=True)
        self.sock, self.hci_version, self.features, self.company, self.refuse = sock, hci_version, features, company, refuse or {}
        self.commands = []

    def run(self):
        while True:
            try:
                pkt = self.sock.recv(4096)
            except OSError:
                return
            if not pkt:
                return
            op, ln = struct.unpack("<HB", pkt[1:4])
            self.commands.append((op, pkt[4:4 + ln]))
            status_ = self.refuse.get(op, 0)
            ret = b""
            if op == 0x1001 and not status_:
                ret = bytes([self.hci_version, 0, 0, self.hci_version]) + struct.pack("<HH", self.company, 1)
            elif op == 0x2003 and not status_:
                ret = self.features.to_bytes(8, "little")
            body = struct.pack("<BHB", 1, op, status_) + ret
            try:
                self.sock.send(bytes([0x04, 0x0E, len(body)]) + body)
            except OSError:
                return


def make_sensor(hci_version, features, cfg=None, refuse=None, name="hci9"):
    status.SENSORS.clear()
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    sensor = BluetoothSensor(name, cfg or Config(), None)
    sensor.sock, sensor.stop = a, threading.Event()
    ctl = Controller(b, hci_version, features, refuse=refuse)
    ctl.start()
    return sensor, ctl, (a, b)


BT60 = (1 << 8) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 46)
BT42 = (1 << 0) | (1 << 5)


def ops(ctl, n=None):
    """The opcodes the simulated controller has received. It runs in its own thread, so wait until `n` have arrived and
    then until nothing more is arriving (tests slice the list at a point they just read; a late command shifted it)."""
    import time
    end = time.monotonic() + 3
    while n and len(ctl.commands) < n and time.monotonic() < end:
        time.sleep(0.01)
    quiet, last = 0, -1
    while quiet < 5 and time.monotonic() < end:  # five polls in a row with no new command
        time.sleep(0.01)
        quiet = quiet + 1 if len(ctl.commands) == last else 0
        last = len(ctl.commands)
    return [c[0] for c in ctl.commands]


def test_a_bluetooth_6_controller_gets_extended_and_coded_scanning():
    sensor, ctl, socks = make_sensor(14, BT60)
    sensor._configure()
    st = status.SENSORS["bt:hci9"]
    assert st["bt_version"] == "6.0" and st["chip"] == "Intel" and "Channel Sounding" in st["caps"] and st["scan"] == "extended"
    assert st["warning"] is None
    assert sensor.ext_scan and sensor.coded
    assert ops(ctl, 7)[:2] == [0x1001, 0x2003] and ops(ctl)[-3:] == [0x2042, 0x2041, 0x2042]
    params = [p for o, p in ctl.commands if o == 0x2041][0]
    assert params[2] == 0x05 and len(params) == 3 + 2 * 5          # 1M + Coded, one (type, interval, window) set each
    [s.close() for s in socks]


def test_a_bluetooth_4_controller_stays_on_legacy_scanning_and_says_what_it_cannot_see():
    sensor, ctl, socks = make_sensor(8, BT42)
    sensor._configure()
    st = status.SENSORS["bt:hci9"]
    assert st["bt_version"] == "4.2" and not sensor.ext_scan and not sensor.coded
    assert "extended advertising" in st["warning"] and ops(ctl, 7)[-3:] == [0x200C, 0x200B, 0x200C]
    [s.close() for s in socks]


def test_extended_scanning_can_be_turned_off():
    sensor, ctl, socks = make_sensor(14, BT60, cfg=Config(bt_extended_scan=False))
    sensor._configure()
    assert not sensor.ext_scan and ops(ctl, 7)[-3:] == [0x200C, 0x200B, 0x200C]
    assert status.SENSORS["bt:hci9"]["bt_version"] == "6.0"                  # still reported
    [s.close() for s in socks]


def test_a_controller_that_does_not_answer_is_scanned_the_old_way():
    sensor, ctl, socks = make_sensor(14, BT60, refuse={0x1001: 1, 0x2003: 1})
    sensor._configure()
    assert not sensor.ext_scan and ops(ctl, 7)[-3:] == [0x200C, 0x200B, 0x200C]
    [s.close() for s in socks]


def test_refusals_fall_back_without_looping_for_ever():
    sensor, ctl, socks = make_sensor(14, BT60)
    sensor._configure()
    ops(ctl, 7)
    n = len(ctl.commands)
    sensor._handle({"ev": "cmd", "opcode": 0x2041, "status": 0x11}, 0)       # Coded PHY not supported after all
    assert sensor.ext_scan and not sensor.coded
    ops(ctl, n + 3)
    assert [o for o, p in ctl.commands[n:]] == [0x2042, 0x2041, 0x2042] and [p for o, p in ctl.commands[n:] if o == 0x2041][0][2] == 0x01
    sensor._handle({"ev": "cmd", "opcode": 0x2042, "status": 0x0C}, 0)       # extended refused -> legacy
    assert not sensor.ext_scan and sensor.mode_switches == 1
    sensor._handle({"ev": "cmd", "opcode": 0x200B, "status": 0x0C}, 0)       # legacy refused -> extended
    assert sensor.ext_scan and sensor.mode_switches == 2
    sensor._handle({"ev": "cmd", "opcode": 0x2042, "status": 0x0C}, 0)       # and then it stops switching
    assert sensor.ext_scan and sensor.mode_switches == 2
    [s.close() for s in socks]


class Store(list):
    def put(self, o):
        self.append(o)


def test_broadcasts_and_peer_versions_are_recorded():
    st = Store()
    sensor = BluetoothSensor("hci9", Config(), st)
    sensor.stop = threading.Event()
    data = ad((0x16, b"\x56\x18\x04"), (0x16, b"\x52\x18\x01\x02\x03"), (0x30, b"Lobby TV"))
    (e,) = parse_event(ext_report(addr=b"\x11\x22\x33\x44\x55\xc6", data=data))
    sensor._handle(e, 100.0)
    o = st[0]
    assert o["name"] == "Lobby TV" and o["extra"]["phy"] == "Coded"
    assert o["extra"]["auracast"] == {"name": "Lobby TV", "id": "030201", "encrypted": False, "quality": "high"}
    assert o["extra"]["esl"] is None and o["extra"]["encrypted_ad"] is None
    # a connection the host makes, then its peer's version information
    sensor._handle({"ev": "conn", "handle": 0x41, "mac": "aa:bb:cc:dd:ee:ff", "le": True, "addr_type": 0}, 101.0)
    sensor._handle({"ev": "peerver", "handle": 0x41, "version": 14, "company": 0x0059}, 102.0)
    sensor._handle({"ev": "peerver", "handle": 0x99, "version": 14, "company": 0x0059}, 103.0)   # not a connection we know
    assert st[-1]["mac"] == "aa:bb:cc:dd:ee:ff" and st[-1]["extra"] == {"bt_version": "6.0", "chip": "Nordic Semiconductor"} and len(st) == 3


def test_a_remote_sensor_reports_the_adapter_capabilities():
    out = sanitize.remote_status({"name": "bt:hci0", "type": "bluetooth", "bt_version": "6.0", "chip": "Intel",
                                  "caps": ["Ext. adv", "Channel Sounding", 5, "x" * 40], "evil": "x"})
    assert out["bt_version"] == "6.0" and out["chip"] == "Intel" and out["caps"][:2] == ["Ext. adv", "Channel Sounding"] and "evil" not in out
    assert all(len(c) <= 16 for c in out["caps"])
