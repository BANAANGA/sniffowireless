"""Thread: beacons (network name, extended PAN ID, flags) and the MAC-security signature of Thread frames.

The beacon layout is OpenThread's (src/core/mac/mac_beacon.hpp): protocol ID 3, flags (version in the high four bits, bit 3 native
commissioner, bit 0 joining permitted), a 16-byte network name padded with zeros, the 8-byte extended PAN ID."""
import struct
import time

from sniffowireless.sanitize import remote_observation
from sniffowireless.zigbee import ZigbeeMonitor
from sniffowireless.zigbee_radio import (HINT_ENCRYPTED, HINT_THREAD, HINT_ZIGBEE, FrameBatch, parse_mac, parse_thread_beacon)
from tests.test_zigbee import FRAME_ZIGBEE_DATA, captured, ctx, feed  # noqa: F401

EXT = bytes.fromhex("dda17c33905e1208")
ALL_BEACON_FIELDS = b"\xff\xcf\x00\x00"       # superframe specification, empty GTS spec, no pending addresses


def thread_payload(name=b"OpenThread-4e20", flags=0x21, ext=EXT, protocol=3):
    return bytes([protocol, flags]) + name.ljust(16, b"\x00") + ext


def beacon_frame(payload, pan=0x4E20, src=0x0001):
    control = 0x8000                                  # beacon, no security, 2006 revision, short source address
    return struct.pack("<HBHH", control, 7, pan, src) + ALL_BEACON_FIELDS + payload


def secured_frame(level=5, key_mode=1, type_=1, extra_key=b""):
    control = type_ | 0x08 | 0x40 | (2 << 10) | (2 << 14)          # security enabled, PAN compression, short addresses
    sec = bytes([level | key_mode << 3]) + struct.pack("<I", 1234) + {0: b"", 1: b"\x01", 2: b"\xff\xff\xff\xff\x01", 3: b"\x00" * 9}[key_mode]
    return struct.pack("<HBHHH", control, 9, 0x4E20, 0x0002, 0x0001) + sec + b"\xaa\xbb\xcc\xdd\x01\x02\x03\x04"


# ------------------------------------------------------------------ beacons
def test_a_thread_beacon_gives_its_network_name_and_extended_pan_id():
    t = parse_thread_beacon(parse_mac(beacon_frame(thread_payload())).payload)
    assert t == {"version": 2, "native": False, "joining": True, "name": "OpenThread-4e20", "ext_pan": "dd:a1:7c:33:90:5e:12:08"}


def test_the_flags_are_decoded():
    f = lambda flags: parse_thread_beacon(parse_mac(beacon_frame(thread_payload(flags=flags))).payload)   # noqa: E731
    assert (f(0x20)["version"], f(0x20)["joining"], f(0x20)["native"]) == (2, False, False)
    assert (f(0x31)["version"], f(0x31)["joining"]) == (3, True)
    assert f(0x28)["native"] is True and f(0x48)["version"] == 4


def test_a_name_that_fills_all_sixteen_bytes_and_one_with_junk_is_handled():
    full = parse_thread_beacon(parse_mac(beacon_frame(thread_payload(name=b"0123456789ABCDEF"))).payload)
    assert full["name"] == "0123456789ABCDEF"
    junk = parse_thread_beacon(parse_mac(beacon_frame(thread_payload(name=b"Home\x07\x1b net"))).payload)
    assert junk["name"] == "Home net" or junk["name"].startswith("Home")
    assert "\x07" not in junk["name"] and "\x1b" not in junk["name"]


def test_something_that_is_not_a_thread_beacon_is_not_one():
    payload = lambda p: parse_mac(beacon_frame(p)).payload   # noqa: E731
    assert parse_thread_beacon(payload(thread_payload(protocol=0))) is None                  # a Zigbee beacon
    assert parse_thread_beacon(payload(thread_payload()[:25])) is None                       # one byte short
    assert parse_thread_beacon(b"") is None and parse_thread_beacon(b"\x00" * 3) is None


def test_the_batch_reports_a_thread_network_with_its_pan_and_channel():
    b = FrameBatch()
    b.add(captured(beacon_frame(thread_payload()), channel=25, rssi=-80, lqi=90))
    b.add(captured(beacon_frame(thread_payload()), channel=25, rssi=-70, lqi=120))           # the same network again: one entry
    o = b.drain(100.0)
    assert o["networks"] == [{"version": 2, "native": False, "joining": True, "name": "OpenThread-4e20", "ext_pan": "dd:a1:7c:33:90:5e:12:08",
                              "pan": 0x4E20, "channel": 25, "rssi": -70, "lqi": 120}]
    assert o["radios"][0][6] == HINT_THREAD                                                  # and the beaconing radio is labelled Thread
    assert "networks" not in (FrameBatch().drain(1.0) or {})


# ------------------------------------------------------------------ MAC security
def test_the_security_header_is_read():
    f = parse_mac(secured_frame(5, 1))
    assert (f.secured, f.sec_level, f.key_mode) == (True, 5, 1) and f.payload == b"\xaa\xbb\xcc\xdd\x01\x02\x03\x04"
    f2 = parse_mac(secured_frame(5, 2))
    assert (f2.sec_level, f2.key_mode) == (5, 2) and f2.payload == b"\xaa\xbb\xcc\xdd\x01\x02\x03\x04"
    assert parse_mac(FRAME_ZIGBEE_DATA).sec_level is None


def test_level_5_with_key_mode_1_or_2_looks_like_thread():
    assert parse_mac(secured_frame(5, 1)).hint == HINT_THREAD
    assert parse_mac(secured_frame(5, 2)).hint == HINT_THREAD
    assert parse_mac(secured_frame(5, 1, type_=3)).hint == HINT_THREAD                       # a MAC command (data request) too


def test_other_secured_frames_stay_encrypted_and_zigbee_stays_zigbee():
    for level, mode in ((4, 1), (6, 1), (1, 1), (5, 0), (5, 3), (0, 1)):
        assert parse_mac(secured_frame(level, mode)).hint == HINT_ENCRYPTED, (level, mode)
    assert parse_mac(secured_frame(5, 1, type_=2)).hint == HINT_ENCRYPTED                    # an acknowledgement is neither
    assert parse_mac(FRAME_ZIGBEE_DATA).hint == HINT_ZIGBEE


def test_a_truncated_secured_frame_does_not_raise():
    full = secured_frame(5, 2)
    for n in range(2, len(full)):
        parse_mac(full[:n])                                                                  # any cut: a result or None, never an exception


# ------------------------------------------------------------------ store, events, API
def thread_obs(ts, joining=False, name="OpenThread-4e20"):
    return {"t": "zb_frames", "ts": ts, "mac": "-", "undecoded": 0, "channels": {"25": 1}, "radios": [],
            "networks": [{"ext_pan": "dd:a1:7c:33:90:5e:12:08", "pan": 0x4E20, "channel": 25, "name": name, "version": 2,
                          "joining": joining, "native": False, "rssi": -80, "lqi": 90}]}


def test_a_thread_network_is_stored_with_its_name_and_raises_an_event(ctx):  # noqa: F811
    feed(ctx, thread_obs(time.time()))
    row = ctx.one("SELECT protocol, name, version, permit_join, stack_profile FROM zigbee_networks WHERE pan=?", (0x4E20,))
    assert (row["protocol"], row["name"], row["version"], row["permit_join"], row["stack_profile"]) == ("thread", "OpenThread-4e20", 2, 0, None)
    ev = ctx.one("SELECT detail FROM events WHERE type='zigbee_new_network'")
    assert "Thread network “OpenThread-4e20”" in ev["detail"] and "0x4e20" in ev["detail"]
    nets = [n for n in ctx_api(ctx)["networks"] if n["pan"] == 0x4E20]
    assert nets[0]["protocol"] == "thread" and nets[0]["name"] == "OpenThread-4e20"


def ctx_api(ctx):
    from tests.test_zigbee import api
    return api(ctx).json()


def test_a_thread_network_accepting_new_devices_is_reported(ctx):  # noqa: F811
    now = time.time()
    feed(ctx, thread_obs(now, joining=True))
    ev = ctx.one("SELECT detail FROM events WHERE type='zigbee_permit_join'")
    assert "Thread network “OpenThread-4e20”" in ev["detail"] and "accepting new devices" in ev["detail"]


def test_a_zigbee_network_is_still_a_zigbee_network(ctx):  # noqa: F811
    feed(ctx, {"t": "zb_network", "ts": time.time(), "mac": "-", "ext_pan": "00:12:4b:00:1e:a0:44:01", "pan": 0x1A62, "channel": 15, "permit_join": False,
               "stack_profile": 2, "update_id": 0, "lqi": 200, "rssi": -50, "routers": []})
    row = ctx.one("SELECT protocol, name FROM zigbee_networks WHERE pan=?", (0x1A62,))
    assert row["protocol"] == "zigbee" and row["name"] is None
    assert "New Zigbee network" in ctx.one("SELECT detail FROM events WHERE type='zigbee_new_network'")["detail"]


def test_a_database_from_before_thread_gets_the_new_columns(ctx):  # noqa: F811
    c = ctx.store.conn
    c.execute("DROP TABLE zigbee_networks")
    c.execute("CREATE TABLE zigbee_networks(ext_pan TEXT NOT NULL, pan INTEGER NOT NULL, channel INTEGER NOT NULL, permit_join INTEGER, stack_profile INTEGER, "
              "update_id INTEGER, lqi INTEGER, rssi INTEGER, routers TEXT, vendor TEXT, first_seen REAL, last_seen REAL, sightings INTEGER DEFAULT 0, "
              "PRIMARY KEY(ext_pan, pan, channel)) WITHOUT ROWID")
    c.execute("INSERT INTO zigbee_networks(ext_pan, pan, channel, first_seen, last_seen) VALUES('aa:bb:cc:dd:ee:ff:00:11', 1, 11, 1, 1)")
    ZigbeeMonitor(ctx)
    row = ctx.one("SELECT protocol, name, version FROM zigbee_networks WHERE pan=1")
    assert row["protocol"] == "zigbee" and row["name"] is None and row["version"] is None


# ------------------------------------------------------------------ remote sensors
def test_a_remote_sensor_can_report_thread_networks_and_junk_is_dropped():
    good = thread_obs(time.time())
    good["networks"] += [{"ext_pan": "not an eui", "pan": 1, "channel": 15}, {"ext_pan": "aa:bb:cc:dd:ee:ff:00:11", "pan": 70000, "channel": 15},
                         {"ext_pan": "aa:bb:cc:dd:ee:ff:00:11", "pan": 5, "channel": 40}, "junk",
                         {"ext_pan": "aa:bb:cc:dd:ee:ff:00:11", "pan": 6, "channel": 15, "name": "x\x07y" * 20, "version": 99}]
    r = remote_observation(good, time.time())
    assert r["t"] == "zb_frames" and [n["pan"] for n in r["networks"]] == [0x4E20, 6]
    assert r["networks"][0]["name"] == "OpenThread-4e20" and r["networks"][0]["joining"] is False
    assert len(r["networks"][1]["name"]) <= 16 and "\x07" not in r["networks"][1]["name"] and "version" not in r["networks"][1]
    none = remote_observation({**good, "networks": "nope"}, time.time())
    assert "networks" not in none
