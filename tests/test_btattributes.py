"""Passive Bluetooth LE attributes: flags, 32/128-bit UUIDs, connection interval, iBeacon, advertising interval."""
import random

from sniffowireless.bluetooth import AdvInterval, parse_ad, parse_event, uuid_label

NUS = bytes.fromhex("6e400001b5a3f393e0a9e50e24dcca9e")


def test_flags_and_connection_interval():
    ad = parse_ad(bytes([2, 1, 6]) + bytes([5, 0x12, 24, 0, 40, 0]))
    assert ad["flags"] == 6
    assert ad["conn_interval"] == [30.0, 50.0]


def test_nonsense_connection_interval_is_ignored():
    assert "conn_interval" not in parse_ad(bytes([5, 0x12, 0xFF, 0xFF, 0xFF, 0xFF]))  # "no preference"


def test_128_bit_and_32_bit_uuids():
    ad = parse_ad(bytes([17, 7]) + NUS[::-1] + bytes([3, 3, 0x0F, 0x18]) + bytes([5, 5, 0x78, 0x56, 0x34, 0x12]))
    assert set(ad["uuids"]) == {"180f", "6e400001-b5a3-f393-e0a9-e50e24dcca9e", "12345678"}
    assert ad["uuids"][0] == "180f"  # short standard ones first


def test_a_128_bit_uuid_on_the_bluetooth_base_is_shortened():
    base = bytes.fromhex("0000180f00001000800000805f9b34fb")
    assert uuid_label(base) == "180f"
    assert uuid_label(bytes.fromhex("0000fff000001000800000805f9b34fb")) == "fff0"


def test_ibeacon():
    ib = bytes([0x4C, 0, 2, 0x15]) + bytes(range(16)) + bytes([1, 2, 3, 4, 0xC5])
    ad = parse_ad(bytes([len(ib) + 1, 0xFF]) + ib)
    assert ad["ibeacon"] == {"uuid": "00010203-0405-0607-0809-0a0b0c0d0e0f", "major": 258, "minor": 772, "power": -59}


def test_apple_data_that_is_not_a_beacon_is_not_one():
    ib = bytes([0x4C, 0, 0x10, 5, 1, 2, 3, 4, 5])
    assert "ibeacon" not in parse_ad(bytes([len(ib) + 1, 0xFF]) + ib)


def test_a_truncated_ad_does_not_raise():
    for ad in (bytes([5, 6, 1, 2]), bytes([3, 0x12, 1, 2]), bytes([2, 1])):
        parse_ad(ad)


def test_advertising_interval_estimate_survives_missed_packets():
    rnd = random.Random(3)
    a, t, r = AdvInterval(), 0.0, None
    for i in range(60):
        t += 0.1 + rnd.uniform(-0.004, 0.004) + (0.2 if i % 7 == 0 else 0)  # every 7th gap includes missed packets
        r = a.update("m", t)
    assert r == 100


def test_no_estimate_before_enough_samples_or_for_slow_senders():
    a = AdvInterval()
    assert all(a.update("m", i * 0.1) is None for i in range(5))
    s = AdvInterval()
    assert all(s.update("m", i * 30.0) is None for i in range(30))  # gaps beyond the plausible range


def test_scan_responses_are_flagged_in_the_event_parser():
    # LE advertising report, evt_type 4 = scan response
    data = bytes([2, 1, 6])
    rep = bytes([0x02, 1, 4, 0]) + bytes(6) + bytes([len(data)]) + data + bytes([0xC0])
    ev = parse_event(bytes([0x04, 0x3E, len(rep)]) + rep)
    assert ev and ev[0]["srsp"] is True
