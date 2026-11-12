"""Identification added in release 32: Bluetooth (Find My kinds, Xiaomi sensors, health and hearing services, pairing beacons),
Wi-Fi (Wi-Fi Direct device info, iPhone hotspots, access point makers) and 802.15.4 (join requests, Thread routers, Green Power)."""
import struct

from sniffowireless import identify, sanitize, trackers
from sniffowireless import zigbee as zb
from sniffowireless import zigbee_radio as zr
from sniffowireless.bluetooth import parse_ad

EUI = "00:17:88:01:0b:a2:3c:de"


def cap(data, ch=15):
    return {"channel": ch, "data": data, "rssi": -60, "lqi": 150}


def raw_eui(e):
    return bytes.fromhex(e.replace(":", ""))[::-1]


# ------------------------------------------------------------------ 802.15.4
def assoc_request(caps, parent=0x0000, pan=0x1A62, src=EUI):
    """Association request: command frame, short destination, 64-bit source with its own (broadcast) PAN."""
    return struct.pack("<HBHHH", 0xC823, 3, pan, parent, 0xFFFF) + raw_eui(src) + bytes([1, caps])


def mle_advertisement(src=EUI, pan=0x1A62, to=1):
    return struct.pack("<HBHH", 0xC841, 5, pan, 0xFFFF) + raw_eui(src) + bytes.fromhex(f"7f3b{to:02x}f04d4c4d4c") + b"\x12\x34\x00" + b"\xaa" * 20


def green_power(src_id, command, level=2, pan=0xFFFF, to_device=False):
    ext = (level << 3) | (0x80 if to_device else 0)
    body = bytes([0x8C, ext]) + struct.pack("<I", src_id) + (struct.pack("<I", 7) if level >= 2 else b"") + bytes([command]) + b"\xbb" * 4
    return struct.pack("<HBHH", 0x0801, 9, pan, 0xFFFF) + body


def details(batch):
    o = batch.drain(1)
    got = {a: [r, e, None] for p, a, r, e in o.get("detail") or []}
    for p, a, r, c in o.get("more") or []:
        got.setdefault(a, [0, None, None])
        got[a][0] |= r
        got[a][2] = c
    return o, got


def test_join_request_tells_power_and_sleep_and_marks_the_parent():
    b = zr.FrameBatch()
    b.add(cap(assoc_request(0x8E)))                                   # mains, always listening, can route
    b.add(cap(assoc_request(0x80, src="00:15:8d:00:01:02:03:04")))     # battery, sleeps
    o, got = details(b)
    assert got[EUI][2] == 0x8E and got["00:15:8d:00:01:02:03:04"][2] == 0x80
    assert zr.role_of(got["0x0000"][0]) == "router"
    assert zr.capability_labels(0x8E)[:2] == ["mains powered", "always listening"]
    assert zr.capability_labels(0x80)[:2] == ["battery powered", "sleeps between messages"]
    assert zr.capability_labels(None) == []
    # an ordinary command (a poll) is not a join request
    assert zr.parse_assoc(zr.parse_mac(struct.pack("<HBHHH", 0x8843, 9, 0x1A62, 1, 2) + b"\x04")) is None


def test_thread_router_is_recognised_by_its_mle_advertisements():
    b = zr.FrameBatch()
    b.add(cap(mle_advertisement()))
    o, got = details(b)
    assert got[EUI][0] & zr.ROLE_MLE_ROUTER and zr.role_of(got[EUI][0]) == "router"
    assert next(r for r in o["radios"] if r[1] == EUI)[6] == zr.HINT_THREAD
    # MLE to all routers (a child looking for a parent) is not an advertisement
    b.add(cap(mle_advertisement(to=2)))
    assert "more" not in b.drain(2)


def test_green_power_switch_is_found_by_its_source_id():
    b = zr.FrameBatch()
    b.add(cap(green_power(0x01A2B3C4, 0x22)))       # toggle
    o, got = details(b)
    addr = "gpd:01a2b3c4"
    assert got[addr][0] & zr.ROLE_GREEN_POWER and got[addr][0] & zr.ROLE_GP_SWITCH
    assert zr.role_of(got[addr][0]) == "green power"
    radio = next(r for r in o["radios"] if r[1] == addr)
    assert radio[0] == -1 and radio[3] == 1 and radio[6] == zr.HINT_ZIGBEE
    # an encrypted command (security level 3) still shows the device, not what it sent
    b.add(cap(green_power(0x000000AA, 0x22, level=3)))
    _, got = details(b)
    assert got["gpd:000000aa"][0] & zr.ROLE_GREEN_POWER and not got["gpd:000000aa"][0] & zr.ROLE_GP_SWITCH
    # frames towards a device, and ordinary Zigbee frames, are not Green Power devices
    b.add(cap(green_power(0x000000BB, 0x22, to_device=True)))
    assert not any(r[1].startswith("gpd:") for r in b.drain(3)["radios"])
    assert zr.parse_gp(struct.pack("<HHHBB", 0x0008, 0, 1, 5, 1) + b"\xaa" * 8) is None


def test_new_roles_travel_apart_so_older_servers_keep_working():
    b = zr.FrameBatch()
    b.add(cap(mle_advertisement()))
    o = b.drain(1)
    assert all(r[2] <= 31 for r in o.get("detail") or [])
    clean = sanitize.remote_observation({**o, "t": "zb_frames"}, 100)
    assert clean["more"] == [[0x1A62, EUI, zr.ROLE_MLE_ROUTER, None]]
    bad = {"t": "zb_frames", "ts": 1, "channels": {"15": 1}, "radios": [[-1, "gpd:01a2b3c4", 1 << 15, 1, 0, 0, 3, 2, -60, 150], [-1, "gpd:xyz", 1 << 15, 1, 0, 0, 3, 2, -60, 150]],
           "more": [[-1, "gpd:01a2b3c4", 64 | 128, None], [1, "0x0001", 7, 300], [1, "junk", 64, 1], [1, "0x0002", 10 ** 9, 1]]}
    clean = sanitize.remote_observation(bad, 100)
    assert [r[1] for r in clean["radios"]] == ["gpd:01a2b3c4"]
    assert clean["more"] == [[-1, "gpd:01a2b3c4", 192, None], [1, "0x0001", 0, None]]


def test_device_guess_in_words():
    assert zb.device_guess("gpd:01a2b3c4", zr.ROLE_GREEN_POWER | zr.ROLE_GP_SWITCH, None, "zigbee").startswith("Battery-less switch")
    assert zb.device_guess("0x0000", zr.ROLE_PARENT, None, "zigbee").startswith("Coordinator")
    assert zb.device_guess("0x0000", zr.ROLE_PARENT, None, "thread").startswith("Thread router")   # Thread has no fixed coordinator address
    assert zb.device_guess(EUI, 0, 0x8E, "zigbee").startswith("Mains-powered")
    assert "sleeps" in zb.device_guess(EUI, 0, 0x80, "zigbee")
    assert zb.device_guess("0x1234", zr.ROLE_POLLS, None, "zigbee").startswith("Sleepy end device")
    assert zb.device_guess("0x1234", zr.ROLE_RELAYS, None, "zigbee").startswith("Router")
    assert zb.device_guess("0x1234", 0, None, "unknown") is None


# ----------------------------------------------------------------- Bluetooth
def apple_ad(*messages):
    mfg = b"".join(bytes([t, len(p)]) + p for t, p in messages)
    return {"company_id": 0x004C, "mfg": mfg}


def ble(fp, **kw):
    return {"kind": "ble", "mac": "aa:bb:cc:dd:ee:01", "randomized": True, "extra": {"fp": {"ble": fp}}, **kw}


def test_find_my_status_tells_airtag_from_airpods_and_phones():
    def ident(status):
        return identify.identify(ble(identify.ble_fingerprint(apple_ad((0x12, bytes([status]) + b"\x00" * 24)))))
    tag = ident(0x10 | 0x80)   # AirTag, battery low
    assert tag["dev_type"] == "tag" and tag["model"] == "AirTag" and tag["brand"] == "Apple"
    assert "Battery low" in tag["ident"]["features"]
    pods = ident(0x30)
    assert pods["dev_type"] == "headphones" and pods["brand"] == "Apple"
    other = ident(0x20)
    assert other["dev_type"] == "tag" and other["model"] is None
    phone = ident(0x00)      # an Apple device that can be found: not a tracker tag
    assert phone["dev_type"] != "tag" and any("not a tag" in f for f in phone["ident"]["features"])


def test_tracker_names_follow_the_find_my_kind():
    def dev(kind):
        return {"extra": {"fp": {"ble": {"apple": [0x12], "findmy": {"kind": kind, "battery": 0}}}}}
    assert trackers.tracker_type(dev(1)) == "AirTag"
    assert trackers.tracker_type(dev(3)).startswith("AirPods")
    assert trackers.tracker_type({"extra": {"fp": {"ble": {"apple": [0x12]}}}}) == "AirTag / Find My"


def test_xiaomi_product_id_names_the_sensor():
    ad = parse_ad(bytes([7, 0x16, 0x95, 0xFE, 0x30, 0x58, 0x5B, 0x05]) + bytes([3, 0x03, 0x95, 0xFE]))
    assert ad["mi_product"] == 0x055B
    got = identify.identify(ble(identify.ble_fingerprint(ad)))
    assert got["brand"] == "Xiaomi" and got["dev_type"] == "sensor" and "LYWSD03MMC" in got["model"]
    unknown = identify.identify(ble(identify.ble_fingerprint({"mi_product": 0xFFFF, "uuids": ["fe95"]})))
    assert unknown["model"] is None


def test_services_name_health_devices_hearing_aids_and_locks():
    for uuid, typ in (("1810", "health"), ("181d", "health"), ("1854", "hearing_aid"), ("fdf0", "hearing_aid"), ("fe24", "lock"), ("fe33", "tag")):
        assert identify.identify(ble({"uuids": [uuid]}))["dev_type"] == typ, uuid
    for typ in ("health", "hearing_aid", "lock", "switch"):
        assert typ in identify.TYPE_LABELS


def test_pairing_beacons_and_dual_mode_show_as_features():
    fp = identify.ble_fingerprint({"company_id": 0x0006, "mfg": bytes([0x03, 0x00, 0x80]) + b"Mouse", "flags": 0x1A})
    assert fp["swift_pair"] and fp["dual"]
    feats = identify.identify(ble(fp))["ident"]["features"]
    assert any("Swift Pair" in f for f in feats) and any("classic" in f for f in feats)
    ad = parse_ad(bytes([6, 0x16, 0x2C, 0xFE, 0xAA, 0xBB, 0xCC]))
    assert ad["fast_pair"] == "aabbcc"
    assert any("aabbcc" in f for f in identify.identify(ble(identify.ble_fingerprint(ad)))["ident"]["features"])
    # the account-key form of Fast Pair (longer) carries no model
    assert "fast_pair" not in parse_ad(bytes([8, 0x16, 0x2C, 0xFE, 0x00, 0x11, 0x22, 0x33, 0x44]))
    assert "dual" not in identify.ble_fingerprint({"flags": 0x06})   # LE only


# --------------------------------------------------------------------- Wi-Fi
def p2p_element(name, category, sub):
    info = b"\x02\x00\x00\x00\x00\x01" + b"\x01\x88" + struct.pack(">H", category) + b"\x00\x50\xf2\x04" + struct.pack(">H", sub) + b"\x00"
    info += struct.pack(">HH", 0x1011, len(name)) + name.encode()
    attrs = bytes([2, 2, 0, 0x25, 0x00]) + bytes([13]) + struct.pack("<H", len(info)) + info
    return (221, bytes.fromhex("506f9a09") + attrs)


def test_wifi_direct_device_info_gives_name_and_category():
    fp = identify.wifi_fingerprint([p2p_element("OfficeJet Pro 9010", 3, 1)])
    assert fp["p2p"] == {"category": 3, "subcategory": 1, "name": "OfficeJet Pro 9010"}
    got = identify.identify({"kind": "wifi_client", "mac": "02:00:00:00:00:01", "randomized": True, "extra": {"fp": {"wifi": fp}}})
    assert got["dev_type"] == "printer"
    assert any(e["field"] == "name" and e["value"] == "OfficeJet Pro 9010" for e in got["ident"]["evidence"])
    # truncated and foreign attributes do not crash or invent anything
    assert identify.parse_p2p(b"\x0d\xff\xff\x00") is None and identify.parse_p2p(b"") is None
    assert "p2p" not in identify.wifi_fingerprint([(221, bytes.fromhex("506f9a09") + bytes([2, 2, 0, 0x25, 0x00]))])
    merged = identify.merge_wifi({"p2p": {"category": 3}}, {"p2p": {"name": "x"}})
    assert merged["p2p"] == {"category": 3, "name": "x"}


def test_apple_access_point_on_a_private_address_is_a_personal_hotspot():
    fp = {"vendors": ["00:17:f2"], "gen": 6}
    hot = identify.identify({"kind": "ap", "mac": "02:11:22:33:44:55", "randomized": True, "ssid": "Home", "extra": {"fp": {"wifi": fp}}})
    assert hot["dev_type"] == "hotspot" and hot["os"] == "iOS" and hot["brand"] == "Apple"
    fixed = identify.identify({"kind": "ap", "mac": "00:11:22:33:44:55", "randomized": False, "ssid": "Home", "extra": {"fp": {"wifi": fp}}})
    assert fixed["dev_type"] == "router"


def test_access_point_maker_from_its_vendor_element():
    def ap(oui, kind="ap"):
        return identify.identify({"kind": kind, "mac": "02:11:22:33:44:55", "randomized": True, "ssid": "x", "extra": {"fp": {"wifi": {"vendors": [oui], "gen": 5}}}})
    assert ap("00:04:0e")["brand"] == "AVM (FRITZ!Box)" and ap("00:18:0a")["brand"] == "Cisco Meraki" and ap("00:0c:42")["brand"] == "MikroTik"
    assert ap("00:04:0e", "wifi_client")["brand"] is None   # only an access point's own beacons say who made it


def test_join_capabilities_and_green_power_reach_the_zigbee_page(tmp_path):
    import time

    from fastapi.testclient import TestClient

    from sniffowireless.config import Config
    from sniffowireless.main import build
    from sniffowireless.web import create_app
    ctx = build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))
    b = zr.FrameBatch()
    b.add(cap(assoc_request(0x80)))
    b.add(cap(green_power(0x01A2B3C4, 0x21)))
    b.add(cap(mle_advertisement(src="3a:11:22:33:44:55:66:77")))
    ctx.store.process(b.drain(time.time() - 5))
    ctx.store.flush()
    ctx.auth.disabled = True
    c = TestClient(create_app(ctx), base_url="http://sniffowireless.test")
    radios = {r["addr"]: r for r in c.get("/api/zigbee").json()["radios"]}
    assert radios[EUI]["power"][:2] == ["battery powered", "sleeps between messages"] and "sleeps" in radios[EUI]["device"]
    gp = radios["gpd:01a2b3c4"]
    assert gp["role"] == "green power" and gp["device"].startswith("Battery-less switch") and gp["vendor"] is None and gp["pan"] is None
    assert radios["3a:11:22:33:44:55:66:77"]["role"] == "router" and radios["3a:11:22:33:44:55:66:77"]["device"].startswith("Thread router")
    assert "caps" in c.get("/api/export/zigbee-radios.csv").text.splitlines()[0]
