"""Zigbee / Thread roles and 64-bit addresses learned from headers (the payloads stay encrypted)."""
import struct

from sniffowireless import zigbee_radio as zr


def mac_data(src, dst, payload, pan=0x1A62, secured=False):
    """A 2006 802.15.4 data frame with short addresses, built by hand."""
    fc = 0x8841 | (0x08 if secured else 0)   # data, PAN ID compression, short dst and src
    return struct.pack("<HBHHH", fc, 7, pan, dst, src) + payload


def nwk(src, dst, radius=5, eui=None, via_security=True):
    fc = 0x0008 | (0x0200 if eui and via_security else 0)   # data frame, protocol version 2, security
    body = struct.pack("<HHHBB", fc, dst, src, radius, 1)
    if eui:
        raw = bytes.fromhex(eui.replace(":", ""))[::-1]
        body += bytes([0x2D]) + struct.pack("<I", 1) + raw + b"\x00" + b"\xaa" * 8   # control, counter, extended source, key sequence, encrypted payload
    else:
        body += b"\xaa" * 8
    return body


def cap(data, ch=15):
    return {"channel": ch, "data": data, "rssi": -60, "lqi": 150}


def test_nwk_header_gives_the_senders_64_bit_address():
    n = zr.parse_nwk(nwk(0x1234, 0x0000, eui="00:17:88:01:0b:a2:3c:de"))
    assert n["src"] == 0x1234 and n["dst"] == 0 and n["eui"] == "00:17:88:01:0b:a2:3c:de"
    assert zr.parse_nwk(b"\x00" * 4) is None and zr.parse_nwk(b"\x41\x88" + b"\x00" * 10) is None   # too short / not Zigbee


def test_relaying_marks_a_router_and_the_originator_gets_its_address():
    b = zr.FrameBatch()
    b.add(cap(mac_data(src=0x0001, dst=0x0000, payload=nwk(0x1234, 0x0000, eui="00:17:88:01:0b:a2:3c:de"))))   # 0x0001 forwards 0x1234's frame
    d = b.drain(1)["detail"]
    got = {(p, a): (r, e) for p, a, r, e in d}
    assert got[(0x1A62, "0x0001")][0] & zr.ROLE_RELAYS
    assert got[(0x1A62, "0x1234")][1] == "00:17:88:01:0b:a2:3c:de"
    assert zr.role_of(got[(0x1A62, "0x0001")][0]) == "router"


def test_a_frame_that_is_not_relayed_does_not_mark_a_router():
    b = zr.FrameBatch()
    b.add(cap(mac_data(src=0x0042, dst=0x0000, payload=nwk(0x0042, 0x0000))))
    assert "detail" not in b.drain(1)


def test_broadcast_to_all_routers_marks_the_sender():
    b = zr.FrameBatch()
    b.add(cap(mac_data(src=0x0007, dst=0xFFFF, payload=nwk(0x0007, 0xFFFC))))
    d = b.drain(1)["detail"]
    assert zr.role_of(d[0][2]) == "router"


def command_frame(src, dst, payload, pan=0x1A62):
    fc = 0x8843
    return struct.pack("<HBHHH", fc, 9, pan, dst, src) + payload


def test_polling_marks_an_end_device_and_its_parent():
    b = zr.FrameBatch()
    b.add(cap(command_frame(src=0x00AA, dst=0x0001, payload=b"\x04")))
    got = {a: r for p, a, r, e in b.drain(1)["detail"]}
    assert zr.role_of(got["0x00aa"]) == "end device" and zr.role_of(got["0x0001"]) == "router"


def test_sanitizer_accepts_detail_and_drops_bad_rows():
    from sniffowireless import sanitize
    o = {"t": "zb_frames", "ts": 1, "channels": {"15": 1}, "radios": [],
         "detail": [[6754, "0x0001", 4, "00:17:88:01:0b:a2:3c:de"], [6754, "0x0002", 99, None], [6754, "junk", 1, None], [1, "0x0003", 1, "nope"]]}
    r = sanitize.remote_observation(o, 100)
    assert r["detail"] == [[6754, "0x0001", 4, "00:17:88:01:0b:a2:3c:de"], [1, "0x0003", 1, None]]


# ------------------------------------------------------------------ Thread border routers (mDNS) and Matter (Bluetooth)
def test_meshcop_txt_gives_network_name_extended_pan_and_maker():
    from sniffowireless import ethernet
    raw = ethernet._txt_raw([b"nn=MyHome", b"xp=" + bytes.fromhex("dead00beef00cafe"), b"vn=Apple Inc.", b"mn=HomePod mini", b"tv=1.3.0", b"sb=\x00\x00"])
    assert ethernet.meshcop(raw) == {"xp": "de:ad:00:be:ef:00:ca:fe", "nn": "MyHome", "vn": "Apple Inc.", "mn": "HomePod mini", "tv": "1.3.0"}
    assert ethernet.meshcop({"nn": b"x", "xp": b"short"}) == {}


def test_border_router_names_its_maker_as_evidence():
    from sniffowireless import identify
    ev = identify.Evidence()
    identify.lan_evidence(ev, {"mdns": {"services": ["_meshcop._udp"], "meshcop": {"xp": "de:ad:00:be:ef:00:ca:fe", "vn": "Apple Inc.", "mn": "HomePod mini"}}}, {})
    assert ev.resolve("model")["value"] == "HomePod mini" and ev.resolve("brand")["value"] == "Apple Inc."
    assert ev.resolve("type")["value"] == "router"


def test_matter_commissioning_advert_is_decoded():
    from sniffowireless import bluetooth, identify
    v = bytes([0xF6, 0xFF, 0x00, 0x34, 0x12 | 0x00, 0x49, 0x13, 0x01, 0x00, 0x00])   # UUID, opcode, discriminator+version, vendor 0x1349, product 1
    out = bluetooth.parse_ad(bytes([len(v) + 1, 0x16]) + v)
    assert out["matter"] == {"discriminator": 0x234, "vendor": 0x1349, "product": 1}
    res = identify.identify({"mac": "aa:bb:cc:dd:ee:ff", "kind": "ble", "extra": {"matter": out["matter"]}})
    assert res["dev_type"] == "smart_home"


def test_radio_roles_and_address_are_stored_and_listed(tmp_path):
    from sniffowireless.config import Config
    from sniffowireless.oui import VendorLookup
    from sniffowireless.store import Store
    from sniffowireless.zigbee import ZigbeeMonitor

    class Ctx:
        pass
    s = Store(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)), VendorLookup(None))
    ctx = Ctx()
    ctx.store = s
    s.vendors = type("V", (), {"lookup": lambda self, a: "Philips Lighting" if a.startswith("00:17:88") else None})()   # the real table needs the OUI file
    mon = ZigbeeMonitor(ctx)
    radios = [[0x1A62, "0x0001", 1 << 15, 4, 0, 0, 3, 1, -70, 150], [0x1A62, "0x1234", 1 << 15, 2, 0, 0, 3, 1, -70, 150]]
    mon._frames(s, {"ts": 1000.0, "channels": {"15": 6}, "radios": radios,
                    "detail": [[0x1A62, "0x0001", 4, None], [0x1A62, "0x1234", 0, "00:17:88:01:0b:a2:3c:de"]]})
    r = mon.radios
    assert r[(0x1A62, "0x1234")]["vendor"] == "Philips Lighting" and r[(0x1A62, "0x0001")]["vendor"] is None   # a short address names nobody; its 64-bit address does
    assert r[(0x1A62, "0x0001")]["roles"] == 4 and r[(0x1A62, "0x1234")]["eui"] == "00:17:88:01:0b:a2:3c:de"
    c = s.conn
    mon.flush(s, c)
    row = c.execute("SELECT roles, eui FROM zigbee_radios WHERE addr='0x1234'").fetchone()
    assert row["eui"] == "00:17:88:01:0b:a2:3c:de"
