import time

from scapy.layers.dot11 import (Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11ProbeReq, RadioTap)

from sniffowireless.bluetooth import parse_ad, parse_event
from sniffowireless.config import Config, chan_label, parse_channels
from sniffowireless.oui import VendorLookup
from sniffowireless.store import Store
from sniffowireless.wifi import assign_channels, parse_frame

AP = "24:a4:3c:10:00:01"
CL = "a4:83:e7:01:00:01"


def frame(pkt, ts=1000.0):
    pkt = RadioTap(present="dBm_AntSignal", dBm_AntSignal=-50) / pkt
    pkt = pkt.__class__(bytes(pkt))
    pkt.time = ts
    return pkt


def test_parse_channels():
    assert parse_channels("1,6,11") == [2412, 2437, 2462]
    assert parse_channels("1-3,36") == [2412, 2417, 2422, 5180]
    assert parse_channels("36-48") == [5180, 5200, 5220, 5240]
    assert parse_channels("6g:1,6g:37") == [5955, 6135]
    assert parse_channels("6g:1-13") == [5955, 5975, 5995, 6015]
    assert parse_channels("6") == parse_channels("6ghz") and 5975 in parse_channels("6")  # PSC 5
    assert 5825 in parse_channels("all") and 6135 in parse_channels("all")
    assert [chan_label(f) for f in parse_channels("1,36,6g:37")] == ["1", "36", "6G:37"]


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("WIFI_INTERFACES", "wlan1,wlan2")
    monkeypatch.setenv("WIFI_CHANNELS", "1,6g:37")
    monkeypatch.setenv("WIFI_CHANNELS_wlan2", "6")
    monkeypatch.setenv("WIFI_REGDOMAIN", "nl")
    cfg = Config.from_env()
    assert cfg.wifi_interfaces == ["wlan1", "wlan2"] and cfg.wifi_channels == [2412, 6135]
    assert cfg.wifi_channels_per_iface["wlan2"] == parse_channels("6ghz") and cfg.wifi_regdomain == "NL"


def test_assign_channels():
    freqs = parse_channels("1,6,36,6g:5,6g:21")
    plan = assign_channels(freqs, ["a", "b"], {"a": {2412, 2437}, "b": None})
    assert set(plan["a"]) <= {2412, 2437}
    assert {5180, 5975, 6055} <= set(plan["b"])
    assert sorted(plan["a"] + plan["b"]) == sorted(freqs)


def test_beacon():
    p = frame(Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=AP, addr3=AP)
              / Dot11Beacon(cap="ESS") / Dot11Elt(ID=0, info=b"HomeNet") / Dot11Elt(ID=3, info=b"\x06"))
    (o,) = parse_frame(p)
    assert o["t"] == "wifi_ap" and o["mac"] == AP and o["ssid"] == "HomeNet" and o["channel"] == 6
    assert o["rssi"] == -50


def test_beacon_6ghz():
    # 6 GHz beacons have no DS Parameter Set; channel comes from the radiotap frequency.
    p = RadioTap(present="Channel+dBm_AntSignal", ChannelFrequency=6135, dBm_AntSignal=-60) / \
        Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=AP, addr3=AP) / \
        Dot11Beacon(cap="ESS") / Dot11Elt(ID=0, info=b"HomeNet")
    p = RadioTap(bytes(p))
    p.time = 1000.0
    (o,) = parse_frame(p)
    assert (o["channel"], o["band"], o["freq"]) == (37, "6", 6135)


def test_data_to_ds():
    p = frame(Dot11(type=2, subtype=0, FCfield="to-DS", addr1=AP, addr2=CL, addr3="ff:ff:ff:ff:ff:ff"))
    obs = parse_frame(p)
    client = [o for o in obs if o["t"] == "wifi_client"][0]
    assert client["mac"] == CL and client["bssid"] == AP and client["frame"] == "data"


def test_probe_and_deauth():
    p = frame(Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=CL, addr3="ff:ff:ff:ff:ff:ff")
              / Dot11ProbeReq() / Dot11Elt(ID=0, info=b"eduroam"))
    assert parse_frame(p)[0]["probe"] == "eduroam"
    p = frame(Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=AP, addr3=AP) / Dot11Deauth(reason=7))
    assert any(o["t"] == "event" and o["type"] == "deauth_broadcast" for o in parse_frame(p))


def test_ble_adv_parse():
    ad = bytes([2, 0x01, 0x06, 5, 0x09]) + b"Tile" + bytes([3, 0xFF, 0xED, 0x00])
    addr = bytes([1, 2, 3, 4, 5, 0xC6])
    params = bytes([0x02, 1, 0x00, 0x01]) + addr + bytes([len(ad)]) + ad + bytes([0xC4])  # rssi -60
    pkt = bytes([0x04, 0x3E, len(params)]) + params
    (ev,) = parse_event(pkt)
    assert ev["mac"] == "c6:05:04:03:02:01" and ev["rssi"] == -60
    assert ev["ad"]["name"] == "Tile" and ev["ad"]["company_id"] == 0x00ED
    assert parse_ad(b"") == {}


def test_store_sessions(tmp_path):
    cfg = Config(db_path=str(tmp_path / "t.db"), wifi_session_timeout=300)
    s = Store(cfg, VendorLookup(None))
    t0 = time.time() - 3600
    s.process({"t": "wifi_ap", "ts": t0, "mac": AP, "ssid": "HomeNet", "rssi": -40})
    for i in range(10):
        s.process({"t": "wifi_client", "ts": t0 + i * 30, "mac": CL, "bssid": AP, "frame": "data", "rssi": -55})
    s.sweep(t0 + 300)
    assert CL in s.assoc
    s.sweep(t0 + 1000)  # client silent > timeout
    assert CL not in s.assoc and CL not in s.presence
    s.flush()
    rows = s.conn.execute("SELECT type, peer, end_ts - start_ts d, open FROM sessions WHERE mac=?", (CL,)).fetchall()
    assert {(r["type"], r["peer"], r["open"]) for r in rows} == {("presence", None, 0), ("assoc", AP, 0)}
    assert all(abs(r["d"] - 270) < 1 for r in rows)
    types = [r[0] for r in s.conn.execute("SELECT type FROM events WHERE mac=? ORDER BY id", (CL,))]
    assert types == ["new_device", "connected", "disconnected", "left"]
    n = s.conn.execute("SELECT COUNT(*) FROM samples WHERE mac=?", (CL,)).fetchone()[0]
    assert n >= 4


def test_store_roam(tmp_path):
    s = Store(Config(db_path=str(tmp_path / "t.db")), VendorLookup(None))
    ap2 = "24:a4:3c:10:00:02"
    s.process({"t": "wifi_client", "ts": 100, "mac": CL, "bssid": AP, "frame": "data"})
    s.process({"t": "wifi_client", "ts": 160, "mac": CL, "bssid": ap2, "frame": "data"})
    s.process({"t": "wifi_client", "ts": 170, "mac": CL, "bssid": ap2, "frame": "deauth", "reason": 3})
    s.flush()
    types = [r[0] for r in s.conn.execute("SELECT type FROM events WHERE mac=? ORDER BY id", (CL,))]
    assert types == ["new_device", "connected", "roamed", "disconnected"]


def test_band_migration(tmp_path):
    import sqlite3
    db = str(tmp_path / "old.db")
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE devices(mac TEXT PRIMARY KEY, kind TEXT NOT NULL, first_seen REAL, last_seen REAL, "
              "vendor TEXT, name TEXT, ssid TEXT, channel INTEGER, freq INTEGER, enc TEXT, bssid TEXT, "
              "randomized INTEGER DEFAULT 0, packets INTEGER DEFAULT 0, last_rssi INTEGER, best_rssi INTEGER, extra TEXT)")
    c.execute("INSERT INTO devices(mac, kind, channel, freq) VALUES (?, 'ap', 37, 6135), (?, 'ap', 36, NULL)", (AP, CL))
    c.commit()
    c.close()
    s = Store(Config(db_path=db), VendorLookup(None))
    bands = dict(s.conn.execute("SELECT mac, band FROM devices").fetchall())
    assert bands == {AP: "6", CL: "5"}


# ---------------------------------------------------------------- identification
from sniffowireless.identify import ble_fingerprint, identify, wifi_fingerprint  # noqa: E402


def _ht(ss, w40=True):
    return (45, (2 if w40 else 0).to_bytes(2, "little") + b"\x17" + bytes([0xFF] * ss + [0] * (16 - ss)) + bytes(7))


def _he(ss):
    m = sum((2 if i < ss else 3) << (2 * i) for i in range(8))
    return (255, bytes([35]) + bytes(6) + bytes([0x06]) + bytes(10) + m.to_bytes(2, "little"))


def test_wifi_fingerprint_caps_and_wps():
    wps = (bytes.fromhex("0050f204") + (0x1021).to_bytes(2, "big") + (2).to_bytes(2, "big") + b"HP"
           + (0x1023).to_bytes(2, "big") + (13).to_bytes(2, "big") + b"OfficeJet Pro"
           + (0x1054).to_bytes(2, "big") + (8).to_bytes(2, "big") + (3).to_bytes(2, "big") + bytes.fromhex("0050f204")
           + (1).to_bytes(2, "big"))
    fp = wifi_fingerprint([(1, b"\x82"), _ht(2), _he(2), (221, bytes.fromhex("0017f20a")), (221, wps)])
    assert fp["gen"] == 6 and fp["ss"] == 2 and fp["width"] == 80 and "00:17:f2" in fp["vendors"]
    assert fp["wps"] == {"manufacturer": "HP", "model": "OfficeJet Pro", "category": 3, "subcategory": 1}
    r = identify({"kind": "ap", "ssid": "DIRECT-4F-HP OfficeJet Pro", "extra": {"fp": {"wifi": fp}}})
    assert (r["brand"], r["dev_type"], r["wifi_gen"], r["era"]) == ("HP", "printer", 6, 2019)
    assert r["ident"]["label"] == "HP OfficeJet Pro · Printer"


def test_identify_legacy_and_6e():
    old = identify({"kind": "ap", "extra": {"fp": {"wifi": wifi_fingerprint([(1, b"\x82"), (50, b"\x0c")])}}})
    assert old["wifi_gen"] == 3 and old["era"] == 2003 and "2010" in old["ident"]["age_hint"]
    laptop = identify({"kind": "wifi_client", "name": "LAPTOP-AB12CD34", "extra": {"fp": {"wifi": wifi_fingerprint([_ht(2)])}}})
    assert laptop["ident"]["age_hint"].startswith("typically 2009–2016")
    iot = identify({"kind": "wifi_client", "vendor": "Espressif Inc.", "extra": {"fp": {"wifi": wifi_fingerprint([_ht(1)])}}})
    assert iot["ident"]["age_hint"].startswith("2009 or newer")
    six = identify({"kind": "wifi_client", "band": "6", "randomized": 1,
                    "extra": {"fp": {"wifi": wifi_fingerprint([_ht(2), _he(2)])}}})
    assert six["wifi_gen"] == 66 and six["era"] == 2021


def test_identify_ble_apple_and_cdp():
    ad = {"company_id": 0x004C, "mfg": bytes([0x07, 0x19, 0x01, 0x14, 0x20]) + bytes(23)}
    r = identify({"kind": "ble", "extra": {"fp": {"ble": ble_fingerprint(ad)}}})
    assert (r["model"], r["dev_type"], r["era"]) == ("AirPods Pro (2nd gen)", "headphones", 2022)
    ms = identify({"kind": "ble", "extra": {"fp": {"ble": ble_fingerprint({"company_id": 6, "mfg": bytes([1, 0x2F])})}}})
    assert (ms["dev_type"], ms["os"]) == ("laptop", "Windows")


def test_identify_names_and_cod():
    r = identify({"kind": "ble", "name": "Galaxy Watch5", "extra": {}})
    assert (r["brand"], r["dev_type"], r["model"]) == ("Samsung", "watch", "Galaxy Watch5")
    r = identify({"kind": "bt_classic", "name": "Car Multimedia", "extra": {"cod": "0x200420"}})
    assert r["dev_type"] == "car"
    r = identify({"kind": "wifi_client", "vendor": "Espressif Inc.", "extra": {}})
    assert (r["brand"], r["dev_type"]) == ("Espressif", "iot")


def test_store_identifies_and_hashes(tmp_path):
    s = Store(Config(db_path=str(tmp_path / "t.db")), VendorLookup(None))
    fp = wifi_fingerprint([(1, b"\x82"), _ht(2), _he(2), (221, bytes.fromhex("0017f20a"))])
    for mac in ("da:00:00:00:00:01", "da:00:00:00:00:02"):
        s.process({"t": "wifi_client", "ts": 100, "mac": mac, "frame": "probe", "fp": {"wifi": fp, "src": "probe"}})
    s.flush()
    rows = s.conn.execute("SELECT brand, dev_type, wifi_gen, fp_hash FROM devices").fetchall()
    assert len({r["fp_hash"] for r in rows}) == 1 and rows[0]["brand"] == "Apple" and rows[0]["dev_type"] == "phone"
    from sniffowireless.identify import IDENT_VERSION
    assert s.conn.execute("SELECT value FROM meta WHERE key='ident_version'").fetchone()[0] == str(IDENT_VERSION)


def test_bt_filter_size_and_extended_scan_fallback():
    import threading

    from sniffowireless.bluetooth import BluetoothSensor

    class FakeSock:
        def __init__(self):
            self.sent, self.opts = [], []

        def send(self, b):
            self.sent.append(b)

        def setsockopt(self, *a):
            self.opts.append(a)

    sensor = BluetoothSensor("hci0", Config(), None)
    sensor.sock = FakeSock()
    sensor.stop = threading.Event()
    sensor._start_le_scan()
    assert [b[1] | b[2] << 8 for b in sensor.sock.sent] == [0x200C, 0x200B, 0x200C]  # legacy first
    # controller answers "Command Disallowed" -> switch to LE extended scan commands
    sensor._handle({"ev": "cmd", "opcode": 0x200B, "status": 0x0C}, 0)
    assert sensor.ext_scan
    assert [b[1] | b[2] << 8 for b in sensor.sock.sent[3:]] == [0x2042, 0x2041, 0x2042]
    import inspect
    src = inspect.getsource(BluetoothSensor._open)
    assert '"<IIIH2x"' in src  # struct hci_ufilter must be 16 bytes on recent kernels


def test_beacon_csa_and_ht_primary():
    # 5 GHz beacon without DS Parameter Set: channel from HT Operation; CSA (IE 37) to channel 36 in 5 beacons.
    p = frame(Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=AP, addr3=AP)
              / Dot11Beacon(cap="ESS") / Dot11Elt(ID=0, info=b"Radar") / Dot11Elt(ID=37, info=bytes([1, 36, 5]))
              / Dot11Elt(ID=61, info=bytes([100]) + bytes(21)))
    (o,) = parse_frame(p)
    assert o["channel"] == 100 and o["csa"] == {"mode": 1, "new_channel": 36, "count": 5}
    p = frame(Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=AP, addr3=AP)
              / Dot11Beacon(cap="ESS") / Dot11Elt(ID=0, info=b"Radar") / Dot11Elt(ID=60, info=bytes([0, 115, 44, 3])))
    assert parse_frame(p)[0]["csa"] == {"mode": 0, "op_class": 115, "new_channel": 44, "count": 3}


def test_identify_bikes():
    r = identify({"kind": "ble", "name": "ES3-4F2A1C", "extra": {}})
    assert (r["brand"], r["dev_type"]) == ("VanMoof", "bike")
    r = identify({"kind": "ble", "name": None, "extra": {"appearance": "cycling sensor"}})
    assert r["dev_type"] == "bike"  # Bluetooth "Cycling" appearance is a bike, not a wearable
    r = identify({"kind": "ble", "extra": {"fp": {"ble": {"uuids": ["1816"]}}}})
    assert r["dev_type"] == "bike"
    assert identify({"kind": "ble", "name": "Cowboy 4", "extra": {}})["brand"] == "Cowboy"


def test_6ghz_mislabelled_by_driver():
    from sniffowireless.wifi import radio_freq

    def beacon(present, **rt):
        p = RadioTap(present=present, dBm_AntSignal=-60, **rt) / \
            Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=AP, addr3=AP) / \
            Dot11Beacon(cap="ESS") / Dot11Elt(ID=0, info=b"Six")
        p = RadioTap(bytes(p))
        p.time = 1000.0
        return p
    # driver puts 6 GHz channel 37 in the 5 GHz band (5185 MHz): the tuned frequency wins
    (o,) = parse_frame(beacon("Channel+dBm_AntSignal", ChannelFrequency=5185), tuned=6135)
    assert (o["band"], o["channel"], o["freq"], o["ssid"]) == ("6", 37, 6135, "Six")
    # no frequency in radiotap at all
    (o,) = parse_frame(beacon("dBm_AntSignal"), tuned=6135)
    assert (o["band"], o["channel"]) == ("6", 37)
    # a genuine frame from another channel (straggler after a hop) is left alone
    assert radio_freq(5180, 6135) == 5180 and radio_freq(6135, 6135) == 6135 and radio_freq(2437, None) == 2437


def test_regulatory_warning(monkeypatch):
    from sniffowireless import wifi
    out = "global\ncountry 00: DFS-UNSET\n\t(2402 - 2472 @ 40), (6, 20), (N/A)\n\nphy#1\ncountry US: DFS-FCC\n"
    monkeypatch.setattr(wifi, "run_cmd", lambda *a: (0, out))
    assert wifi.global_regdomain() == "00"
    w = wifi.regulatory_warning("00", "NL", True)
    assert "still 00" in w and "wireless-regdb" in w
    assert "Set WIFI_REGDOMAIN" in wifi.regulatory_warning("00", "", True)
    assert wifi.regulatory_warning("00", "NL", False) is None  # no 6 GHz configured: nothing to warn about
    assert wifi.regulatory_warning("NL", "NL", True) is None
    assert "was not applied" in wifi.regulatory_warning("US", "NL", True)


# ------------------------------------------------------------------ handshake capture
def eapol_frame(ack, mic, secure, src, dst, ts=1000.0):
    """A synthetic EAPOL-Key Data frame, like a real WPA 4-way-handshake message."""
    import struct

    from scapy.layers.eap import EAPOL
    from scapy.all import LLC, SNAP, Raw

    ki = (2 << 0) | (1 << 3) | (ack << 7) | (mic << 8) | (secure << 9)
    body = struct.pack(">B H H 8s 32s 16s 8s 8s 16s H", 2, ki, 0, b"\x00" * 8, b"\x11" * 32, b"\x00" * 16,
                       b"\x00" * 8, b"\x00" * 8, b"\x22" * 16, 0)
    fc = "to-DS" if src != AP else "from-DS"
    pkt = RadioTap() / Dot11(type=2, subtype=0, FCfield=fc, addr1=dst, addr2=src, addr3=AP) / \
        LLC() / SNAP(OUI=0, code=0x888e) / EAPOL(version=1, type=3) / Raw(load=body)
    pkt = pkt.__class__(bytes(pkt))
    pkt.time = ts
    return pkt


def test_eapol_message_classification():
    from sniffowireless.handshake import eapol_message
    STA = "a4:83:e7:01:00:01"
    assert eapol_message(eapol_frame(ack=True, mic=False, secure=False, src=AP, dst=STA)) == 1
    assert eapol_message(eapol_frame(ack=False, mic=True, secure=False, src=STA, dst=AP)) == 2
    assert eapol_message(eapol_frame(ack=True, mic=True, secure=True, src=AP, dst=STA)) == 3
    assert eapol_message(eapol_frame(ack=False, mic=True, secure=True, src=STA, dst=AP)) == 4
    assert eapol_message(frame(Dot11Beacon(cap="ESS") / Dot11Elt(ID=0, info=b"x"))) is None


def test_handshake_capture_scoped_to_my_networks(tmp_path):
    from sniffowireless.config import Config
    from sniffowireless.context import Ctx
    from sniffowireless.handshake import HandshakeCapture
    from sniffowireless.settings import Settings
    from sniffowireless.store import Store, connect
    from sniffowireless.oui import VendorLookup

    cfg = Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path))
    store = Store(cfg, VendorLookup(cfg.manuf_path))
    ctx = Ctx(cfg, store, Settings(lambda: connect(cfg.db_path)))
    hc = HandshakeCapture(ctx)
    STA = "a4:83:e7:01:00:01"

    # Enabling capture for a network that isn't "mine" is refused outright.
    import pytest as pt
    with pt.raises(ValueError):
        hc.enable("HomeNet", True)
    assert not hc.want("HomeNet")

    ctx.settings.set("networks", {"ssids": ["HomeNet"], "trusted_bssids": []})
    hc.enable("HomeNet", True)
    assert hc.want("HomeNet")

    # A recognized access point shows up right away, well before (or even without) a captured handshake —
    # this used to be indistinguishable from "capture isn't working at all", see the regression test below.
    hc.note_ap(AP, "HomeNet")
    assert hc.status()[0]["known_bssids"] == [AP] and hc.status()[0]["eapol_bssids"] == []

    hc.feed(eapol_frame(ack=True, mic=False, secure=False, src=AP, dst=STA), AP, STA, 1)
    hc.feed(eapol_frame(ack=False, mic=True, secure=False, src=STA, dst=AP), AP, STA, 2)
    st = hc.status()
    assert len(st) == 1 and st[0]["ssid"] == "HomeNet" and st[0]["frames"] == 2 and st[0]["usable_pairs"] == 1
    assert st[0]["known_bssids"] == [AP] and st[0]["eapol_bssids"] == [AP]
    assert st[0]["downloadable"] and hc.pcap_path("HomeNet")

    # Dropping the network from "My networks" stops and hides the capture, even though it stays enabled.
    ctx.settings.set("networks", {"ssids": [], "trusted_bssids": []})
    assert not hc.want("HomeNet")
    assert hc.status() == []
    assert hc.pcap_path("HomeNet") is None  # can't download what's no longer "mine" either

    # An unrelated SSID, even while nothing restricts it beforehand, is simply never fed without note_ap.
    hc.feed(eapol_frame(ack=True, mic=False, secure=False, src=AP, dst=STA), "aa:bb:cc:dd:ee:ff", STA, 1)
    assert hc.status() == []


def test_handshake_known_bssids_distinct_from_captured(tmp_path):
    """Regression test: a recognized access point must be reported even with zero captured EAPOL frames,
    so "0 access points" in the UI means "yolo hasn't seen this network's beacons", not "no handshake
    yet" — those used to be reported as the same number, which made a healthy-but-waiting capture
    indistinguishable from one that was never wired up at all."""
    from sniffowireless.config import Config
    from sniffowireless.context import Ctx
    from sniffowireless.handshake import HandshakeCapture
    from sniffowireless.settings import Settings
    from sniffowireless.store import Store, connect
    from sniffowireless.oui import VendorLookup

    cfg = Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path))
    store = Store(cfg, VendorLookup(cfg.manuf_path))
    ctx = Ctx(cfg, store, Settings(lambda: connect(cfg.db_path)))
    hc = HandshakeCapture(ctx)
    ctx.settings.set("networks", {"ssids": ["HomeNet"], "trusted_bssids": []})
    hc.enable("HomeNet", True)

    for i in range(3):
        hc.note_ap(f"24:a4:3c:10:00:0{i}", "HomeNet")
    st = hc.status()[0]
    assert len(st["known_bssids"]) == 3 and st["eapol_bssids"] == [] and st["frames"] == 0
    assert not st["downloadable"]  # nothing captured yet, so nothing to download


# ------------------------------------------------------------------ tracker sound ("play sound" button)
def test_tracker_sound_packet_framing():
    """The HCI/ATT framing tracker_sound.py builds and parses, checked without any real adapter."""
    import struct

    from sniffowireless.tracker_sound import _att_write, _parse_packet

    class FakeSocket:
        def __init__(self):
            self.sent = []

        def send(self, data):
            self.sent.append(data)

    sock = FakeSocket()
    _att_write(sock, handle=0x002A, att_pdu=bytes([0x12, 0x34, 0x12, 0x02]))
    (pkt,) = sock.sent
    assert pkt[0] == 0x02  # HCI ACL Data packet type
    handle_flags, total_len = struct.unpack_from("<HH", pkt, 1)
    assert handle_flags & 0x0FFF == 0x002A and (handle_flags >> 12) == 0b10
    l2len, cid = struct.unpack_from("<HH", pkt, 5)
    assert cid == 0x0004 and l2len == 4 and pkt[9:9 + l2len] == bytes([0x12, 0x34, 0x12, 0x02])

    # Round-trips through _parse_packet the same way the controller's ACL data would arrive.
    ev = _parse_packet(pkt)
    assert ev == {"ev": "att", "handle": 0x002A, "data": bytes([0x12, 0x34, 0x12, 0x02])}

    # LE connection complete and disconnection complete events.
    conn_evt = bytes([0x04, 0x3E, 0x13, 0x01, 0x00]) + bytes([0x2A, 0x00]) + b"\x00" * 13
    assert _parse_packet(conn_evt) == {"ev": "conn", "status": 0, "handle": 0x002A}
    disc_evt = bytes([0x04, 0x05, 0x04, 0x00, 0x2A, 0x00, 0x13])
    assert _parse_packet(disc_evt) == {"ev": "disc", "handle": 0x002A}


def test_tracker_sound_requires_real_hardware(monkeypatch):
    """No Bluetooth hardware here: just check play_sound() fails closed (socket error) rather than hanging."""
    from sniffowireless.tracker_sound import SoundError, play_sound
    import pytest as pt

    with pt.raises((SoundError, OSError, PermissionError)):
        play_sound("hci99", "aa:bb:cc:dd:ee:ff")
