import time

from scapy.layers.dot11 import (Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11ProbeReq, RadioTap)

from yolo.bluetooth import parse_ad, parse_event
from yolo.config import Config, chan_label, parse_channels
from yolo.oui import VendorLookup
from yolo.store import Store
from yolo.wifi import assign_channels, parse_frame

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
