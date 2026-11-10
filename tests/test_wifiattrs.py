"""Wi-Fi attributes read passively from beacons, client requests, radiotap and sequence numbers."""
import struct

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, RadioTap

from sniffowireless import wifiattrs as w
from sniffowireless.identify import wifi_fingerprint
from sniffowireless.wifi import AttrGates, parse_frame

AP, CL = "24:a4:3c:10:00:01", "da:11:22:33:44:55"


def sel(t, oui=b"\x00\x0f\xac"):
    return oui + bytes([t])


def rsn(akm, pairwise=(4,), group=4, caps=0):
    return (b"\x01\x00" + sel(group) + struct.pack("<H", len(pairwise)) + b"".join(sel(p) for p in pairwise)
            + struct.pack("<H", len(akm)) + b"".join(sel(a) for a in akm) + struct.pack("<H", caps))


def beacon(elts, tsf=5_000_000, tu=100, ts=1_000_000.0):
    pkt = (RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=AP, addr3=AP) /
           Dot11Beacon(timestamp=tsf, beacon_interval=tu, cap=0x1104))
    for eid, info in elts:
        pkt = pkt / Dot11Elt(ID=eid, info=info)
    pkt.time = ts
    return pkt


def test_rsn_wpa3_transition_and_pmf():
    r = w.parse_rsn(rsn([2, 8], pairwise=(4, 2), caps=0x80))
    assert r["akm"] == ["PSK", "SAE"] and r["pairwise"] == ["CCMP", "TKIP"] and r["group"] == "CCMP"
    assert r["pmf"] == "optional" and r["transition"] is True
    r = w.parse_rsn(rsn([8], caps=0xC0))
    assert r["akm"] == ["SAE"] and r["pmf"] == "required" and "transition" not in r
    assert w.parse_rsn(rsn([2], caps=0))["pmf"] == "off"
    assert w.parse_rsn(rsn([18]))["akm"] == ["OWE"]


def test_rsn_truncated_and_hostile_input_is_safe():
    assert w.parse_rsn(b"") is None and w.parse_rsn(b"\x01\x00\x00\x0f\xac") is None
    assert w.parse_rsn(b"\x01\x00" + sel(4) + b"\xff\xff") is None  # claims 65535 suites, has none
    w.parse_rsn(rsn([2])[:-3])


def test_ap_attributes_from_a_beacon():
    he_oper = bytes([36]) + struct.pack("<I", (23 << 24) | 0x0000F0) + b"\x00\x00"
    ext = bytearray(10)
    ext[2] |= 1 << 3  # bit 19: BSS transition
    ext[8] |= 1 << 6  # bit 70: FTM responder
    elts = [(7, b"DE \x01\x0d\x14"), (11, struct.pack("<HBH", 12, 128, 3000)), (48, rsn([2, 8], caps=0xC0)),
            (54, b"\x34\x12\x01"), (70, b"\x00" * 5), (127, bytes(ext)), (255, he_oper),
            (221, b"\x00\x50\xf2\x04" + bytes.fromhex("10440001021057000101"))]
    a = w.ap_attributes(elts, 100)
    assert a["country"] == "DE" and a["load"] == {"sta": 12, "util": 50} and a["beacon_tu"] == 100
    assert a["rsn"]["pmf"] == "required" and a["roaming"] == ["11k", "11r", "11v"] and a["ftm"] is True
    assert a["bss_color"] == 23 and a["wps_configured"] is True and a["wps_locked"] is True


def test_he_operation_with_bss_color_disabled_gives_no_color():
    he = bytes([36]) + struct.pack("<I", (1 << 31) | (5 << 24)) + b"\x00\x00"
    assert "bss_color" not in w.ap_attributes([(255, he)])


def test_reduced_neighbor_report_lists_the_other_aps():
    ent = b"\x00" + bytes.fromhex("aabbccddee01") + bytes.fromhex("11223344") + b"\x00"  # TBTT offset, BSSID, short SSID, params
    hdr = (len(ent) << 8) | (0 << 4)  # one entry
    rnr = struct.pack("<H", hdr) + bytes([134, 5]) + ent
    assert w.parse_rnr(rnr) == [{"bssid": "aa:bb:cc:dd:ee:01", "ch": 5, "oc": 134}]
    assert w.parse_rnr(b"\x00\x0b\x86") == []  # truncated


def test_multi_link_and_mesh_and_hotspot():
    a = w.ap_attributes([(255, bytes([107, 0, 0])), (114, b"meshnet"), (107, b"\x00"), (71, b"\x03")])
    assert a["mlo"] and a["mesh_id"] == "meshnet" and a["interworking"] and a["mbssid"]


def test_parse_frame_reads_ap_details_and_estimates_boot_time():
    pkt = beacon([(0, b"HomeNet"), (7, b"NL \x01\x0d\x14"), (48, rsn([2]))], tsf=3_600_000_000, ts=1_000_000.0)
    obs = [o for o in parse_frame(pkt, None, None, AttrGates()) if o["t"] == "wifi_ap"]
    ap = obs[0]["extra"]["ap"]
    assert ap["country"] == "NL" and ap["boot"] == 1_000_000 - 3600 and ap["beacon_tu"] == 100
    assert not [o for o in parse_frame(pkt) if o["t"] == "wifi_ap" and (o.get("extra") or {}).get("ap")]  # off without gates


def test_ap_details_are_rate_limited():
    g = AttrGates(ap_interval=60)
    first = parse_frame(beacon([(0, b"x")], ts=100.0), None, None, g)[0]
    again = parse_frame(beacon([(0, b"x")], ts=130.0), None, None, g)[0]
    later = parse_frame(beacon([(0, b"x")], ts=170.0), None, None, g)[0]
    assert "ap" in first["extra"] and not (again.get("extra") or {}).get("ap") and "ap" in later["extra"]


def test_client_capabilities():
    ext = bytearray(10)
    ext[2] |= 1 << 3
    ext[9] |= 1 << 7  # bit 79 is not one we name
    ht = struct.pack("<H", 0x0001 | 0x0020 | 0x0100) + b"\x1b" + bytes(23)
    vht = struct.pack("<I", (1 << 12) | (1 << 20)) + bytes(8)
    elts = [(1, bytes([0x8c, 0x12, 0x98, 0x24])), (50, bytes([0x30, 0x48])), (45, ht), (191, vht), (70, b"\x00" * 5),
            (127, bytes(ext)), (36, bytes([1, 13, 36, 4])), (33, bytes([0, 17])), (59, bytes([81, 115, 124]))]
    c = w.client_caps(elts)
    assert c["dsss"] is False and "802.11v BSS transition" in c["caps"] and "802.11k radio measurement" in c["caps"]
    assert "LDPC" in c["caps"] and "RX STBC" in c["caps"] and "MU-MIMO beamformee" in c["caps"] and "SU beamformee" in c["caps"]
    assert c["chan_count"] == 17 and c["txp"] == [0, 17] and c["opcls"] == [81, 115, 124] and len(c["extcap"]) == 20
    assert w.client_caps([(1, bytes([0x82, 0x84, 0x8b, 0x96]))])["dsss"] is True  # 1, 2, 5.5, 11 Mbit/s


def test_capabilities_join_the_fingerprint_and_merge_between_frames():
    from sniffowireless.identify import merge_wifi
    fp1 = wifi_fingerprint([(127, bytes([0, 0, 8, 0]))])
    fp2 = wifi_fingerprint([(70, b"\x00" * 5)])
    assert "802.11v BSS transition" in fp1["capinfo"]["caps"] and "802.11k radio measurement" in fp2["capinfo"]["caps"]
    m = merge_wifi(merge_wifi(None, fp1), fp2)
    assert set(m["capinfo"]["caps"]) == {"802.11v BSS transition", "802.11k radio measurement"}
    assert fp1["sig"] == wifi_fingerprint([(127, bytes([0, 0, 8, 0]))])["sig"]  # grouping by signature is unchanged


def data_frame(src, dst, bssid, seq, rate=None, ts=1_000_000.0, to_ds=True):
    rt = RadioTap(present="Rate+dBm_AntSignal", Rate=rate, dBm_AntSignal=-55) if rate else RadioTap()
    pkt = rt / Dot11(type=2, subtype=0, FCfield="to-DS" if to_ds else "from-DS", addr1=bssid, addr2=src, addr3=dst, SC=seq << 4)
    pkt.time = ts
    return pkt


def test_link_rate_is_taken_from_data_frames_and_rate_limited():
    g = AttrGates(link_interval=30)
    o = [x for x in parse_frame(data_frame("a4:83:e7:00:00:01", AP, AP, 5, rate=156, ts=1_000_000.0), None, None, g) if x["t"] == "wifi_client"][0]
    assert o["extra"] == {"rate_up": 78.0}
    again = [x for x in parse_frame(data_frame("a4:83:e7:00:00:01", AP, AP, 6, rate=156, ts=1_000_010.0), None, None, g) if x["t"] == "wifi_client"][0]
    assert "extra" not in again


def test_sequence_numbers_only_for_randomised_senders_when_asked():
    rnd = [o for o in parse_frame(data_frame(CL, AP, AP, 1234), None, None, None, True) if o["t"] == "wifi_client"][0]
    assert rnd["seq"] == 1234
    real = [o for o in parse_frame(data_frame("a4:83:e7:00:00:01", AP, AP, 1234), None, None, None, True) if o["t"] == "wifi_client"][0]
    assert "seq" not in real
    assert "seq" not in [o for o in parse_frame(data_frame(CL, AP, AP, 1234)) if o["t"] == "wifi_client"][0]


def test_linker_needs_exactly_one_close_candidate():
    L = w.SeqLinker()
    assert L.feed("aa", 100.0, 1000) == []
    assert L.feed("bb", 101.0, 1010) == [("aa", 10)]     # new address carries on where aa stopped
    L2 = w.SeqLinker()
    L2.feed("aa", 100.0, 1000)
    L2.feed("cc", 100.5, 1005)
    assert L2.feed("bb", 101.0, 1010) == []              # two fit: no guess
    L3 = w.SeqLinker()
    L3.feed("aa", 100.0, 1000)
    assert L3.feed("bb", 120.0, 1010) == []              # too long ago
    assert L3.feed("cc", 120.5, 3000) == []              # counter jumped
    L4 = w.SeqLinker()
    L4.feed("aa", 100.0, 4090)
    assert L4.feed("bb", 100.5, 4) == [("aa", 10)]       # the 12-bit counter wraps


def test_store_links_only_when_opted_in_and_reports_restarts(tmp_path):
    from sniffowireless.config import Config
    from sniffowireless.oui import VendorLookup
    from sniffowireless.store import Store
    for on in (False, True):
        s = Store(Config(db_path=str(tmp_path / f"t{on}.db"), wifi_seq_link=on), VendorLookup(None))
        s.process({"t": "wifi_client", "ts": 100.0, "mac": "da:00:00:00:00:01", "frame": "probe", "seq": 700})
        s.process({"t": "wifi_client", "ts": 101.0, "mac": "da:00:00:00:00:02", "frame": "probe", "seq": 712})
        s.flush()
        ex = s.devices["da:00:00:00:00:02"]["extra"].get("same_as")
        assert (ex == [{"mac": "da:00:00:00:00:01", "step": 12, "ts": 101}]) is on
        if on:
            assert s.devices["da:00:00:00:00:01"]["extra"]["same_as"][0]["mac"] == "da:00:00:00:00:02"
    s = Store(Config(db_path=str(tmp_path / "ap.db")), VendorLookup(None))
    ap = lambda ts, boot: {"t": "wifi_ap", "ts": ts, "mac": AP, "ssid": "x", "extra": {"ap": {"boot": boot}}}
    s.process(ap(1000, 100)); s.process(ap(1060, 101)); s.process(ap(1120, 1100))  # timer started over
    assert [e for e in s.events if e[2] == "ap_restart"] and len([e for e in s.events if e[2] == "ap_restart"]) == 1
