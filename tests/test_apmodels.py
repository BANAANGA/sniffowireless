"""TP-Link, Ubiquiti and HPE Aruba access point models from what the AP announces about itself (apmodels.py)."""
import pytest

from sniffowireless import wifiattrs
from sniffowireless.apmodels import clean_name, recognize, vendor_ap_name
from sniffowireless.identify import identify, wifi_fingerprint

UBNT = bytes.fromhex("00156d")
ARUBA = bytes.fromhex("000b86")


@pytest.mark.parametrize("text, brand, model, gen", [
    ("U6-Pro", "Ubiquiti", "U6 Pro", 6), ("UniFi U6 Lite", "Ubiquiti", "U6 Lite", 6), ("u6 lr", "Ubiquiti", "U6 LR", 6),
    ("U7 Pro Max", "Ubiquiti", "U7 Pro Max", 7), ("U6-Enterprise-IW", "Ubiquiti", "U6 Enterprise IW", 6),
    ("UAP-AC-Pro", "Ubiquiti", "UAP-AC-Pro", 5), ("uap-ac-m pro", "Ubiquiti", "UAP-AC-M-Pro", 5), ("UAP-LR", "Ubiquiti", "UAP-LR", 4),
    ("nanoHD", "Ubiquiti", "nanoHD", 5), ("FlexHD", "Ubiquiti", "FlexHD", 5), ("NanoStation 5AC", "Ubiquiti", "NanoStation 5AC", None),
    ("Archer_C7", "TP-Link", "Archer C7", None), ("Archer AX55", "TP-Link", "Archer AX55", 6), ("ArcherAXE75", "TP-Link", "Archer AXE75", 6),
    ("Archer BE800", "TP-Link", "Archer BE800", 7), ("TL-WR841N", "TP-Link", "TL-WR841N", None), ("EAP225-Outdoor", "TP-Link", "EAP225-Outdoor", 5),
    ("EAP610", "TP-Link", "EAP610", 6), ("Deco X20", "TP-Link", "Deco X20", 6), ("Deco_M4", "TP-Link", "Deco M4", 5),
    ("AP-515", "HPE Aruba", "AP-515", 6), ("Aruba AP-535", "HPE Aruba", "AP-535", 6), ("IAP-305", "HPE Aruba", "AP-305", None),
    ("AP-635", "HPE Aruba", "AP-635", 6), ("AP-505H", "HPE Aruba", "AP-505H", 6),
])
def test_model_names_are_recognised(text, brand, model, gen):
    assert recognize(text) == (brand, model, recognize(text)[2], gen)


@pytest.mark.parametrize("text", ["AP-101", "Office AP", "U6", "Living room", "HomeNet-AX55", "AP 999", "Rocket", "EAP-TLS", "UniFi", "Deco", "", None])
def test_things_that_only_look_like_models_are_not(text):
    assert recognize(text) is None


def test_ubiquiti_and_aruba_ap_name_elements():
    assert vendor_ap_name(UBNT + b"\x01Hallway-U6-Pro") == ("Ubiquiti", "Hallway-U6-Pro", 1)
    assert vendor_ap_name(UBNT + b"\x02whatever") is None                       # only type 1 is the name
    assert vendor_ap_name(ARUBA + b"\x01\x03\x00AP-515-Lobby") == ("Aruba", "AP-515-Lobby", 3)
    assert vendor_ap_name(ARUBA + b"\x01\x04\x00\x10") == ("Aruba", None, 4)    # ARM element: no name
    assert vendor_ap_name(bytes.fromhex("00e04c") + b"\x01x") is None and vendor_ap_name(UBNT) is None and vendor_ap_name(b"") is None
    assert clean_name(b"AP\x00 name\n\x07 ") == "AP name" and len(clean_name(b"x" * 200)) == 48 and clean_name(b"\x00 ") is None


def test_the_beacon_parser_reads_the_elements():
    a = wifiattrs.ap_attributes([(221, UBNT + b"\x01Hallway-U6-Pro")])
    assert a["ap_name"] == "Hallway-U6-Pro" and a["ap_name_src"] == "Ubiquiti"
    a = wifiattrs.ap_attributes([(221, ARUBA + b"\x01\x03\x00AP-515-Lobby"), (221, ARUBA + b"\x01\x04\x00\x10"), (221, ARUBA + b"\x01\x02\x00")])
    assert a["ap_name"] == "AP-515-Lobby" and a["ap_name_src"] == "Aruba" and a["aruba"] == ["AP name", "ARM (adaptive radio management)", "Mesh"]
    assert wifiattrs.ap_attributes([(221, b"\x00\x50\xf2\x01\x01\x00")]).get("wpa1") is True   # other vendor elements still work


def ap(vendor, ssid, ap_info=None, he=False, vht=False, wps=None):
    elts = []
    if he:
        elts.append((255, bytes([35]) + b"\x00" * 24))
    if vht:
        elts.append((191, b"\x00" * 12))
    fp = wifi_fingerprint(elts + [(45, b"\x00" * 26)])
    if wps:
        fp["wps"] = wps
    if ap_info and (ap_info.get("ap_name_src") == "Ubiquiti"):
        fp.setdefault("vendors", []).append("00:15:6d")
    if ap_info and (ap_info.get("ap_name_src") == "Aruba" or ap_info.get("aruba")):
        fp.setdefault("vendors", []).append("00:0b:86")
    return {"kind": "ap", "mac": "24:a4:3c:10:00:01", "vendor": vendor, "ssid": ssid, "randomized": 0, "band": "5",
            "extra": {"ap": ap_info or {}, "fp": {"wifi": fp}}}


def test_a_ubiquiti_ap_with_an_ap_name_is_identified_with_its_model():
    r = identify(ap("Ubiquiti Inc", "HomeNet", {"ap_name": "U6-Pro", "ap_name_src": "Ubiquiti"}, he=True))
    assert (r["brand"], r["model"], r["wifi_gen"]) == ("Ubiquiti", "U6 Pro", 6)
    names = [e for e in r["ident"]["evidence"] if e["field"] == "name"]
    assert names and names[0]["value"] == "U6-Pro"


def test_the_name_must_agree_with_what_the_beacons_advertise():
    r = identify(ap("Ubiquiti Inc", "HomeNet", {"ap_name": "U6-Pro", "ap_name_src": "Ubiquiti"}, he=False, vht=True))   # Wi-Fi 5 only
    assert r["model"] is None
    assert any("looks like Ubiquiti U6 Pro, but the beacons show Wi-Fi 5" in e["value"] for e in r["ident"]["evidence"] if e["field"] == "feature")
    r = identify(ap("Ubiquiti Inc", "HomeNet", {"ap_name": "nanoHD", "ap_name_src": "Ubiquiti"}, vht=True))
    assert r["model"] == "nanoHD"


def test_an_aruba_ap_is_recognised_by_its_elements_and_a_room_name_is_not_a_model():
    info = {"ap_name": "AP-515-Lobby", "ap_name_src": "Aruba", "aruba": ["AP name", "ARM (adaptive radio management)"]}
    r = identify(ap("Aruba, a Hewlett Packard Enterprise Company", "Corp", info, he=True))
    assert r["brand"] == "HPE Aruba" and r["model"] == "AP-515"
    assert any(e["value"].startswith("Aruba: ARM") for e in r["ident"]["evidence"])
    room = identify(ap("Aruba, a Hewlett Packard Enterprise Company", "Corp", {"ap_name": "AP-101", "ap_name_src": "Aruba"}, he=True))
    assert room["model"] is None and room["brand"] == "HPE Aruba"                 # still an Aruba AP, from the vendor element


def test_a_vendor_element_alone_names_the_brand_even_with_another_oui():
    r = identify(ap("Some Rebrander Ltd", "x", {"aruba": ["ARM (adaptive radio management)"]}, he=True))
    assert r["brand"] == "HPE Aruba"


def test_a_tp_link_router_with_wps_gets_a_clean_model():
    r = identify(ap("TP-Link Technologies Co.,Ltd.", "TP-Link_4F2A", wps={"manufacturer": "TP-Link", "model": "Archer_C7", "model_number": "v5"}, vht=True))
    assert r["brand"] == "TP-Link" and "Archer" in r["model"]
    r = identify(ap("TP-Link Technologies Co.,Ltd.", "OmadaNet", {"ap_name": "EAP225-Outdoor"}, vht=True))     # an AP name from a controller-set name
    assert r["model"] is None or r["model"].startswith("EAP225")


def test_a_network_name_is_weak_evidence():
    r = identify(ap("Ubiquiti Inc", "UAP-AC-Pro", vht=True))
    assert r["model"] == "UAP-AC-Pro"
    top = [e for e in r["ident"]["evidence"] if e["field"] == "model"][0]
    assert top["conf"] <= 60                                                         # a name anyone can pick
