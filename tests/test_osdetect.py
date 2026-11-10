"""Operating-system detection: evidence fusion, Wi-Fi signatures learned from the network, and OS carried over confirmed links."""
import json
import time

import pytest

from sniffowireless import ossig
from sniffowireless.config import Config
from sniffowireless.identify import Evidence, identify as run_identify
from sniffowireless.oui import VendorLookup
from sniffowireless.store import Store


# ------------------------------------------------------------------ fusion
def test_two_kinds_of_evidence_agreeing_are_stronger_than_either():
    e = Evidence()
    e.add("os", "Android", 65, "DHCP option-55 fingerprint 1,3,6")
    one = e.resolve("os")["conf"]
    e.add("os", "Android 14", 60, "mDNS model “Pixel 8”")
    r = e.resolve("os")
    assert one == 65 and r["conf"] > 65 and r["agree"] == 2 and r["value"] == "Android 14"   # the more specific name wins


def test_two_clues_from_one_kind_of_source_count_once():
    e = Evidence()
    e.add("os", "Windows", 80, "DHCP option-55 fingerprint 1,3,6,15")
    e.add("os", "Windows", 85, "DHCP vendor class “MSFT 5.0”")
    r = e.resolve("os")
    assert r["agree"] == 1 and r["conf"] == 85


def test_confidence_is_capped_and_families_group_apple_names():
    e = Evidence()
    for src, c in (("DHCP vendor class", 90), ("mDNS model “iPhone15,2”", 85), ("Apple vendor element in Wi-Fi frames", 80), ("Device name “iPhone”", 70)):
        e.add("os", "iOS / macOS" if c != 70 else "iOS", c, src)
    r = e.resolve("os")
    assert r["agree"] == 4 and r["conf"] <= 97 and r["also"] == []


def test_a_well_supported_rival_marks_the_result_as_contested():
    e = Evidence()
    e.add("os", "iOS", 75, "Device name “iPhone de Sam”")
    e.add("os", "Android", 70, "DHCP option-55 fingerprint 1,3,6")
    r = e.resolve("os")
    assert r["value"] == "iOS" and r["conf"] < 75 and r["also"][0]["value"] == "Android"
    weak = Evidence()
    weak.add("os", "iOS", 80, "Device name “iPhone”")
    weak.add("os", "Android", 20, "Network name “AndroidAP”")
    assert weak.resolve("os")["conf"] == 80 and weak.resolve("os")["also"] == []             # a weak rival changes nothing


def test_the_result_carries_agreement_and_rivals():
    dev = {"kind": "wifi_client", "mac": "a4:83:e7:01:00:01", "randomized": 0, "name": "iPhone", "extra": {"fp": {"lan": {"dhcp": {"vendor": "android-dhcp-14"}}}}}
    f = run_identify(dev)["ident"]["fields"]["os"]
    assert f["agree"] >= 1 and "level" in f and (not f.get("also") or all({"value", "conf", "source"} <= set(a) for a in f["also"]))


# ------------------------------------------------------------------ learned signatures
def client(mac, fp_hash="ab12cd34ef", ext="0000080000000040", vendors=("00:10:18",), lan=None, name=None):
    return {"kind": "wifi_client", "mac": mac, "randomized": 1, "name": name, "fp_hash": fp_hash,
            "extra": {"fp": {"wifi": {"vendors": list(vendors), "capinfo": {"extcap": ext}}, **({"lan": lan} if lan else {})}}}


ANDROID_DHCP = {"dhcp": {"vendor": "android-dhcp-14"}}


@pytest.fixture
def learner(tmp_path):
    s = Store(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)), VendorLookup(None))
    return s


def test_the_signature_needs_a_probe_fingerprint_and_a_client():
    assert ossig.wifi_signature(client("da:00:00:00:00:01")) == "ab12cd34ef|0000080000000040|00:10:18"
    assert ossig.wifi_signature({**client("da:00:00:00:00:01"), "fp_hash": None}) is None
    assert ossig.wifi_signature({**client("da:00:00:00:00:01"), "kind": "ble"}) is None


def test_a_pattern_seen_on_known_devices_identifies_an_unknown_one(learner):
    s = learner
    for i in range(4):                                      # four devices the strong evidence identifies
        d = client(f"da:00:00:00:00:0{i}", lan=ANDROID_DHCP)
        r = run_identify(d)
        assert r["os"] == "Android 14" and r["ident"]["fields"]["os"]["conf"] >= 80
        s._learn({**d, **r})
    unknown = client("da:00:00:00:00:99")                  # same pattern, nothing else to go on
    r = run_identify(unknown)
    assert r["os"] == "Android"
    top = [e for e in r["ident"]["evidence"] if e["field"] == "os"][0]
    assert top["source"].startswith("Wi-Fi capability pattern shared with 4 devices identified as Android") and 55 <= top["conf"] <= 70
    other = run_identify(client("da:00:00:00:00:98", fp_hash="ffffffffff"))            # another pattern: nothing learned
    assert other["os"] is None


def test_it_needs_enough_devices_and_agreement(learner):
    s = learner
    sig = ossig.wifi_signature(client("da:00:00:00:01:00"))
    for i in range(2):
        s.learner.observe(f"da:00:00:00:01:0{i}", sig, "Android")
    assert s.learner.lookup(sig) is None                                                   # two is not enough
    s.learner.observe("da:00:00:00:01:05", sig, "Android")
    assert s.learner.lookup(sig)[0] == "Android"
    for i in range(3):
        s.learner.observe(f"da:00:00:00:01:1{i}", sig, "Windows")
    assert s.learner.lookup(sig) is None                                                   # the pattern does not tell them apart


def test_a_device_does_not_vouch_for_itself_and_a_changed_os_moves_it(learner):
    s = learner
    sig = ossig.wifi_signature(client("da:00:00:00:02:00"))
    for i in range(3):
        s.learner.observe(f"da:00:00:00:02:0{i}", sig, "Android")
    assert s.learner.lookup(sig, "da:00:00:00:02:00") is None                              # without itself only two are left
    assert s.learner.lookup(sig, "da:00:00:00:02:99")[1] == 3
    s.learner.observe("da:00:00:00:02:00", sig, "Windows")                                  # it was something else after all
    assert s.learner.counts[sig] == {"Android": 2, "Windows": 1}
    s.learner.observe("da:00:00:00:02:00", sig, "Windows")
    assert s.learner.counts[sig] == {"Android": 2, "Windows": 1}                           # once per device


def test_only_strong_non_derived_evidence_teaches():
    ev = [{"field": "os", "value": "Android", "conf": 90, "source": "DHCP vendor class"}]
    assert ossig.trusted_family(ev) == "Android"
    assert ossig.trusted_family([{"field": "os", "value": "Android", "conf": 70, "source": "mDNS model"}]) is None            # too weak
    assert ossig.trusted_family([{"field": "os", "value": "Android", "conf": 70, "source": "Wi-Fi capability pattern shared with 5 devices"}], 50) is None
    assert ossig.trusted_family([{"field": "os", "value": "Android", "conf": 95, "source": "Linked to aa:bb (confirmed by you)"}]) is None
    assert ossig.trusted_family(ev + [{"field": "os", "value": "Windows", "conf": 85, "source": "mDNS model"}]) is None       # they disagree
    assert ossig.trusted_family([{"field": "os", "value": "Embedded Linux (BusyBox)", "conf": 90, "source": "DHCP vendor class"}]) is None


def test_what_was_learned_survives_a_restart_and_reidentify_all_uses_it(tmp_path):
    cfg = Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path))
    s = Store(cfg, VendorLookup(None))
    now = time.time()
    macs = [f"da:00:00:00:03:0{i}" for i in range(4)]
    for i, m in enumerate(macs):
        d = client(m, lan=ANDROID_DHCP if i < 3 else None)
        s.conn.execute("INSERT INTO devices(mac, kind, first_seen, last_seen, randomized, fp_hash, extra) VALUES(?,?,?,?,1,?,?)",
                       (m, "wifi_client", now, now, d["fp_hash"], json.dumps(d["extra"])))
    s.reidentify_all()
    rows = {r["mac"]: r["os"] for r in s.conn.execute("SELECT mac, os FROM devices")}
    assert rows[macs[0]] == rows[macs[2]] == "Android 14" and rows[macs[3]] == "Android"   # the fourth had nothing but its pattern
    s2 = Store(cfg, VendorLookup(None))
    assert s2.learner.counts and sum(sum(v.values()) for v in s2.learner.counts.values()) == 3
    assert s2.learner.lookup(ossig.wifi_signature(client("x"))) is not None


# ------------------------------------------------------------------ links
def test_the_os_follows_a_confirmed_link_and_goes_when_it_is_rejected(tmp_path):
    from sniffowireless.matching import SCHEMA
    s = Store(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)), VendorLookup(None))
    s.conn.executescript(SCHEMA)
    now = time.time()
    wifi = client("da:00:00:00:04:01", lan=ANDROID_DHCP)
    s.conn.execute("INSERT INTO devices(mac, kind, first_seen, last_seen, randomized, extra, ident) VALUES(?,?,?,?,1,?,?)",
                   (wifi["mac"], "wifi_client", now, now, json.dumps(wifi["extra"]), json.dumps(run_identify(wifi)["ident"])))
    ble = "c1:22:33:44:55:66"
    s.conn.execute("INSERT INTO devices(mac, kind, first_seen, last_seen, randomized, extra) VALUES(?,?,?,?,1,?)", (ble, "ble", now, now, json.dumps({})))
    s.conn.execute("INSERT INTO device_links(mac_a, mac_b, status, score, created) VALUES(?,?,?,?,?)", (ble, wifi["mac"], "proposed", 0.9, now))
    assert s.propagate_linked_os() == 0 and s.conn.execute("SELECT os FROM devices WHERE mac=?", (ble,)).fetchone()["os"] is None   # not confirmed: nothing
    s.conn.execute("UPDATE device_links SET status='linked'")
    assert s.propagate_linked_os() == 1
    dev = s._load_dev(ble)
    assert dev["os"] == "Android" and dev["extra"]["linked_os"]["from"] == wifi["mac"]
    ev = [e for e in dev["ident"]["evidence"] if e["field"] == "os"][0]
    assert "confirmed by you" in ev["source"] and ev["conf"] == 70
    assert s.propagate_linked_os() == 0                                                  # nothing to do the second time
    s.conn.execute("UPDATE device_links SET status='rejected'")
    assert s.propagate_linked_os() == 1 and s._load_dev(ble)["os"] is None
    assert "linked_os" not in s._load_dev(ble)["extra"]


def test_a_device_with_its_own_os_keeps_it_over_a_link(tmp_path):
    from sniffowireless.matching import SCHEMA
    s = Store(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)), VendorLookup(None))
    s.conn.executescript(SCHEMA)
    now = time.time()
    a = client("da:00:00:00:05:01", lan=ANDROID_DHCP)
    b = client("da:00:00:00:05:02", lan={"dhcp": {"vendor": "MSFT 5.0"}})
    for d in (a, b):
        s.conn.execute("INSERT INTO devices(mac, kind, first_seen, last_seen, randomized, extra, ident) VALUES(?,?,?,?,1,?,?)",
                       (d["mac"], "wifi_client", now, now, json.dumps(d["extra"]), json.dumps(run_identify(d)["ident"])))
    s.conn.execute("INSERT INTO device_links(mac_a, mac_b, status, score, created) VALUES(?,?,?,?,?)", (a["mac"], b["mac"], "linked", 0.9, now))
    assert s.propagate_linked_os() == 0


def test_linux_based_systems_do_not_contradict_each_other():
    assert ossig.os_compatible("Linux", "Linux / Android") and ossig.os_compatible("Linux / Android", "Android 14")
    assert ossig.os_compatible("Linux", "Home Assistant OS") and ossig.os_compatible("Android", "Android 14")
    assert not ossig.os_compatible("Android", "Windows") and not ossig.os_compatible("iOS / macOS", "Linux") and not ossig.os_compatible("Windows", "Home Assistant OS")
    e = Evidence()
    e.add("os", "Home Assistant OS", 75, "Device name “homeassistant”")
    e.add("os", "Linux", 60, "DHCP option-55 fingerprint 1,28,2")
    r = e.resolve("os")
    assert r["value"] == "Home Assistant OS" and r["conf"] == 75 and r["also"] == []
