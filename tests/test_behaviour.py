"""Beacon fingerprint, beacon clock drift (cloned BSSIDs) and scan-burst behaviour."""
import json
import time

from sniffowireless import apclock, ossig, scanbehavior, wifiattrs
from sniffowireless.config import Config
from sniffowireless.identify import identify
from sniffowireless.oui import VendorLookup
from sniffowireless.store import Store


# ------------------------------------------------------------------ beacon fingerprint
def test_beacon_signature_depends_on_build_not_content():
    a = [(0, b"home"), (1, b"\x82"), (221, b"\x00\x50\xf2\x04xx")]
    b = [(0, b"office-wifi"), (1, b"\x82"), (221, b"\x00\x50\xf2\x04yy")]    # other name and payload, same layout
    c = [(1, b"\x82"), (0, b"home"), (221, b"\x00\x50\xf2\x04xx")]           # other order
    assert wifiattrs.beacon_signature(a, 1073, 100) == wifiattrs.beacon_signature(b, 1073, 100)
    assert wifiattrs.beacon_signature(a, 1073, 100) != wifiattrs.beacon_signature(c, 1073, 100)
    assert wifiattrs.beacon_signature(a, 1073, 100) != wifiattrs.beacon_signature(a, 1073, 200)
    assert wifiattrs.ap_attributes(a, 100, 1073)["bsig"] == wifiattrs.beacon_signature(a, 1073, 100)


# ------------------------------------------------------------------ clock drift
def beacons(w, bssid, start, n, tsf0, drift_ppm=20, every=10, sensor="local"):
    out = []
    for i in range(n):
        t = start + i * every
        out.append(w.feed(sensor, bssid, t, int((tsf0 + (t - start) * (1 + drift_ppm / 1e6)) * 1e6)))
    return out


def test_one_access_point_is_quiet_even_after_a_restart():
    w = apclock.ClockWatch()
    assert not any(beacons(w, "aa:bb:cc:00:00:01", 1000, 40, 5000))
    assert not any(beacons(w, "aa:bb:cc:00:00:01", 1400, 40, 3))   # restarted: one jump, stays on the new line


def test_two_timers_under_one_address_are_reported():
    w, hits, t0 = apclock.ClockWatch(), [], 1000
    for i in range(30):
        t = t0 + i * 10
        tsf = (50000 if i % 2 else 9_000_000) + (t - t0)
        hits.append(w.feed("local", "aa:bb:cc:00:00:02", t, int(tsf * 1e6)))
    assert any(hits) and "two beacon timers" in next(h for h in hits if h)


def test_drift_is_measured_and_sensors_are_kept_apart():
    w = apclock.ClockWatch()
    beacons(w, "aa:bb:cc:00:00:03", 1000, 60, 100, drift_ppm=25)
    assert abs(w.skew_ppm("local", "aa:bb:cc:00:00:03") - 25) < 1
    assert w.skew_ppm("other", "aa:bb:cc:00:00:03") is None
    # the same AP heard by a sensor whose clock is minutes off is not a conflict
    assert not any(beacons(w, "aa:bb:cc:00:00:03", 1000 + 300, 40, 100, sensor="other"))


def test_store_raises_the_event(tmp_path):
    s = Store(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)), VendorLookup(None))
    t0 = time.time() - 400
    for i in range(30):
        t = t0 + i * 10
        tsf = (50000 if i % 2 else 9_000_000) + (t - t0)
        s.process({"t": "wifi_ap", "ts": t, "mac": "aa:bb:cc:00:00:04", "rssi": -50, "ssid": "x", "channel": 6, "tsf": int(tsf * 1e6)})
    assert any(e[2] == "ap_clock_conflict" for e in s.events)


# ------------------------------------------------------------------ scan bursts
def burst(tr, mac, t, n=3, gap=0.05):
    r = None
    for i in range(n):
        r = tr.feed(mac, t + i * gap) or r
    return r


def test_signature_after_three_bursts_and_stable_under_jitter():
    tr, got = scanbehavior.ScanTracker(), None
    for i in range(5):
        got = burst(tr, "m1", 100 + i * 60) or got
    assert got and got["sig"] == "n3|g-4|p6" or got["sig"].startswith("n3|")
    tr2 = scanbehavior.ScanTracker()
    got2 = None
    for i in range(5):
        got2 = burst(tr2, "m2", 100 + i * 61.5, gap=0.052) or got2
    assert got["sig"] == got2["sig"]


def test_different_scanners_differ():
    a, b, ga, gb = scanbehavior.ScanTracker(), scanbehavior.ScanTracker(), None, None
    for i in range(5):
        ga = burst(a, "x", 100 + i * 60, n=3, gap=0.05) or ga
        gb = burst(b, "y", 100 + i * 15, n=8, gap=0.3) or gb
    assert ga["sig"] != gb["sig"]


def test_scan_behaviour_is_learned_and_used(tmp_path):
    s = Store(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)), VendorLookup(None))
    sig, now = "n3|g-4|p6", time.time()
    for i in range(4):
        m = f"da:00:00:00:09:0{i}"
        ex = {"scan": {"sig": sig, "size": 3, "gap_ms": 50, "period": 60, "bursts": 3}}
        s.conn.execute("INSERT INTO devices(mac, kind, first_seen, last_seen, randomized, extra) VALUES(?,?,?,?,1,?)", (m, "wifi_client", now, now, json.dumps(ex)))
        if i < 3:
            s.scan_learner.observe(m, sig, "Android")
    dev = {"mac": "da:00:00:00:09:03", "kind": "wifi_client", "extra": {"scan": {"sig": sig}}}
    res = identify(dev)
    assert res["os"] == "Android" and "scan behaviour" in json.dumps(res["ident"]).lower()
    assert ossig.source_category("Wi-Fi scan behaviour shared with 3 devices") == "learned-scan"
    assert ossig.trusted_family([{"field": "os", "value": "Android", "conf": 90, "source": "Wi-Fi scan behaviour shared with 3 devices identified as Android"}]) is None
