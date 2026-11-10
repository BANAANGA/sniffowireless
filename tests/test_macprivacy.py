"""Privacy mode: full static MAC addresses are never stored (macprivacy.py), plus per-kind data retention."""
import json
import logging
import os
import sqlite3
import time


from sniffowireless import macprivacy
from sniffowireless.config import Config
from sniffowireless.macprivacy import MacHasher
from sniffowireless.oui import VendorLookup
from sniffowireless.store import Store, connect

REAL_CLIENT, REAL_AP, REAL_BLE, REAL_LAN, REAL_PEER = ("a4:83:e7:5c:21:0b", "24:a4:3c:10:00:01", "c8:2b:96:11:22:33",
                                                       "00:1a:2b:3c:4d:5e", "f0:9f:c2:aa:bb:cc")
RANDOMIZED = "da:11:22:33:44:55"   # locally administered: not static
MULTICAST = "01:00:5e:00:00:fb"


def hasher(tmp_path, scope="static", key=b"k" * 32):
    return MacHasher(sqlite3.connect(str(tmp_path / "alias.db"), check_same_thread=False, isolation_level=None), key, scope)


def test_a_static_address_keeps_its_vendor_and_gets_a_stable_pseudonym(tmp_path):
    h = hasher(tmp_path)
    p = h.pseudonym(REAL_CLIENT)
    assert p.startswith("a4:83:e7:") and p != REAL_CLIENT and len(p) == 17
    assert h.pseudonym(REAL_CLIENT) == p and h.pseudonym(REAL_CLIENT.upper()) == p
    assert hasher(tmp_path).pseudonym(REAL_CLIENT) == p                      # also after a restart (same key, same table)
    assert hasher(tmp_path, key=b"x" * 32).pseudonym(REAL_AP) != h.pseudonym(REAL_AP)   # the key decides
    assert h.pseudonym(REAL_AP) != h.pseudonym(REAL_BLE)


def test_randomised_and_multicast_addresses_are_left_alone_unless_the_scope_is_all(tmp_path):
    h = hasher(tmp_path)
    assert h.pseudonym(RANDOMIZED) == RANDOMIZED and h.pseudonym(MULTICAST) == MULTICAST and h.pseudonym("ff:ff:ff:ff:ff:ff") == "ff:ff:ff:ff:ff:ff"
    a = hasher(tmp_path, "all")
    assert a.pseudonym(RANDOMIZED) != RANDOMIZED and a.pseudonym(RANDOMIZED)[:2] == "da"  # the first byte (the address type) stays
    assert a.pseudonym(MULTICAST) == MULTICAST


def test_two_addresses_never_share_a_pseudonym(tmp_path):
    h = hasher(tmp_path)
    p = h.pseudonym(REAL_CLIENT)
    # force a clash: another address whose hash starts at the same place gets moved to the next free pseudonym
    other = "a4:83:e7:00:00:01"
    h.conn.execute("DELETE FROM mac_alias WHERE pseud=?", (p,))
    h.cache.clear()
    h.conn.execute("INSERT INTO mac_alias(pseud, digest) VALUES(?, ?)", (p, b"\x01" * 16))   # taken by an unrelated digest
    q = h.pseudonym(REAL_CLIENT)
    assert q != p and q.startswith("a4:83:e7:")
    assert h.count() == 2 and other


def test_text_json_and_dict_keys_are_scrubbed_but_other_hex_is_not(tmp_path):
    h = hasher(tmp_path)
    p = h.pseudonym(REAL_CLIENT)
    assert h.scrub_text(f"deauth to {REAL_CLIENT} reason 7") == f"deauth to {p} reason 7"
    assert h.scrub_text("rogue:" + REAL_CLIENT + ": locally") == f"rogue:{p}: locally"
    zb = "00:12:4b:00:1c:aa:bb:cc"                 # an 8-byte Zigbee address is not a MAC address
    assert h.scrub_text(zb) == zb and h.scrub_text("a4:83:e7") == "a4:83:e7" and h.scrub_text("fe80::1") == "fe80::1"
    o = {"mac": REAL_CLIENT, "hosts": {REAL_AP: "10.0.0.2"}, "items": [{"mac": REAL_PEER}], "n": 5, "fp": {"x": [f"bssid {REAL_AP}"]}}
    out = h.scrub(o)
    assert REAL_CLIENT not in json.dumps(out) and REAL_AP not in json.dumps(out) and REAL_PEER not in json.dumps(out)
    assert out["n"] == 5 and o["mac"] == REAL_CLIENT                                  # a copy: the input is untouched
    assert h.scrub(out, idempotent=True) == out                                       # pseudonyms are recognised
    assert h.scrub(out) != out                                                        # observations are real: hashed again


def stored_bytes(db_path):
    """Everything on disk that belongs to the database: the file, its write-ahead log and the journal."""
    data = b""
    for suffix in ("", "-wal", "-shm", "-journal"):
        try:
            with open(db_path + suffix, "rb") as f:
                data += f.read()
        except OSError:
            pass
    return data


def feed(store, ts=None):
    ts = ts or time.time()
    store.process({"t": "wifi_client", "ts": ts, "mac": REAL_CLIENT, "bssid": REAL_AP, "frame": "assoc", "rssi": -50, "probe": "HomeNet",
                   "fp": {"wifi": {"gen": 6}, "src": "assoc"}})
    store.process({"t": "wifi_ap", "ts": ts, "mac": REAL_AP, "ssid": "HomeNet", "rssi": -40,
                   "extra": {"ap": {"rnr": [{"bssid": REAL_PEER, "ch": 5, "oc": 131}]}}})
    store.process({"t": "bt", "kind": "ble", "ts": ts, "mac": REAL_BLE, "rssi": -60, "name": "Sensor", "randomized": False})
    store.process({"t": "wifi_client", "ts": ts, "mac": RANDOMIZED, "frame": "probe", "rssi": -70, "probe": "x"})
    store.process({"t": "event", "ts": ts, "mac": REAL_AP, "type": "deauth_broadcast", "detail": f"deauth to {REAL_CLIENT} reason 7"})
    store.process({"t": "lan", "ts": ts, "mac": REAL_LAN, "ip": "192.168.1.5", "name": "printer", "src": "arp"})
    store.flush()


def test_no_full_static_address_reaches_the_database(tmp_path):
    db = str(tmp_path / "t.db")
    cfg = Config(db_path=db, data_dir=str(tmp_path), hash_macs=True)
    s = Store(cfg, VendorLookup(None))
    assert s.macpriv is not None and os.path.exists(tmp_path / macprivacy.KEY_FILE)
    assert oct(os.stat(tmp_path / macprivacy.KEY_FILE).st_mode & 0o777) == "0o600"
    feed(s)
    s.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    blob = stored_bytes(db)
    for real in (REAL_CLIENT, REAL_AP, REAL_BLE, REAL_LAN, REAL_PEER):
        assert real.encode() not in blob, real
    assert RANDOMIZED.encode() in blob                                           # not a static address: kept as it is
    row = s.conn.execute("SELECT mac, vendor, kind FROM devices WHERE kind='wifi_client' AND randomized=0").fetchone()
    assert row["mac"] == s.macpriv.pseudonym(REAL_CLIENT) and row["mac"].startswith("a4:83:e7:")
    ev = s.conn.execute("SELECT detail FROM events WHERE type='deauth_broadcast'").fetchone()
    assert REAL_CLIENT not in ev["detail"] and s.macpriv.pseudonym(REAL_CLIENT) in ev["detail"]


def test_without_privacy_mode_nothing_changes(tmp_path):
    s = Store(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)), VendorLookup(None))
    assert s.macpriv is None and not macprivacy.is_active()
    feed(s)
    assert s.conn.execute("SELECT 1 FROM devices WHERE mac=?", (REAL_CLIENT,)).fetchone()


def test_existing_data_is_rewritten_and_the_old_values_leave_the_file(tmp_path):
    db = str(tmp_path / "t.db")
    plain = Store(Config(db_path=db, data_dir=str(tmp_path)), VendorLookup(None))
    feed(plain)
    plain.conn.execute("CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT)")
    plain.conn.execute("INSERT INTO settings(key, value) VALUES('ignore', ?)", (json.dumps({"macs": [REAL_LAN], "prefixes": []}),))
    plain.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    assert REAL_CLIENT.encode() in stored_bytes(db)
    plain.conn.close()
    conn = connect(db)
    conn.execute("INSERT OR REPLACE INTO settings(key, value) VALUES('privacy', ?)",
                 (json.dumps({"macs": False, "ssids": False, "hash_macs": True, "hash_scope": "static", "hash_existing": True}),))
    conn.close()
    s = Store(Config(db_path=db, data_dir=str(tmp_path)), VendorLookup(None))         # the next start does the work
    blob = stored_bytes(db)
    for real in (REAL_CLIENT, REAL_AP, REAL_BLE, REAL_LAN, REAL_PEER):
        assert real.encode() not in blob, real
    h = s.macpriv
    assert s.conn.execute("SELECT 1 FROM devices WHERE mac=?", (h.pseudonym(REAL_AP),)).fetchone()
    assert s.conn.execute("SELECT 1 FROM sessions WHERE mac=? AND peer=?", (h.pseudonym(REAL_CLIENT), h.pseudonym(REAL_AP))).fetchone()
    assert RANDOMIZED in [r[0] for r in s.conn.execute("SELECT mac FROM devices")]
    st = json.loads(s.conn.execute("SELECT value FROM settings WHERE key='ignore'").fetchone()[0])
    assert st["macs"] == [h.pseudonym(REAL_LAN)]
    p = json.loads(s.conn.execute("SELECT value FROM settings WHERE key='privacy'").fetchone()[0])
    assert p["hash_existing"] is False and p["hashed_at"]
    s.close() if hasattr(s, "close") else None


def test_ignore_macs_from_the_environment_are_matched_hashed(tmp_path):
    cfg = Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path), hash_macs=True, ignore_macs={REAL_CLIENT})
    s = Store(cfg, VendorLookup(None))
    feed(s)
    assert s.conn.execute("SELECT 1 FROM devices WHERE mac=?", (s.macpriv.pseudonym(REAL_CLIENT),)).fetchone() is None   # ignored
    assert s.conn.execute("SELECT 1 FROM devices WHERE mac=?", (s.macpriv.pseudonym(REAL_AP),)).fetchone()


def test_the_real_address_of_a_recently_heard_device_is_only_in_memory(tmp_path):
    h = hasher(tmp_path)
    macprivacy.set_current(h)
    p = h.pseudonym(REAL_BLE)
    assert macprivacy.resolve(p) == REAL_BLE and macprivacy.is_pseudonym(p)
    assert macprivacy.resolve("aa:aa:aa:aa:aa:aa") == "aa:aa:aa:aa:aa:aa"
    h.recent[p] = (REAL_BLE, time.time() - macprivacy.RECENT_TTL - 1)
    assert macprivacy.resolve(p) == p                                              # forgotten after the time limit
    assert REAL_BLE.encode() not in stored_bytes(str(tmp_path / "alias.db"))


def test_log_lines_do_not_contain_real_addresses(tmp_path):
    h = hasher(tmp_path)
    macprivacy.set_current(h)
    stream = []

    class Cap(logging.Handler):
        def emit(self, record):
            stream.append(record.getMessage())
    cap = Cap()
    cap.addFilter(macprivacy.LogScrubber())
    lg = logging.getLogger("test.privacy")
    lg.addHandler(cap)
    lg.setLevel(logging.INFO)
    lg.info("probe failed for %s (and %s)", REAL_BLE, h.pseudonym(REAL_AP))
    lg.removeHandler(cap)
    assert REAL_BLE not in stream[0] and h.pseudonym(REAL_BLE) in stream[0] and h.pseudonym(REAL_AP) in stream[0]


def test_retention_is_per_kind_and_defaults_to_retention_days(tmp_path):
    s = Store(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path), retention_days=30), VendorLookup(None))
    now = time.time()
    old = now - 10 * 86400
    s.conn.execute("INSERT INTO probes(mac, ssid, first_seen, last_seen, count) VALUES('aa:aa:aa:aa:aa:01','x',?,?,1)", (old, old))
    s.conn.execute("INSERT INTO events(ts, mac, type) VALUES(?, 'aa:aa:aa:aa:aa:01', 'arrived')", (old,))
    s.conn.execute("INSERT INTO devices(mac, kind, first_seen, last_seen) VALUES('aa:aa:aa:aa:aa:01','wifi_client',?,?)", (old, old))
    s.prune(now)
    assert s.conn.execute("SELECT COUNT(*) FROM probes").fetchone()[0] == 1          # 10 days is inside the 30-day default
    s.set_retention({"probes": 7, "events": 0, "bogus": -3})
    assert s.retention == {"probes": 7} and s.retention_days("devices") == 30
    s.prune(now)
    assert s.conn.execute("SELECT COUNT(*) FROM probes").fetchone()[0] == 0          # the probed networks follow the shorter limit
    assert s.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1 and s.conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1


def test_an_address_after_a_word_ending_in_hex_is_still_found(tmp_path):
    h = hasher(tmp_path)
    p = h.pseudonym(REAL_AP)
    assert h.scrub_text(f"nowpa3:{REAL_AP}") == f"nowpa3:{p}"                        # "wpa3" ends in a hex-looking pair
    assert h.scrub_text(f"karma:{REAL_AP} and wps:{REAL_CLIENT}").count(REAL_AP) == 0
    assert h.scrub_text(f"{REAL_AP}:00") == f"{REAL_AP}:00"                          # seven pairs not after a letter: not an address
    assert macprivacy.find_macs("x 00:12:4b:00:1c:aa:bb:cc y") == []                 # an 8-byte Zigbee address
