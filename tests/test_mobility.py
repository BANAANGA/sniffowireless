"""Fixed or mobile: signal-strength spread over 10-minute bins."""
import json
import math
import time

from sniffowireless import mobility
from sniffowireless.config import Config
from sniffowireless.oui import VendorLookup
from sniffowireless.store import Store


def make(tmp_path):
    return Store(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)), VendorLookup(None))


def add(s, mac, now, rssi_of, bins=20):
    s.conn.execute("INSERT INTO devices(mac, kind, first_seen, last_seen, extra) VALUES(?,?,?,?,?)", (mac, "ble", now, now, "{}"))
    for b in range(bins):
        for m in range(10):
            t = int(now) - (bins - b) * 600 + m * 60
            r = rssi_of(b, m)
            s.conn.execute("INSERT INTO samples(mac, minute, packets, rssi_sum, rssi_count) VALUES(?,?,?,?,1)", (mac, t // 60 * 60, 1, r))


def test_classes(tmp_path):
    s, now = make(tmp_path), time.time() // 600 * 600   # aligned to the bins so the test data fills them exactly
    add(s, "aa:00:00:00:00:01", now, lambda b, m: -60 + (m % 3) - 1)                      # flutter only
    add(s, "aa:00:00:00:00:02", now, lambda b, m: -60 + round(4 * math.sin(b)))           # drifts a few dB
    add(s, "aa:00:00:00:00:03", now, lambda b, m: -50 - (b % 5) * 8)                      # swings widely
    add(s, "aa:00:00:00:00:04", now, lambda b, m: -60, bins=5)                            # too little data
    r = mobility.compute(s.conn, now)
    assert r["aa:00:00:00:00:01"]["c"] == "fixed"
    assert r["aa:00:00:00:00:02"]["c"] == "mostly"
    assert r["aa:00:00:00:00:03"]["c"] == "mobile"
    assert "aa:00:00:00:00:04" not in r


def test_stored_and_cleared(tmp_path):
    s, now = make(tmp_path), time.time() // 600 * 600   # aligned to the bins so the test data fills them exactly
    add(s, "aa:00:00:00:00:01", now, lambda b, m: -60)
    s.apply_mobility(mobility.compute(s.conn, now))
    row = s.conn.execute("SELECT extra FROM devices WHERE mac='aa:00:00:00:00:01'").fetchone()
    assert json.loads(row["extra"])["mobility"]["c"] == "fixed"
    s.clear_mobility(frozenset())
    row = s.conn.execute("SELECT extra FROM devices WHERE mac='aa:00:00:00:00:01'").fetchone()
    assert "mobility" not in json.loads(row["extra"])
