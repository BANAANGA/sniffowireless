"""People nearby: a range from phones heard per 5 minutes, not a count of addresses."""
import json
import time

import pytest
from fastapi.testclient import TestClient

from sniffowireless import occupancy, status
from sniffowireless.auth import hash_password
from sniffowireless.config import Config
from sniffowireless.main import build
from sniffowireless.web import create_app

PW = "correct-horse-battery"


@pytest.fixture
def ctx(tmp_path):
    status.SENSORS.clear()
    c = build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))
    with c.wdb() as w:
        w.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('view', ?, 'viewer', 0)", (hash_password(PW, iterations=1000),))
    return c


def device(w, mac, kind, dev_type=None, randomized=0, mobility=None, minutes=(1,), now=None):
    now = now or time.time()
    w.execute("INSERT INTO devices(mac, kind, first_seen, last_seen, dev_type, randomized, extra) VALUES(?,?,?,?,?,?,?)",
              (mac, kind, now - 3600, now, dev_type, randomized, json.dumps({"mobility": {"c": mobility}} if mobility else {})))
    for m in minutes:
        w.execute("INSERT OR IGNORE INTO samples(mac, minute) VALUES(?, ?)", (mac, int(now - m * 60) // 60 * 60))


def test_only_phones_count_and_the_answer_is_a_range(ctx):
    with ctx.wdb() as w:
        device(w, "02:00:00:00:00:01", "wifi_client", randomized=1)            # unidentified, random address: a phone
        device(w, "02:00:00:00:00:02", "wifi_client", "phone", randomized=1)
        device(w, "00:00:00:00:00:03", "wifi_client", "laptop")                # not a phone
        device(w, "00:00:00:00:00:04", "wifi_client")                          # unidentified with a real address: not counted
        device(w, "4a:00:00:00:00:05", "ble", "phone")
        device(w, "4a:00:00:00:00:06", "ble", "headphones")
        device(w, "4a:00:00:00:00:07", "ble", "phone", mobility="fixed")       # never moves: not a person
        device(w, "00:00:00:00:00:08", "ap")
        device(w, "02:00:00:00:00:09", "wifi_client", "phone", minutes=(30,))  # not heard in the last 5 minutes
    got = occupancy.now(ctx)
    assert got == {"low": 2, "high": 3, "wifi": 2, "bluetooth": 1, "linked": 0}


def test_a_hand_linked_pair_counts_once(ctx):
    with ctx.wdb() as w:
        device(w, "02:00:00:00:00:01", "wifi_client", "phone")
        device(w, "4a:00:00:00:00:05", "ble", "phone")
        w.execute("INSERT INTO device_links(mac_a, mac_b, status, created) VALUES('02:00:00:00:00:01', '4a:00:00:00:00:05', 'linked', 0)")
    assert occupancy.now(ctx) == {"low": 1, "high": 1, "wifi": 1, "bluetooth": 1, "linked": 1}


def test_history_counts_per_five_minutes_not_per_address_seen_in_the_period(ctx):
    """One phone that changed its address every 10 minutes for an hour is one person at any moment, not six."""
    now = time.time()
    with ctx.wdb() as w:
        for i in range(6):
            device(w, f"02:00:00:00:01:{i:02x}", "wifi_client", randomized=1, minutes=range(i * 10 + 6, i * 10 + 16), now=now)
    c = TestClient(create_app(ctx), base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    assert c.post("/api/auth/login", json={"username": "view", "password": PW}).status_code == 200
    o = c.get("/api/occupancy?hours=2").json()
    assert o["bucket"] == 300 and len(o["t"]) == len(o["low"]) == len(o["high"])
    assert max(x for x in o["high"] if x is not None) <= 2   # an address change inside one slot can show two
    assert sum(1 for x in o["low"] if x) >= 10               # present for about an hour
    assert o["now"]["high"] == 0
    # more than a day: half-hour averages of the 5-minute figures
    week = c.get("/api/occupancy?hours=1000").json()
    assert week["bucket"] == 1800 and week["hours"] == 168
    assert max(x for x in week["high"] if x is not None) <= 2


def test_summary_carries_the_current_range_and_needs_a_sign_in(ctx):
    app = create_app(ctx)
    anon = TestClient(app, base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    assert anon.get("/api/occupancy").status_code in (401, 403)
    c = TestClient(app, base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    c.post("/api/auth/login", json={"username": "view", "password": PW})
    assert c.get("/api/summary").json()["people"] == {"low": 0, "high": 0, "wifi": 0, "bluetooth": 0, "linked": 0}
