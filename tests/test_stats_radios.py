"""Statistics: breakdowns of the Zigbee / Thread radios and the LoRa nodes."""
import time

import pytest
from fastapi.testclient import TestClient

from sniffowireless import status
from sniffowireless.auth import hash_password
from sniffowireless.config import Config
from sniffowireless.main import build
from sniffowireless.web import create_app
from sniffowireless.zigbee_radio import CAP_MAINS, HINT_THREAD, HINT_ZIGBEE, ROLE_GREEN_POWER, ROLE_POLLS

PW = "correct-horse-battery"


@pytest.fixture
def client(tmp_path):
    status.SENSORS.clear()
    ctx = build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))
    now = time.time()
    with ctx.wdb() as w:
        w.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('view', ?, 'viewer', 0)", (hash_password(PW, iterations=1000),))
        for pan, addr, hint, roles, caps, vendor, seen in (
                (1, "0x0000", HINT_ZIGBEE, 1, None, "Silicon Labs", now),
                (1, "0x1a2b", HINT_ZIGBEE, ROLE_POLLS, None, None, now),
                (1, "0x3c4d", HINT_ZIGBEE, 0, CAP_MAINS, "IKEA", now),
                (1, "gpd:01020304", HINT_ZIGBEE, ROLE_GREEN_POWER, None, None, now),
                (2, "0x0400", HINT_THREAD, 0, None, None, now),
                (1, "0x9999", HINT_ZIGBEE, 0, None, None, now - 3 * 86400)):  # outside one day
            w.execute("INSERT INTO zigbee_radios(pan, addr, hint, roles, caps, vendor, first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?)",
                      (pan, addr, hint, roles, caps, vendor, seen, seen))
        for protocol, addr, kind, profile, lat, seen in (
                ("meshtastic", "!a1", "client", "meshtastic-eu", 52.0, now),
                ("meshtastic", "!a2", "router", "meshtastic-eu", None, now),
                ("lorawan", "26011f", None, None, None, now),
                ("meshcore", "ab", None, None, None, now - 3 * 86400)):
            w.execute("INSERT INTO lora_nodes(protocol, addr, kind, profile, lat, first_seen, last_seen) VALUES(?,?,?,?,?,?,?)",
                      (protocol, addr, kind, profile, lat, seen, seen))
    c = TestClient(create_app(ctx), base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    assert c.post("/api/auth/login", json={"username": "view", "password": PW}).status_code == 200
    return c


def chart(block, title):
    return {r["v"]: r["n"] for c in block["charts"] if c["title"] == title for r in c["rows"]}


def test_zigbee_breakdown(client):
    z = client.get("/api/stats?days=1").json()["zigbee"]
    assert z["total"] == 5
    assert chart(z, "Protocol") == {"Zigbee": 4, "Thread": 1}
    assert chart(z, "Role") == {"Coordinator": 1, "End device": 1, "Green Power device": 1, None: 2}
    assert chart(z, "Power") == {"Mains powered": 1, "No battery (Green Power)": 1, None: 3}
    assert chart(z, "Vendor") == {"Silicon Labs": 1, "IKEA": 1, None: 3}
    assert chart(z, "Probable device")["Coordinator"] == 1
    for c in z["charts"]:  # every chart counts every radio once
        assert sum(r["n"] for r in c["rows"]) == z["total"], c["title"]


def test_lora_breakdown(client):
    lo = client.get("/api/stats?days=1").json()["lora"]
    assert lo["total"] == 3
    assert chart(lo, "Protocol") == {"Meshtastic": 2, "LoRaWAN": 1}
    assert chart(lo, "Node type") == {"client": 1, "router": 1, None: 1}
    assert chart(lo, "Position") == {"Sends its position": 1, "No position heard": 2}
    for c in lo["charts"]:
        assert sum(r["n"] for r in c["rows"]) == lo["total"], c["title"]


def test_the_period_is_followed(client):
    s = client.get("/api/stats?days=7").json()
    assert s["zigbee"]["total"] == 6 and s["lora"]["total"] == 4


def test_empty_database_gives_empty_breakdowns(tmp_path):
    status.SENSORS.clear()
    ctx = build(Config(db_path=str(tmp_path / "e.db"), data_dir=str(tmp_path)))
    with ctx.wdb() as w:
        w.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('view', ?, 'viewer', 0)", (hash_password(PW, iterations=1000),))
    c = TestClient(create_app(ctx), base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    c.post("/api/auth/login", json={"username": "view", "password": PW})
    s = c.get("/api/stats?days=1").json()
    assert s["zigbee"]["total"] == 0 and s["lora"]["total"] == 0


def test_activity_by_hour_counts_zigbee_radios_and_lora_nodes(tmp_path):
    status.SENSORS.clear()
    ctx = build(Config(db_path=str(tmp_path / "h.db"), data_dir=str(tmp_path)))
    hour = int(time.time() - 7200) // 3600 * 3600  # a whole hour, inside the last day
    with ctx.wdb() as w:
        w.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('view', ?, 'viewer', 0)", (hash_password(PW, iterations=1000),))
        # one radio heard in three 5-minute slots of the same hour counts once; a second radio makes two
        w.executemany("INSERT INTO radio_seen VALUES(?, ?, ?)", [
            (hour, "zigbee", "1:0x0000"), (hour + 300, "zigbee", "1:0x0000"), (hour + 600, "zigbee", "1:0x0000"),
            (hour + 300, "zigbee", "1:0x1a2b"), (hour, "lora", "meshtastic:!a1"),
            (hour - 3 * 86400, "lora", "meshtastic:!old")])  # outside the period
    c = TestClient(create_app(ctx), base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    c.post("/api/auth/login", json={"username": "view", "password": PW})
    h = c.get("/api/stats?days=1").json()["hourly"]
    got = {(r["kind"], r["h"]): r["n"] for r in h["rows"]}
    assert got == {("zigbee", hour % 86400 // 3600): 2, ("lora", hour % 86400 // 3600): 1}
    # the local hour follows the timezone, like the devices do
    shifted = {(r["kind"], r["h"]) for r in c.get("/api/stats?days=1&tz=-60").json()["hourly"]["rows"]}
    assert shifted == {("zigbee", (hour + 3600) % 86400 // 3600), ("lora", (hour + 3600) % 86400 // 3600)}
