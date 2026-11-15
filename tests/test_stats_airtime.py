"""Statistics: airtime per channel and per band over time, clients per channel, Zigbee frames per channel and LoRa airtime."""
import time

import pytest
from fastapi.testclient import TestClient

from sniffowireless import status, survey
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


def client(ctx):
    c = TestClient(create_app(ctx), base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    assert c.post("/api/auth/login", json={"username": "view", "password": PW}).status_code == 200
    return c


def fill(ctx, now):
    m = int(now - 3600) // 60 * 60
    with ctx.wdb() as w:
        # channel 6: listened 10 s, 2.5 s of airtime -> 25%; heard by two sensors, which add up
        w.executemany("INSERT INTO channel_stats VALUES(?,?,?,?,?,?,?,?,?,?)", [
            (m, "local", 2437, 6000, 600, 0, 1_500_000, 60, -900, 10),
            (m, "attic", 2437, 4000, 400, 0, 1_000_000, 40, -950, 10),
            (m, "local", 5180, 10000, 100, 0, 500_000, 0, 0, 0),          # channel 36: 5%
            (m - 3 * 86400, "local", 2412, 10000, 999, 0, 9_000_000, 0, 0, 0)])   # outside one day
        for mac, ch, band in (("02:00:00:00:00:01", 6, "2.4"), ("02:00:00:00:00:02", 6, "2.4"), ("02:00:00:00:00:03", 36, "5")):
            w.execute("INSERT INTO devices(mac, kind, first_seen, last_seen, channel, band) VALUES(?, 'wifi_client', ?, ?, ?, ?)", (mac, now, now, ch, band))
        w.execute("INSERT INTO devices(mac, kind, first_seen, last_seen, channel, band) VALUES('00:00:00:00:00:09', 'ap', ?, ?, 6, '2.4')", (now, now))
        w.executemany("INSERT INTO zigbee_channels VALUES(?,?,?)", [(m, 15, 40), (m + 60, 15, 2), (m, 25, 7)])
        w.executemany("INSERT INTO lora_stats(minute, protocol, profile, packets, air_ms) VALUES(?,?,?,?,?)",
                      [(m, "meshtastic", "meshtastic-eu868", 10, 2500.0), (m, "unknown", "meshtastic-eu868", 1, 100.0), (m, "lorawan", "lorawan-eu868-sf7", 4, 200.0)])


def test_airtime_per_channel(ctx):
    fill(ctx, time.time())
    s = client(ctx).get("/api/stats?days=1").json()
    by = {(x["band"], x["channel"]): x for x in s["airtime"]}
    assert set(by) == {("2.4", 6), ("5", 36)}
    assert by[("2.4", 6)]["utilization"] == 0.25 and by[("2.4", 6)]["retry_rate"] == 0.1 and by[("2.4", 6)]["noise"] == -92.5
    assert by[("5", 36)]["utilization"] == 0.05


def test_airtime_per_band_over_time(ctx):
    now = time.time()
    fill(ctx, now)
    ser = client(ctx).get("/api/stats?days=1").json()["airtime_series"]
    assert ser["bucket"] == 900 and len(ser["t"]) == len(ser["bands"]["2.4"]) == len(ser["bands"]["5"])
    assert [v for v in ser["bands"]["2.4"] if v is not None] == [0.25] and [v for v in ser["bands"]["5"] if v is not None] == [0.05]
    assert "6" not in ser["bands"]  # a band nobody listened to is left out, not drawn as zero
    week = survey.airtime_series(ctx, now - 7 * 86400, now, 3600)
    assert sum(v is not None for v in week["bands"]["2.4"]) == 2   # the old row is in a 7-day view


def test_clients_zigbee_and_lora_channels(ctx):
    fill(ctx, time.time())
    s = client(ctx).get("/api/stats?days=1").json()
    assert {(r["b"], r["channel"]): r["n"] for r in s["client_channels"]} == {("2.4", 6): 2, ("5", 36): 1}
    zc = {r["channel"]: r["frames"] for r in s["zigbee_channels"]}
    assert len(zc) == 16 and zc[15] == 42 and zc[25] == 7 and zc[11] == 0
    la = {(r["profile"], r["protocol"]): r for r in s["lora_airtime"]}
    assert la[("meshtastic-eu868", "meshtastic")]["air_s"] == 2.5 and la[("meshtastic-eu868", "meshtastic")]["protocol_label"] == "Meshtastic"
    assert la[("lorawan-eu868-sf7", "lorawan")]["packets"] == 4
    assert s["lora_airtime"][0]["air_s"] >= s["lora_airtime"][-1]["air_s"]


def test_empty_database(ctx):
    s = client(ctx).get("/api/stats?days=7").json()
    assert s["airtime"] == [] and s["airtime_series"]["bands"] == {} and s["client_channels"] == [] and s["lora_airtime"] == []
    assert all(r["frames"] == 0 for r in s["zigbee_channels"])


def test_the_channels_page_still_works(ctx):
    fill(ctx, time.time())
    r = client(ctx).get("/api/channels?hours=24").json()
    assert {(x["band"], x["channel"]) for x in r["channels"]} == {("2.4", 6), ("5", 36)} and r["has_survey"]
