"""Who uses the airtime (release 35): per channel, the share of the listening time each device's data frames were on the air."""
import json
import sqlite3
import time

import pytest
from test_hardening import client, ctx  # noqa: F401  (ctx is a fixture)

from sniffowireless import linkstats as ls
from sniffowireless.web import create_app

AP, FAST, SLOW = "24:a4:3c:10:00:01", "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"


def test_frame_time():
    assert ls.frame_us(1.0, 100) == 192 + 800        # DSSS, long preamble
    assert ls.frame_us(24.0, 300) == 20 + 100         # OFDM
    assert ls.frame_us(300.0, 1500) == 40 + 40        # HT/VHT/HE
    us, median = ls.airtime_us({"frames": 10, "bytes": 3000, "rates": json.dumps({"24": 4, "54": 4})})
    assert median == 24 and us == pytest.approx(4 * (20 + 100) + 4 * (20 + 2400 / 54) + 2 * (20 + 100))   # 2 frames of unknown rate at the median


def setup(ctx):
    now = time.time()
    ctx.execute("INSERT INTO devices(mac, kind, ssid, channel, band, last_seen, first_seen, extra) VALUES(?, 'ap', 'Home', 6, '2.4', ?, 0, ?)",
                (AP, now, json.dumps({"ap": {"basic_rate": 1.0, "beacon_len": 300, "beacon_tu": 100}})))
    ctx.execute("INSERT INTO devices(mac, kind, name, last_seen, first_seen) VALUES(?, 'wifi_client', 'Old printer', ?, 0)", (SLOW, now))
    m = int(now // 60) * 60
    ctx.execute("INSERT INTO channel_stats(minute, sensor, freq, dwell_ms, frames, bytes, airtime_us, retries) VALUES(?, 'local', 2437, 10000, 100, 1, 5000000, 1)", (m,))
    s = ctx.store
    for mac, rates, way, n, size in ((FAST, {"144.4": 2000}, "up", 2000, 1500), (SLOW, {"1": 100, "2": 100}, "up", 200, 1000),
                                     (FAST, {"288.9": 3000}, "down", 3000, 1500)):
        s.process({"t": "link", "ts": now, "mac": mac, "bssid": AP, "dir": way, "frames": n, "retries": 0, "bytes": n * size, "rates": rates,
                   "mcs": {}, "rssi_sum": 0, "rssi_n": 0})
    s.flush()


def test_shares_per_channel(ctx):
    setup(ctx)
    r = ls.airtime(ctx, time.time() - 3600)
    ch = r["channels"][0]
    assert (ch["band"], ch["channel"], ch["listened_s"]) == ("2.4", 6, 10) and ch["utilization"] == 0.5
    d = {x["mac"]: x for x in ch["devices"]}
    slow_us = 100 * (192 + 8000 / 1) + 100 * (192 + 8000 / 2)
    assert d[SLOW]["share"] == pytest.approx(slow_us / 10e6, abs=1e-4) and d[SLOW]["slow"] and d[SLOW]["name"] == "Old printer"
    assert d[SLOW]["median_rate"] == 1.0 and d[SLOW]["at_100"] == pytest.approx(d[SLOW]["share"] / 100, abs=1e-4)
    assert not d[FAST]["slow"] and d[FAST]["share"] == pytest.approx(2000 * (40 + 12000 / 144.4) / 10e6, abs=1e-4)
    assert d[AP]["kind"] == "ap" and d[AP]["share"] > 0.025   # what it sent its clients, and its beacons at 1 Mb/s
    assert [x["mac"] for x in r["slow"]] == [SLOW]
    assert ch["devices"][0]["mac"] == SLOW


def test_route(ctx):
    setup(ctx)
    d = client(create_app(ctx), "view").get("/api/channels/airtime?hours=1").json()
    assert d["channels"][0]["devices"][0]["mac"] == SLOW


def test_release_34_tables_get_the_byte_count(tmp_path):
    db = tmp_path / "old.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE link_stats(hour INTEGER NOT NULL, mac TEXT NOT NULL, dir TEXT NOT NULL, bssid TEXT, frames INTEGER DEFAULT 0, "
              "retries INTEGER DEFAULT 0, rssi_sum INTEGER DEFAULT 0, rssi_n INTEGER DEFAULT 0, rates TEXT, mcs TEXT, PRIMARY KEY(hour, mac, dir)) WITHOUT ROWID")
    c.commit()
    c.close()
    from sniffowireless.config import Config
    from sniffowireless.main import build
    built = build(Config(db_path=str(db), data_dir=str(tmp_path)))
    assert "bytes" in {r[1] for r in built.store.conn.execute("PRAGMA table_info(link_stats)")}


def test_the_sensor_counts_bytes():
    import struct
    rt = struct.pack("<BBHI", 0, 0, 9, (1 << 2)) + bytes([48])
    frame = bytes([0x88, 0x41, 0, 0]) + bytes.fromhex("24a43c100001") + bytes.fromhex("aabbcc000001") + bytes.fromhex("24a43c100001") + bytes(4) + bytes(100)
    c = ls.LinkCounter()
    c.feed(rt + frame)
    c.feed(rt + frame)
    assert c.drain()[0]["bytes"] == 2 * len(frame)
