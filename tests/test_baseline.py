"""Baseline: events when an hour is far busier than usual, a known device shows at an hour it is never here, or a maker is new."""
import sqlite3
import time

import pytest

from sniffowireless import baseline, status
from sniffowireless.alerts import EVENT_TYPES, LATER_RULES, describe
from sniffowireless.config import Config
from sniffowireless.main import build

HOUR, DAY = 3600, 86400
NOW = int(time.time()) // HOUR * HOUR - HOUR  # the hour under test


@pytest.fixture
def ctx(tmp_path):
    status.SENSORS.clear()
    return build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))


def presence(c, hour, n, prefix="aa"):
    c.executemany("INSERT OR IGNORE INTO presence_hours VALUES(?, ?)", [(hour, f"{prefix}:00:00:00:{i // 256:02x}:{i % 256:02x}") for i in range(n)])


def heard(c, mac, hour):
    c.execute("INSERT OR IGNORE INTO presence_hours VALUES(?, ?)", (hour, mac))
    c.execute("INSERT OR IGNORE INTO samples(mac, minute) VALUES(?, ?)", (mac, hour))


def test_usual_limit():
    med, limit = baseline.usual([20, 22, 19, 21, 20, 23, 20])
    assert med == 20 and limit == 30           # a steady site: 10 devices more is the floor
    med, limit = baseline.usual([200, 210, 190, 205, 200, 195, 200])
    assert limit == 300                        # half the median
    med, limit = baseline.usual([50, 150, 60, 140, 100, 40, 160])
    assert limit > 300                         # a site that varies a lot needs more to be unusual


def test_activity_is_only_unusual_against_enough_history(ctx):
    c = ctx.store.conn
    presence(c, NOW, 80)
    for k in range(1, 7):
        presence(c, NOW - k * DAY, 20)
    assert baseline.activity(c, NOW) is None   # six earlier days: not enough to call anything usual
    presence(c, NOW - 7 * DAY, 22)
    count, med, limit = baseline.activity(c, NOW)
    assert (count, med) == (80, 20) and limit == 30
    presence(c, NOW + HOUR, 25)                # a normal hour
    for k in range(1, 9):
        presence(c, NOW + HOUR - k * DAY, 20)
    assert baseline.activity(c, NOW + HOUR) is None


def test_hours_when_the_sensor_was_off_do_not_count_as_quiet(ctx):
    c = ctx.store.conn
    presence(c, NOW, 25)
    for k in (1, 2, 3, 4, 5, 6, 7, 9, 11):     # days 8 and 10: nothing stored at all
        presence(c, NOW - k * DAY, 20)
    assert baseline.activity(c, NOW) is None


def test_known_device_at_an_hour_it_is_never_here(ctx):
    c = ctx.store.conn
    mac, other = "00:11:22:33:44:55", "00:11:22:33:44:66"
    for d in range(1, 21):                     # 20 days, heard 09:00-11:00 UTC-ish each day (relative to the test hour)
        for h in (5, 6, 7):
            heard(c, mac, NOW - d * DAY + h * HOUR)
            heard(c, other, NOW - d * DAY + h * HOUR)
    heard(c, mac, NOW)                         # now: five hours away from anything before
    heard(c, other, NOW + 6 * HOUR)            # the other one at its usual hour
    got = baseline.odd_hours(c, NOW, [mac, other])
    assert [g[0] for g in got] == [mac] and got[0][1] == 19
    assert baseline.odd_hours(c, NOW + 6 * HOUR, [mac, other]) == []
    # next to a usual hour is not unusual
    heard(c, mac, NOW + 4 * HOUR)
    assert baseline.odd_hours(c, NOW + 4 * HOUR, [mac]) == []


def test_a_device_with_little_history_has_no_usual_hours(ctx):
    c = ctx.store.conn
    mac = "00:11:22:33:44:77"
    for d in range(1, 6):
        for h in (5, 6, 7, 8, 9):
            heard(c, mac, NOW - d * DAY + h * HOUR)   # 25 hours, but only 5 days
    heard(c, mac, NOW)
    assert baseline.odd_hours(c, NOW, [mac]) == []


def device(c, mac, vendor, first, randomized=0):
    c.execute("INSERT INTO devices(mac, kind, first_seen, last_seen, vendor, randomized) VALUES(?, 'wifi_client', ?, ?, ?, ?)", (mac, first, first, vendor, randomized))


def test_new_vendor_only_on_an_installation_with_history(ctx):
    c = ctx.store.conn
    device(c, "00:00:00:00:00:01", "Acme", NOW + 60)
    assert baseline.new_vendors(c, NOW) == []                      # young installation: everything would be new
    device(c, "00:00:00:00:00:02", "Old Co", NOW - 30 * DAY)
    device(c, "00:00:00:00:00:03", "Old Co", NOW + 120)            # a maker seen before
    device(c, "02:00:00:00:00:04", "Random Co", NOW + 120, randomized=1)
    assert baseline.new_vendors(c, NOW) == [("Acme", "00:00:00:00:00:01")]
    assert baseline.new_vendors(c, NOW + HOUR) == []


def test_the_monitor_raises_each_event_once_per_hour(ctx):
    c, store = ctx.store.conn, ctx.store
    mac = "00:11:22:33:44:55"
    presence(c, NOW, 80)
    for k in range(1, 9):
        presence(c, NOW - k * DAY, 20)
    for d in range(1, 21):
        for h in (5, 6, 7):
            heard(c, mac, NOW - d * DAY + h * HOUR)
    heard(c, mac, NOW)
    device(c, "00:00:00:00:00:02", "Old Co", NOW - 30 * DAY)
    device(c, "00:00:00:00:00:01", "Acme", NOW + 60)
    store.important = {mac}
    m = baseline.BaselineMonitor(ctx)
    c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('baseline_hour', ?)", (str(NOW - HOUR),))
    at = NOW + HOUR + 300
    store.events.clear()
    m.sweep(store, at)
    assert sorted(e[2] for e in store.events) == ["activity_unusual", "unusual_time", "vendor_new"]
    site = next(e for e in store.events if e[2] == "activity_unusual")
    assert site[1] == baseline.SITE and "81 devices" in site[4] and "about 20" in site[4]
    m.sweep(store, at + 600)                                       # same hour again: nothing more
    assert len(store.events) == 3
    again = baseline.BaselineMonitor(ctx)                          # and not after a restart either
    again.sweep(store, at + 900)
    assert len(store.events) == 3


def test_first_run_does_not_judge_the_past_and_waits_for_the_hour_to_settle(ctx):
    store = ctx.store
    m = baseline.BaselineMonitor(ctx)
    store.events.clear()
    m.sweep(store, NOW + HOUR + 300)
    assert store.events == [] and m.done == NOW
    m.sweep(store, NOW + 2 * HOUR + 30)                            # the next hour ended 30 s ago: too early
    assert m.done == NOW
    m.sweep(store, NOW + 2 * HOUR + 180)
    assert m.done == NOW + HOUR


def test_events_are_known_to_the_alert_rules_and_describable(ctx, tmp_path):
    for t in ("activity_unusual", "unusual_time", "vendor_new"):
        assert t in EVENT_TYPES
    assert LATER_RULES["baseline"][1] == ["activity_unusual", "unusual_time"]
    with sqlite3.connect(tmp_path / "t.db") as c:
        assert c.execute("SELECT COUNT(*) FROM alert_rules WHERE name='Unusual activity'").fetchone()[0] == 1
    title, body = describe({"ts": NOW, "mac": baseline.SITE, "type": "activity_unusual", "peer": None, "detail": "80 devices heard"}, None, None, None, "%H:%M:%S")
    assert "80 devices heard" in title + body
