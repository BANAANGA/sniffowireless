"""The scheduled report: daily or weekly, with what needs a look (new devices, trackers, security events, offline sensors)."""
import time

import pytest

from sniffowireless import reports, status
from sniffowireless.config import Config
from sniffowireless.main import build
from sniffowireless.manage import validate_setting


@pytest.fixture
def ctx(tmp_path):
    status.SENSORS.clear()
    return build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))


def fill(ctx, now):
    with ctx.wdb() as w:
        w.execute("INSERT INTO devices(mac, kind, first_seen, last_seen, vendor, name, dev_type, randomized) VALUES"
                  "('00:11:22:33:44:55', 'wifi_client', ?, ?, 'Acme', '<b>Printer</b>', 'printer', 0)", (now - 3600, now))
        w.execute("INSERT INTO devices(mac, kind, first_seen, last_seen, randomized) VALUES('02:11:22:33:44:66', 'wifi_client', ?, ?, 1)", (now - 3600, now))
        w.execute("INSERT INTO devices(mac, kind, first_seen, last_seen, vendor, randomized) VALUES('00:11:22:33:44:77', 'ble', ?, ?, 'Old', 0)", (now - 3 * 86400, now))
        for ts, mac, typ, detail in ((now - 600, "4a:00:00:00:00:01", "tracker_following", "AirTag following Sam"),
                                     (now - 700, "00:aa:00:00:00:01", "rogue_ap", "HomeNet"), (now - 800, "00:aa:00:00:00:02", "rogue_ap", "HomeNet"),
                                     (now - 900, "00:aa:00:00:00:03", "new_device", None),           # low severity: not listed
                                     (now - 3 * 86400, "00:aa:00:00:00:04", "deauth_flood", None)):  # before a daily period
            w.execute("INSERT INTO events(ts, mac, type, detail) VALUES(?,?,?,?)", (ts, mac, typ, detail))
        w.execute("INSERT INTO sensors(id, name, last_seen) VALUES('s1', 'Garage', ?)", (now - 7200,))
        w.execute("INSERT INTO sensors(id, name, last_seen) VALUES('s2', 'Hall', ?)", (now - 10,))


def test_digest_sections(ctx):
    now = time.time()
    fill(ctx, now)
    got = dict(reports.digest_lines(ctx, now - 86400, now))
    assert got["New devices"] == ["<b>Printer</b> · Acme · Printer"]           # the random address and the older device are not new devices
    assert len(got["Possible trackers"]) == 1 and "AirTag following Sam" in got["Possible trackers"][0]
    assert got["Security and warnings"] == ["Rogue / evil-twin access point: 2"]
    assert len(got["Sensors offline now"]) == 1 and got["Sensors offline now"][0].startswith("Garage: last report 2h")
    week = dict(reports.digest_lines(ctx, now - 7 * 86400, now))
    assert "Deauthentication flood: 1" in week["Security and warnings"] and len(week["New devices"]) == 2


def test_nothing_to_report_gives_no_sections(ctx):
    now = time.time()
    assert reports.digest_lines(ctx, now - 86400, now) == []


def test_daily_and_weekly_report_text_and_html(ctx):
    fill(ctx, time.time())
    title, text, html = reports.summary(ctx, 1)
    assert title == "sniffowireless daily report"
    assert "Possible trackers" in text and "- Garage: last report" in text and "Rogue / evil-twin access point: 2" in text
    assert "&lt;b&gt;Printer&lt;/b&gt;" in html and "<b>Printer</b>" not in html   # names from the air are escaped in the email
    assert "<h3" in html and "daily report" in html
    title, text, _ = reports.weekly_summary(ctx)
    assert title == "sniffowireless weekly report" and "Deauthentication flood: 1" in text


def at(weekday, hour):
    """A timestamp on that weekday (0 = Monday) and hour, local time."""
    t = time.mktime((2026, 11, 2 + weekday, hour, 30, 0, 0, 0, -1))  # 2 November 2026 is a Monday
    assert time.localtime(t).tm_wday == weekday
    return t


def test_schedule(ctx):
    s = reports.ReportScheduler(ctx)
    weekly = {"email": True, "notifier_id": 1, "weekday": 2, "hour": 8, "last_sent": 0, "daily": False}
    assert s.due(weekly, at(2, 8)) and not s.due(weekly, at(3, 8)) and not s.due(weekly, at(2, 9))
    assert not s.due({**weekly, "last_sent": at(2, 8) - 3 * 86400}, at(2, 8))
    daily = {**weekly, "daily": True}
    assert s.due(daily, at(3, 8)) and s.due(daily, at(5, 8)) and not s.due(daily, at(3, 7))
    assert not s.due({**daily, "last_sent": at(3, 8) - 600}, at(3, 8))          # already sent this hour
    assert s.due({**daily, "last_sent": at(2, 8)}, at(3, 8))                    # yesterday's: due again
    assert not s.due({**daily, "email": False}, at(3, 8)) and not s.due({**daily, "notifier_id": None}, at(3, 8))
    assert not s.due({k: v for k, v in weekly.items() if k != "daily"}, at(3, 8))  # settings saved before this option: weekly


def test_send_uses_the_period_that_is_set(ctx, monkeypatch):
    sent = []
    monkeypatch.setattr(reports, "send", lambda typ, cfg, title, body, html=None: sent.append(title))
    with ctx.wdb() as w:
        w.execute("INSERT INTO notifiers(name, type, config) VALUES('n', 'webhook', '{}')")
        nid = w.execute("SELECT id FROM notifiers").fetchone()[0]
    ctx.settings.set("report", {**ctx.settings.get("report"), "notifier_id": nid, "daily": True})
    ctx.reports.send_now()
    ctx.settings.set("report", {**ctx.settings.get("report"), "daily": False})
    ctx.reports.send_now()
    assert sent == ["sniffowireless daily report", "sniffowireless weekly report"]
    assert ctx.settings.get("report")["last_sent"] > 0


def test_the_setting_is_validated():
    assert validate_setting("report", {"daily": True, "hour": 7}) == {"daily": True, "hour": 7}
    with pytest.raises(Exception):
        validate_setting("report", {"daily": "yes"})
