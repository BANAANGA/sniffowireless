import time

import pytest

from sniffowireless.alerts import describe, in_schedule, matches
from sniffowireless.auth import hash_password, verify_password
from sniffowireless.config import Config
from sniffowireless.main import build
from sniffowireless.manage import apply_ignore, apply_meta
from sniffowireless.metrics import render
from sniffowireless.reports import occupancy
from sniffowireless.survey import recommend

AP = "24:a4:3c:10:00:01"
CL = "a4:83:e7:01:00:01"


@pytest.fixture
def ctx(tmp_path):
    return build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))


def test_passwords():
    h = hash_password("correct-horse-1", iterations=1000)
    assert verify_password("correct-horse-1", h) and not verify_password("wrong", h)
    assert not verify_password("x", "garbage")


def test_auth_sessions_and_tokens(ctx):
    a = ctx.auth
    assert a.needs_setup() and a.setup_code
    with ctx.wdb() as c:
        c.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('admin', ?, 'admin', 0)",
                  (hash_password("correct-horse-1", iterations=1000),))
    token, user = a.login("admin", "correct-horse-1", "1.2.3.4")
    assert user.is_admin and a.from_session(token).username == "admin"
    a.logout(token)
    assert a.from_session(token) is None
    tid, tok = a.create_token("prom", "metrics")
    u = a.from_token(tok)
    assert u.scope == "metrics" and not u.is_admin and a.from_token("nope") is None
    for _ in range(8):
        with pytest.raises(Exception):
            a.login("admin", "bad", "9.9.9.9")
    with pytest.raises(Exception) as e:
        a.login("admin", "correct-horse-1", "9.9.9.9")
    assert getattr(e.value, "status_code", None) == 429


def test_auth_from_env(tmp_path):
    c = build(Config(db_path=str(tmp_path / "e.db"), data_dir=str(tmp_path), web_user="root",
                     web_password="from-environment"))
    assert not c.auth.needs_setup() and c.auth.setup_code is None
    assert c.auth.login("root", "from-environment", "x")[1].is_admin


def test_ignore_rules(ctx):
    s = ctx.store
    ctx.settings.set("ignore", {"macs": ["aa:bb:cc:dd:ee:ff"], "prefixes": ["24:0a:c4"],
                                "ssids": [{"ssid": "Neighbour", "clients": True}]})
    apply_ignore(ctx)
    t = time.time()
    for o in ({"t": "wifi_client", "mac": "aa:bb:cc:dd:ee:ff"}, {"t": "wifi_client", "mac": "24:0a:c4:00:00:01"},
              {"t": "wifi_ap", "mac": "02:00:00:00:00:99", "ssid": "Neighbour"},
              {"t": "wifi_client", "mac": "02:00:00:00:00:98", "bssid": "02:00:00:00:00:99", "frame": "data"},
              {"t": "wifi_ap", "mac": AP, "ssid": "Mine"}):
        s.process({**o, "ts": t})
    s.flush()
    assert [r[0] for r in s.conn.execute("SELECT mac FROM devices")] == [AP]


def test_group_presence_events(ctx):
    s = ctx.store
    with ctx.wdb() as c:
        gid = c.execute("INSERT INTO groups(name, kind) VALUES('Sam', 'person')").lastrowid
        c.execute("INSERT INTO device_meta(mac, group_id, known) VALUES(?, ?, 1)", (CL, gid))
    apply_meta(ctx)
    t0 = time.time() - 2000
    s.process({"t": "wifi_client", "ts": t0, "mac": CL, "frame": "probe", "rssi": -50})
    s.sweep(t0 + 1000)
    s.flush()
    types = [r[0] for r in s.conn.execute("SELECT type FROM events ORDER BY id")]
    assert "group_arrived" in types and "group_left" in types


def test_alert_matching_and_schedule():
    rule = {"events": ["arrived"], "target": {"mode": "watchlist"}}
    ev = {"type": "arrived", "mac": CL, "ts": time.time(), "peer": None, "detail": None}
    assert matches(rule, ev, {"kind": "wifi_client"}, {"watch": 1}, None)
    assert not matches(rule, ev, {"kind": "wifi_client"}, {"watch": 0}, None)
    unknown = {"events": ["arrived"], "target": {"mode": "unknown"}}
    assert matches(unknown, ev, {"kind": "wifi_client", "randomized": 0}, None, None)
    assert not matches(unknown, ev, {"kind": "wifi_client", "randomized": 1}, None, None)
    assert not matches(unknown, ev, {"kind": "wifi_client"}, {"known": 1}, None)
    noon = time.mktime(time.strptime("2026-11-02 12:00", "%Y-%m-%d %H:%M"))
    night = time.mktime(time.strptime("2026-11-02 23:30", "%Y-%m-%d %H:%M"))
    sched = {"start": "23:00", "end": "06:00"}
    assert in_schedule(sched, night) and not in_schedule(sched, noon) and in_schedule({}, noon)
    title, body = describe(ev, {"kind": "wifi_client", "ident": {"label": "Apple"}}, {"label": "Sam's iPhone"}, None)
    assert title == "Sam's iPhone arrived" and CL in body


def test_alert_engine_logs(ctx):
    ctx.alerts.handle({"type": "rogue_ap", "mac": AP, "ts": time.time(), "peer": None, "detail": "evil twin"})
    rows = ctx.rows("SELECT rule_name, severity FROM alert_log")
    assert rows == [{"rule_name": "Security alerts", "severity": "high"}]


def test_security_detectors(ctx):
    s = ctx.store
    ctx.settings.set("networks", {"ssids": ["HomeNet"], "trusted_bssids": [AP]})
    t = time.time()
    s.process({"t": "wifi_ap", "ts": t, "mac": AP, "ssid": "HomeNet", "enc": "WPA2/PSK"})
    s.process({"t": "wifi_ap", "ts": t, "mac": "0a:00:00:00:00:01", "ssid": "HomeNet", "enc": "OPN", "randomized": True})
    for i, ssid in enumerate(["A", "B", "C", "D"]):
        s.process({"t": "wifi_ap", "ts": t + i, "mac": "0a:13:37:00:00:01", "ssid": ssid, "enc": "OPN"})
    for i in range(30):
        s.process({"t": "wifi_client", "ts": t + i * 0.1, "mac": CL, "bssid": AP, "frame": "deauth", "reason": 7})
    s.flush()
    types = {r["type"]: r["severity"] for r in ctx.rows("SELECT type, severity FROM findings")}
    assert types["rogue_ap"] == "high" and types["karma_ap"] == "high" and types["deauth_flood"] == "high"
    assert types["no_wpa3"] == "low"
    events = {r["type"] for r in ctx.rows("SELECT type FROM events")}
    assert {"rogue_ap", "karma_ap", "deauth_flood"} <= events


def test_channel_recommendation():
    aps = [{"mac": "a", "channel": 6, "band": "2.4", "last_rssi": -40}, {"mac": "b", "channel": 6, "band": "2.4",
                                                                         "last_rssi": -50},
           {"mac": "c", "channel": 11, "band": "2.4", "last_rssi": -60}, {"mac": "d", "channel": 36, "band": "5",
                                                                          "last_rssi": -45}]
    rec = recommend(aps, {("2.4", 1): 0.05, ("2.4", 6): 0.6})
    assert rec["2.4"][0]["channel"] == 1 and rec["2.4"][-1]["channel"] == 6
    assert rec["5"][0]["channel"] != 36 and not rec["5"][0]["dfs"]


def test_location_and_survey(ctx):
    s = ctx.store
    with ctx.wdb() as c:
        c.execute("UPDATE sensors SET room='Hall', x=0.5, y=0.9 WHERE id='local'")
        c.execute("INSERT INTO sensors(id, name, room, x, y) VALUES('lr', 'LR', 'Living', 0.2, 0.2)")
    ctx.location.reload()
    t = time.time()
    s.process({"t": "wifi_client", "ts": t, "mac": CL, "frame": "probe", "rssi": -75})
    s.process({"t": "wifi_client", "ts": t, "mac": CL, "frame": "probe", "rssi": -45, "sensor": "lr"})
    s.process({"t": "chan", "ts": t, "mac": "-", "freq": 2437, "dwell_ms": 500, "frames": 100, "bytes": 1,
               "airtime_us": 250_000, "retries": 10, "noise_sum": -950, "noise_cnt": 10})
    s.sweep(t + 1)
    s.flush()
    d = ctx.one("SELECT room, pos_x, pos_y FROM devices WHERE mac=?", (CL,))
    assert d["room"] == "Living" and d["pos_x"] < 0.35 and d["pos_y"] < 0.35
    cs = ctx.one("SELECT * FROM channel_stats")
    assert cs["freq"] == 2437 and cs["airtime_us"] == 250_000


def test_occupancy_and_metrics(ctx):
    s = ctx.store
    now = time.time()
    for k, mac in enumerate(("da:00:00:00:00:01", "da:00:00:00:00:02")):
        for i in range(0, 1800, 60):
            s.process({"t": "wifi_client", "ts": now - 7200 + k * 600 + i, "mac": mac, "frame": "probe", "rssi": -50})
    s.sweep(now)
    s.flush()
    occ = occupancy(ctx, 1)
    assert occ["summary"]["unique"] == 2 and occ["summary"]["peak"] == 2
    text = render(ctx)
    assert 'sniffowireless_devices_total{kind="wifi_client"} 2' in text and "sniffowireless_store_queue" in text


def test_occupancy_splits_visits_at_midnight(ctx):
    s = ctx.store
    start = (int(time.time() // 86400) - 2) * 86400 + 20 * 3600  # 20:00 UTC, two days ago
    for i in range(0, 12 * 3600, 120):  # present until 08:00 the next day
        s.process({"t": "wifi_client", "ts": start + i, "mac": "da:00:00:00:00:09", "frame": "probe", "rssi": -50})
    s.sweep(start + 13 * 3600)
    s.flush()
    occ = occupancy(ctx, 3, tz=0)
    dwell = {d["day"]: d["median_dwell"] for d in occ["days"]}
    assert all(v <= 86400 for v in dwell.values()) and len([v for v in dwell.values() if v]) == 2


def test_occupancy_merges_group_devices(ctx):
    s = ctx.store
    with ctx.wdb() as c:
        gid = c.execute("INSERT INTO groups(name, kind) VALUES('Sam', 'person')").lastrowid
        for m in ("da:00:00:00:00:11", "da:00:00:00:00:12"):
            c.execute("INSERT INTO device_meta(mac, group_id, known) VALUES(?, ?, 1)", (m, gid))
    start = (int(time.time() // 86400) - 1) * 86400 + 10 * 3600  # yesterday 10:00 UTC (no midnight split)
    for m in ("da:00:00:00:00:11", "da:00:00:00:00:12"):  # two devices, same 2 hours
        for i in range(0, 7200, 60):
            s.process({"t": "wifi_client", "ts": start + i, "mac": m, "frame": "probe", "rssi": -50})
    s.sweep(start + 9000)
    s.flush()
    occ = occupancy(ctx, 2, tz=0)
    assert occ["summary"]["unique"] == 1 and 7000 <= occ["summary"]["median_dwell"] <= 7300


def test_global_search(ctx):
    from sniffowireless.search import search
    s = ctx.store
    t = time.time()
    s.process({"t": "wifi_ap", "ts": t, "mac": AP, "ssid": "HomeNet", "rssi": -40})
    s.process({"t": "wifi_client", "ts": t, "mac": CL, "frame": "probe", "probe": "CoffeeShop_Free", "rssi": -50})
    s.process({"t": "lan", "ts": t, "mac": "d8:bb:c1:00:00:01", "ip": "192.168.1.20", "name": "GAMING-PC", "src": "dhcp"})
    s.flush()
    with ctx.wdb() as c:
        c.execute("INSERT INTO device_meta(mac, label, notes, known) VALUES(?, 'Sam phone', 'bought 2024', 1)", (CL,))
        c.execute("INSERT INTO groups(name, kind) VALUES('Sam', 'person')")
        c.execute("INSERT INTO lan_dns VALUES('d8:bb:c1:00:00:01', 'steamcontent.com', 1, 2, 3)")
    r = search(ctx, "sam")["results"]
    assert [d["mac"] for d in r["devices"]] == [CL] and r["groups"][0]["name"] == "Sam"
    assert search(ctx, "a483e7")["results"]["devices"][0]["mac"] == CL  # MAC without separators
    assert search(ctx, "192.168.1.2")["results"]["devices"][0]["name"] == "GAMING-PC"
    assert search(ctx, "coffee")["results"]["probes"][0]["ssid"] == "CoffeeShop_Free"
    assert search(ctx, "homen")["results"]["networks"][0]["ssid"] == "HomeNet"
    assert search(ctx, "steam")["results"]["dns"][0]["devices"] == 1
    assert search(ctx, "2024")["results"]["devices"][0]["mac"] == CL  # notes
    assert search(ctx, "100%")["total"] == 0  # LIKE wildcards are escaped
    assert search(ctx, "x")["total"] == 0  # too short
