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


def test_fingerprint_drift_alert(ctx):
    s = ctx.store
    t = time.time()
    with ctx.wdb() as c:
        c.execute("INSERT INTO device_meta(mac, known, updated) VALUES(?, 1, ?)", (CL, t))
    s.sweep(t)  # picks up the new "known" device (device_meta has no change hook; sweep re-reads it)
    assert CL in ctx.security.known_macs

    # First fingerprint ever seen for this device: recorded as the baseline, no alert.
    s.process({"t": "wifi_client", "ts": t, "mac": CL, "frame": "probe", "probe": "x",
               "fp": {"wifi": {"sig": "sig-A"}, "src": "probe"}})
    s.flush()
    assert not ctx.rows("SELECT 1 FROM findings WHERE type='fingerprint_changed'")

    # A different fingerprint for the same (known) device: that's the drift alert.
    s.process({"t": "wifi_client", "ts": t + 1, "mac": CL, "frame": "probe", "probe": "x",
               "fp": {"wifi": {"sig": "sig-B"}, "src": "probe"}})
    s.flush()
    f = ctx.one("SELECT * FROM findings WHERE type='fingerprint_changed'")
    assert f and f["mac"] == CL and f["severity"] == "medium"
    assert "fingerprint_changed" in {r["type"] for r in ctx.rows("SELECT type FROM events")}

    # The same device probing on another band with a different layout is normal, not drift.
    s.process({"t": "wifi_client", "ts": t + 2, "mac": CL, "frame": "probe", "probe": "x", "band": "2.4",
               "fp": {"wifi": {"sig": "sig-24"}, "src": "probe"}})
    s.process({"t": "wifi_client", "ts": t + 3, "mac": CL, "frame": "probe", "probe": "x", "band": "5",
               "fp": {"wifi": {"sig": "sig-5"}, "src": "probe"}})
    s.process({"t": "wifi_client", "ts": t + 4, "mac": CL, "frame": "probe", "probe": "x", "band": "2.4",
               "fp": {"wifi": {"sig": "sig-24"}, "src": "probe"}})
    s.flush()
    assert ctx.one("SELECT COUNT(*) n FROM findings WHERE type='fingerprint_changed'")["n"] == 1

    # An unknown device with the exact same kind of change raises nothing.
    other = "a4:83:e7:01:00:02"
    s.process({"t": "wifi_client", "ts": t, "mac": other, "frame": "probe", "probe": "x",
               "fp": {"wifi": {"sig": "sig-A"}, "src": "probe"}})
    s.process({"t": "wifi_client", "ts": t + 1, "mac": other, "frame": "probe", "probe": "x",
               "fp": {"wifi": {"sig": "sig-B"}, "src": "probe"}})
    s.flush()
    assert ctx.one("SELECT COUNT(*) n FROM findings WHERE type='fingerprint_changed'")["n"] == 1


def _finding(ctx, type_):
    ctx.store.flush()
    return ctx.one("SELECT * FROM findings WHERE type=?", (type_,))


def test_handshake_attack_detection(ctx):
    s = ctx.store
    ctx.settings.set("networks", {"ssids": ["HomeNet"], "trusted_bssids": [AP]})
    t = time.time()
    s.process({"t": "wifi_ap", "ts": t, "mac": AP, "ssid": "HomeNet", "enc": "WPA2/PSK,WPA3/SAE"})
    kick = lambda ts, mac, **kw: s.process({"t": "wifi_client", "ts": ts, "mac": mac, "bssid": AP, "frame": "deauth",
                                              "reason": 7, **kw})
    rejoin = lambda ts, mac: s.process({"t": "wifi_client", "ts": ts, "mac": mac, "bssid": AP, "frame": "assoc"})

    # The client leaving by itself (not sent by the AP), a slow rejoin and a rejoin that never happens: nothing.
    for i in range(6):
        kick(t + i * 20, CL)
        rejoin(t + i * 20 + 2, CL)
    slow = "a4:83:e7:01:00:02"
    for i in range(6):
        kick(t + i * 20, slow, from_ap=True)
        rejoin(t + i * 20 + 60, slow)
    s.process({"t": "wifi_client", "ts": t, "mac": "a4:83:e7:01:00:03", "bssid": "24:a4:3c:99:99:99", "frame": "deauth",
               "from_ap": True})
    assert not _finding(ctx, "handshake_attack")

    # Kicked by the AP and straight back, four times in a few minutes: well under the flood threshold.
    for i in range(4):
        kick(t + 100 + i * 30, CL, from_ap=True)
        rejoin(t + 100 + i * 30 + 2, CL)
    f = _finding(ctx, "handshake_attack")
    assert f and f["severity"] == "high" and f["mac"] == AP and f["ssid"] == "HomeNet" and CL in f["detail"]
    assert not _finding(ctx, "deauth_flood")
    assert "handshake_attack" in {r["type"] for r in ctx.rows("SELECT type FROM events")}


def test_ap_security_downgrade(ctx):
    s = ctx.store
    ctx.settings.set("networks", {"ssids": ["HomeNet"], "trusted_bssids": [AP]})
    t = time.time()
    beacon = lambda i, enc: s.process({"t": "wifi_ap", "ts": t + i, "mac": AP, "ssid": "HomeNet", "enc": enc})
    beacon(0, "WPA2/PSK,WPA3/SAE")
    # A single odd beacon, or one that recovers before three in a row, isn't believed.
    beacon(1, "WPA2/PSK"); beacon(2, "WPA2/PSK"); beacon(3, "WPA2/PSK,WPA3/SAE")
    beacon(4, "WPA2/PSK"); beacon(5, "WPA2/PSK")
    assert not _finding(ctx, "ap_downgrade")
    beacon(6, "WPA2/PSK")
    f = _finding(ctx, "ap_downgrade")
    assert f and f["severity"] == "medium" and "WPA3/SAE" in f["detail"] and f["mac"] == AP
    assert ctx.one("SELECT rank FROM ap_enc WHERE mac=?", (AP,))["rank"] == 4  # baseline survives for restarts

    # Dropping all the way to open is the worst case.
    for i in range(7, 10):
        beacon(i, "OPN")
    assert _finding(ctx, "ap_downgrade")["severity"] == "high"

    # Resolving the finding accepts the new level as normal: the baseline is relearned from what's seen next.
    ctx.security.accept_security(AP)
    for i in range(10, 16):
        beacon(i, "WPA2/PSK")
    assert ctx.security.enc_base[AP][0] == 3 and ctx.security.down_count.get(AP) is None


def test_probe_scan_detection(ctx):
    s = ctx.store
    t = time.time()
    probe = lambda i, mac: s.process({"t": "wifi_client", "ts": t + i, "mac": mac, "frame": "probe", "probe": f"net-{i}"})
    for i in range(20):  # a long saved-network list, but not scanner-long
        probe(i, CL)
    assert not _finding(ctx, "probe_scan")
    scanner = "a4:83:e7:01:00:09"
    for i in range(30):
        probe(i, scanner)
    f = _finding(ctx, "probe_scan")
    assert f and f["mac"] == scanner and f["severity"] == "medium"
    # The same names spread over far more than the window don't add up.
    slow = "a4:83:e7:01:00:0a"
    for i in range(30):
        probe(i * 10, slow)
    assert ctx.one("SELECT COUNT(*) n FROM findings WHERE type='probe_scan'")["n"] == 1


def test_mac_duplicate_detection(ctx):
    s = ctx.store
    t = time.time()
    fp = lambda sig: {"wifi": {"sig": sig}, "src": "probe"}
    # One device on two bands legitimately sends different probe layouts on each; that's not a clone.
    for i in range(8):
        s.process({"t": "wifi_client", "ts": t + i, "mac": CL, "frame": "probe", "probe": "x", "band": "2.4" if i % 2 else "5",
                   "fp": fp("sig-24" if i % 2 else "sig-5")})
    assert not _finding(ctx, "mac_duplicate")
    # Two chipsets sharing one address on the same band: the layout flips back and forth.
    clone = "a4:83:e7:01:00:0b"
    for i in range(6):
        s.process({"t": "wifi_client", "ts": t + i, "mac": clone, "frame": "probe", "probe": "x", "band": "5",
                   "fp": fp("sig-A" if i % 2 == 0 else "sig-B")})
    f = _finding(ctx, "mac_duplicate")
    assert f and f["mac"] == clone and f["severity"] == "medium" and "fingerprint" in f["detail"]
    # One sensor hearing the address leap between close and far, again and again.
    twin = "a4:83:e7:01:00:0c"
    for i in range(8):
        s.process({"t": "wifi_client", "ts": t + i, "mac": twin, "frame": "data", "rssi": -35 if i % 2 else -80})
    s.flush()
    assert ctx.one("SELECT detail FROM findings WHERE mac=? AND type='mac_duplicate'", (twin,))
    # A steadily moving device (big change only once) is fine.
    walker = "a4:83:e7:01:00:0d"
    for i in range(8):
        s.process({"t": "wifi_client", "ts": t + i, "mac": walker, "frame": "data", "rssi": -35 if i < 4 else -80})
    s.flush()
    assert not ctx.one("SELECT 1 FROM findings WHERE mac=? AND type='mac_duplicate'", (walker,))


def test_remote_deauth_keeps_ap_origin():
    from sniffowireless import sanitize
    o = {"t": "wifi_client", "ts": time.time(), "mac": CL, "bssid": AP, "frame": "deauth", "reason": 7, "from_ap": True}
    assert sanitize.remote_observation(o, time.time())["from_ap"] is True
    o.pop("from_ap")
    assert "from_ap" not in sanitize.remote_observation(o, time.time())


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
