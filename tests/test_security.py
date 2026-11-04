"""Security tests: auth, CSRF/origin, headers/CSP, input validation, ingest sanitising, uploads, limits."""
import gzip
import json
import os
import time

import pytest

pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from sniffowireless.auth import hash_password  # noqa: E402
from sniffowireless.config import Config  # noqa: E402
from sniffowireless.main import build  # noqa: E402
from sniffowireless.sanitize import clean_str, remote_observation  # noqa: E402
from sniffowireless.web import create_app  # noqa: E402

PW = "correct-horse-battery"
H = {"X-Sniffowireless": "1"}


@pytest.fixture
def env(tmp_path):
    ctx = build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))
    with ctx.wdb() as c:
        c.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('admin', ?, 'admin', 0)",
                  (hash_password(PW, iterations=1000),))
        c.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('viewer', ?, 'viewer', 0)",
                  (hash_password(PW, iterations=1000),))
    client = TestClient(create_app(ctx), base_url="http://sniffowireless.test")
    return ctx, client


def login(client, user="admin"):
    r = client.post("/api/auth/login", json={"username": user, "password": PW})
    assert r.status_code == 200, r.text
    return client


def test_unauthenticated_access_denied(env):
    _, c = env
    for path in ("/api/summary", "/api/devices", "/api/search?q=ab", "/api/backup/config", "/metrics", "/api/docs"):
        assert c.get(path).status_code == 401, path
    r = c.get("/", follow_redirects=False)
    assert r.status_code in (302, 307) and r.headers["location"] == "/login"


def test_security_headers_and_csp(env):
    _, c = env
    r = c.get("/login")
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]
    assert "frame-ancestors 'none'" in csp and "object-src 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "server" not in {k.lower() for k in r.headers} or "uvicorn" not in r.headers.get("server", "")
    login(c)
    assert c.get("/api/summary").headers["cache-control"] == "no-store"
    # no inline scripts / handlers in the shipped HTML (they'd be blocked by the CSP)
    for page in ("/", "/login"):
        html = c.get(page).text
        assert "<script>" not in html and "onerror=" not in html and "onclick=" not in html


def test_csrf_and_origin(env):
    _, c = env
    login(c)
    assert c.put("/api/settings/networks", json={"ssids": ["X"]}).status_code == 403  # no X-Sniffowireless header
    r = c.put("/api/settings/networks", json={"ssids": ["X"]}, headers={**H, "Origin": "https://evil.example"})
    assert r.status_code == 403
    assert c.put("/api/settings/networks", json={"ssids": ["X"]}, headers={**H, "Origin": "http://sniffowireless.test"}).status_code == 200
    # login CSRF from another site is refused as well
    r = c.post("/api/auth/login", json={"username": "admin", "password": PW}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_login_throttle_and_enumeration(env):
    _, c = env
    t0 = time.time()
    assert c.post("/api/auth/login", json={"username": "nobody", "password": "x" * 12}).status_code == 401
    t_missing = time.time() - t0
    t0 = time.time()
    assert c.post("/api/auth/login", json={"username": "admin", "password": "x" * 12}).status_code == 401
    t_wrong = time.time() - t0
    assert t_missing > t_wrong * 0.3  # unknown users also pay for a hash (no fast path)
    codes = [c.post("/api/auth/login", json={"username": "admin", "password": "wrong-pass-1"}).status_code
             for _ in range(12)]
    assert 429 in codes
    assert c.post("/api/auth/login", json={"username": "admin", "password": PW}).status_code == 429  # locked out


def test_viewer_cannot_write(env):
    _, c = env
    login(c, "viewer")
    assert c.get("/api/summary").status_code == 200
    for method, path, body in (("put", "/api/settings/ignore", {"macs": []}), ("post", "/api/users", {}),
                               ("get", "/api/backup/config", None), ("post", "/api/tokens", {"name": "x"})):
        r = getattr(c, method)(path, headers=H, **({"json": body} if body is not None else {}))
        assert r.status_code in (403, 422), (path, r.status_code)


def test_input_validation(env):
    ctx, c = env
    login(c)
    bad = [
        ("put", "/api/settings/ignore", {"macs": ["not-a-mac"]}),
        ("put", "/api/settings/ignore", {"prefixes": ["zz:zz"]}),
        ("put", "/api/settings/networks", {"ssids": ["x" * 200]}),
        ("put", "/api/devices/aa:bb:cc:dd:ee:ff/meta", {"label": "x" * 500}),
        ("put", "/api/devices/notamac/meta", {"label": "x"}),
        ("post", "/api/groups", {"name": "g", "kind": "<script>"}),
        ("post", "/api/groups", {"name": "   "}),
        ("put", "/api/settings/security", {"deauth_threshold": "lots"}),
        ("put", "/api/settings/report", {"hour": 99}),
        ("post", "/api/notifiers", {"name": "x", "type": "webhook", "config": {"url": "file:///etc/passwd"}}),
        ("post", "/api/notifiers", {"name": "x", "type": "ntfy", "config": {"topic": "a b\r\nX-Evil: 1"}}),
        ("post", "/api/notifiers", {"name": "x", "type": "email", "config": {"host": "smtp", "to": "a@b.c\r\nBcc: x@y.z"}}),
        ("post", "/api/alert-rules", {"name": "r", "events": ["arrived"], "schedule": {"start": "25:99", "end": "x"}}),
        ("post", "/api/alert-rules", {"name": "r", "events": ["arrived"], "target": {"mode": "macs", "macs": ["x"]}}),
        ("post", "/api/alert-rules", {"name": "r", "events": ["arrived"], "cooldown": -5}),
        ("post", "/api/users", {"username": "bad name!", "password": "long-enough-pass"}),
        ("post", "/api/users", {"username": "bob", "password": "aaaaaaaaaaaa"}),
        ("post", "/api/users", {"username": "bob", "password": "long-enough-pass", "role": "root"}),
        ("post", "/api/tokens", {"name": "x", "scope": "sensor"}),
        ("put", "/api/backup/settings", {"hour": "x"}),
        ("put", "/api/sensors/local", {"x": 5}),
    ]
    for method, path, body in bad:
        r = getattr(c, method)(path, json=body, headers=H)
        assert r.status_code in (400, 422), (path, body, r.status_code, r.text)
    # notes keep newlines but lose control characters; labels are stripped of them
    r = c.put("/api/devices/AA-BB-CC-DD-EE-FF/meta", json={"label": "Sam‮\x00phone", "notes": "line1\nline2\x07"},
              headers=H)
    assert r.status_code == 200 and r.json()["label"] == "Samphone" and r.json()["notes"] == "line1\nline2"
    assert ctx.one("SELECT mac FROM device_meta")["mac"] == "aa:bb:cc:dd:ee:ff"


def test_query_limits(env):
    _, c = env
    login(c)
    assert c.get("/api/timeline?hours=24&bucket=1").status_code == 400
    assert c.get("/api/timeline?hours=1e9").status_code == 400
    assert c.get("/api/devices?limit=999999").status_code == 400
    assert c.get("/api/timeline?hours=24").status_code == 200
    assert c.get("/api/search?q=" + "a" * 500).status_code == 422


def test_body_size_limit(env):
    _, c = env
    login(c)
    r = c.put("/api/settings/networks", content=b"{" + b" " * (2 * 1024 * 1024) + b"}",
              headers={**H, "Content-Type": "application/json"})
    assert r.status_code == 413


def test_ingest_sanitises_remote_data(env):
    ctx, c = env
    login(c)
    s = c.post("/api/sensors", json={"name": "Pi"}, headers=H).json()
    tok = {"Authorization": f"Bearer {s['token']}"}
    plain = TestClient(c.app, base_url="http://sniffowireless.test")
    now = time.time()
    batch = {"sent_at": now, "obs": [
        {"t": "_cmd", "ts": now, "mac": "-", "fn": "boom"},                                   # internal command
        {"t": "bt", "kind": "<img src=x onerror=alert(1)>", "ts": now, "mac": "aa:bb:cc:dd:ee:01"},  # bad kind
        {"t": "wifi_ap", "ts": now, "mac": "nope", "ssid": "x"},                              # bad MAC
        {"t": "wifi_ap", "ts": now, "mac": "aa:bb:cc:dd:ee:02", "ssid": "Evil\r\n<script>", "band": "<b>",
         "channel": "<svg>", "rssi": "-40"},
        {"t": "event", "ts": now, "mac": "aa:bb:cc:dd:ee:03", "type": "rogue_ap", "detail": "forged"},  # not allowed
    ], "status": [{"name": "wifi:wlan1", "pps": "<img>", "packets": "1e999", "state": "x" * 500}]}
    r = plain.post("/api/ingest", json=batch, headers=tok)
    assert r.status_code == 200 and r.json() == {"accepted": 1, "rejected": 4}
    o = remote_observation(batch["obs"][3], now)
    assert o["ssid"] == "Evil<script>" and "band" not in o and "channel" not in o and o["rssi"] == -40
    from sniffowireless import status
    st = status.SENSORS[f"{s['id']}/wifi:wlan1"]
    assert "pps" not in st and "packets" not in st and len(st["state"]) == 32
    bomb = gzip.compress(b"[" + b"0," * (40 * 1024 * 1024) + b"0]")
    r = plain.post("/api/ingest", content=bomb, headers={**tok, "Content-Encoding": "gzip"})
    assert r.status_code == 413
    assert plain.post("/api/ingest", json=batch).status_code == 401  # no token


def test_floorplan_upload_is_validated_and_served_inert(env):
    _, c = env
    login(c)
    r = c.post("/api/floorplan", content=b"<html><script>alert(1)</script>",
               headers={**H, "Content-Type": "image/png"})
    assert r.status_code == 415  # content, not the claimed type, decides
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><script>alert(2)</script><a href="javascript:x"/></svg>'
    assert c.post("/api/floorplan", content=svg, headers={**H, "Content-Type": "image/svg+xml"}).status_code == 200
    r = c.get("/api/floorplan/image")
    assert b"script" not in r.content and b"onload" not in r.content and b"javascript:" not in r.content
    assert "sandbox" in r.headers["content-security-policy"] and r.headers["content-type"].startswith("image/svg")


def test_csv_formula_injection(env):
    ctx, c = env
    ctx.store.process({"t": "wifi_ap", "ts": time.time(), "mac": "aa:bb:cc:dd:ee:04", "ssid": "=HYPERLINK(\"x\")"})
    ctx.store.flush()
    login(c)
    body = c.get("/api/export/devices.csv").text
    assert "'=HYPERLINK" in body


def test_device_export_honours_filters(env):
    ctx, c = env
    now = time.time()
    ctx.store.process({"t": "wifi_ap", "ts": now, "mac": "aa:bb:cc:dd:ee:10", "ssid": "Keep"})
    ctx.store.process({"t": "wifi_ap", "ts": now, "mac": "aa:bb:cc:dd:ee:11", "ssid": "Skip"})
    ctx.store.flush()
    login(c)
    assert "Keep" in c.get("/api/export/devices.csv").text and "Skip" in c.get("/api/export/devices.csv").text
    body = c.get("/api/export/devices.csv", params={"q": "Keep"}).text
    assert "Keep" in body and "Skip" not in body
    r = c.get("/api/export/devices.json", params={"q": "Keep"})
    assert r.headers["content-disposition"].startswith("attachment")
    assert [d["ssid"] for d in r.json()["devices"]] == ["Keep"]
    assert c.get("/api/devices", params={"q": "Skip"}).json()["total"] == 1


def test_allowed_hosts(tmp_path):
    ctx = build(Config(db_path=str(tmp_path / "h.db"), data_dir=str(tmp_path), allowed_hosts=["sniffowireless.lan"]))
    assert TestClient(create_app(ctx), base_url="http://evil.example").get("/api/health").status_code == 421
    assert TestClient(create_app(ctx), base_url="http://sniffowireless.lan").get("/api/health").status_code == 200


def test_clean_str():
    assert clean_str("a\x00b‮c\r\nd") == "abcd"
    assert clean_str("x" * 500, 10) == "x" * 10
    assert clean_str(None) is None and clean_str("\x01") is None


def test_logs_admin_only_and_redacted(env):
    import logging

    from sniffowireless.logs import HANDLER, install
    install("INFO")
    _, c = env
    logging.getLogger("sniffowireless.auth").warning("No accounts exist yet ... setup code: ABCD-1234-EF56")
    logging.getLogger("sniffowireless.test").info("token sniffowireless_%s used", "x" * 30)
    logging.getLogger("sniffowireless.test").info("ssid <script>alert(1)</script>")
    assert c.get("/api/logs").status_code == 401
    login(c, "viewer")
    assert c.get("/api/logs").status_code == 403 and c.get("/api/logs/stream").status_code == 403
    c.post("/api/auth/logout", headers=H)
    login(c)
    items = c.get("/api/logs?limit=50").json()["items"]
    text = "\n".join(i["msg"] for i in items)
    assert "ABCD-1234-EF56" not in text and "setup code: ••••" in text and "sniffowireless_xxx" not in text
    assert "<script>alert(1)</script>" in text  # raw in JSON; the page renders it as text, never HTML
    after = items[-1]["id"]
    logging.getLogger("sniffowireless.test").error("fresh line")
    new = c.get(f"/api/logs?after={after}").json()["items"]
    assert [i["msg"] for i in new][-1] == "fresh line" and all(i["id"] > after for i in new)
    assert c.put("/api/logs/level", json={"level": "DEBUG"}, headers=H).json() == {"level": "DEBUG"}
    assert logging.getLogger().level == logging.DEBUG
    assert c.put("/api/logs/level", json={"level": "TRACE"}, headers=H).status_code == 422
    c.put("/api/logs/level", json={"level": "INFO"}, headers=H)
    assert HANDLER.buf.maxlen == 5000


def test_investigations_api(env):
    ctx, c = env
    ctx.store.process({"t": "wifi_ap", "ts": time.time(), "mac": "0a:00:00:00:00:01", "ssid": "Café <b>", "enc": "OPN"})
    ctx.store.flush()
    login(c)
    assert c.put("/api/settings/investigate", json={"ssids": [{"ssid": "x" * 100}]}, headers=H).status_code == 422
    r = c.put("/api/settings/investigate", json={"ssids": [{"ssid": "Café <b>", "note": "who?\x07"}, {"ssid": "Café <b>"}]},
              headers=H)
    assert r.json()["count"] == 1
    entry = c.get("/api/settings/investigate").json()["ssids"][0]
    assert entry["note"] == "who?" and entry["added"]
    lst = c.get("/api/investigations").json()["items"]
    assert lst[0]["ssid"] == "Café <b>" and lst[0]["aps"] == 1
    d = c.get("/api/investigations/" + "Caf%C3%A9%20%3Cb%3E").json()
    assert d["investigated"] and d["aps"][0]["mac"] == "0a:00:00:00:00:01"
    assert [x["ssid"] for x in c.get("/api/ssids?q=caf").json()["items"]] == ["Café <b>"]
    c.post("/api/auth/logout", headers=H)
    login(c, "viewer")
    assert c.get("/api/investigations").status_code == 200
    assert c.put("/api/settings/investigate", json={"ssids": []}, headers=H).status_code == 403


def test_remote_csa_is_validated():
    from sniffowireless.sanitize import remote_observation
    base = {"t": "wifi_ap", "ts": time.time(), "mac": "0a:00:00:00:00:01", "channel": 100}
    ok = remote_observation({**base, "csa": {"mode": 1, "new_channel": 36, "count": 5, "x": "<script>"}}, time.time())
    assert ok["csa"] == {"mode": 1, "new_channel": 36, "count": 5}
    assert remote_observation({**base, "csa": {"new_channel": 999}}, time.time()).get("csa") is None
    assert remote_observation({**base, "csa": "36"}, time.time()).get("csa") is None


def test_timeline_per_band(env):
    ctx, c = env
    s = ctx.store
    t = time.time() - 1800
    s.process({"t": "wifi_ap", "ts": t, "mac": "24:a4:3c:00:00:01", "ssid": "H", "freq": 2412, "band": "2.4", "channel": 1})
    s.process({"t": "wifi_ap", "ts": t, "mac": "24:a4:3c:00:00:02", "ssid": "H", "freq": 5180, "band": "5", "channel": 36})
    s.process({"t": "wifi_ap", "ts": t, "mac": "24:a4:3c:00:00:03", "ssid": "H", "freq": 6135, "band": "6", "channel": 37})
    phone = "a4:83:e7:00:00:01"  # connected on 2.4 GHz first, then roams to 5 GHz
    for i in range(0, 600, 60):
        s.process({"t": "wifi_client", "ts": t + i, "mac": phone, "bssid": "24:a4:3c:00:00:01", "frame": "data",
                   "band": "2.4", "freq": 2412})
    for i in range(600, 1200, 60):
        s.process({"t": "wifi_client", "ts": t + i, "mac": phone, "bssid": "24:a4:3c:00:00:02", "frame": "data",
                   "band": "5", "freq": 5180})
    s.flush()
    login(c)
    r = c.get("/api/timeline?hours=1").json()
    b = r["bands"]
    assert set(b) == {"2.4", "5", "6"} and all(len(v["connected"]) == len(r["t"]) for v in b.values())
    assert max(b["2.4"]["ap"]) == 1 and max(b["5"]["ap"]) == 1 and max(b["6"]["ap"]) == 1
    assert max(b["2.4"]["connected"]) == 1 and max(b["5"]["connected"]) == 1 and max(b["6"]["connected"]) == 0
    assert max(b["5"]["wifi_client"]) == 1 and max(b["2.4"]["wifi_client"]) == 0  # last heard on 5 GHz


def test_appearance(env):
    ctx, c = env
    a = c.get("/api/appearance").json()  # public: the sign-in page uses it too
    assert a["name"] == "sniffowireless" and a["icon"] == "dot" and a["colors"]["ap"] == "#4cc2ff" and a["custom_colors"] == []
    body = {"name": "Home <b>radar</b>", "icon": "radar", "colors": {"ap": "#FF8800", "bg": "#0b0c0e"}}
    assert c.put("/api/appearance", json=body, headers=H).status_code == 401
    login(c, "viewer")
    assert c.put("/api/appearance", json=body, headers=H).status_code == 403
    c.cookies.clear()
    login(c)
    for bad in ({"colors": {"ap": "red"}}, {"colors": {"ap": "#ff0000;x"}}, {"colors": {"evil": "#ffffff"}},
                {"icon": "../etc"}, {"name": "x" * 40}, {"icon": "custom"}):
        assert c.put("/api/appearance", json={**body, **bad}, headers=H).status_code in (400, 422), bad
    r = c.put("/api/appearance", json=body, headers=H).json()
    assert r["icon"] == "radar" and r["colors"]["ap"] == "#ff8800" and r["custom_colors"] == ["ap"]  # default bg not stored
    assert "<" not in r["name"]
    # icon upload: only real raster images, served with a locked-down CSP
    assert c.post("/api/appearance/icon", content=b"<svg onload=alert(1)>", headers=H).status_code == 415
    png = b"\x89PNG\r\n\x1a\n" + b"\0" * 64
    assert c.post("/api/appearance/icon", content=b"\x89PNG\r\n\x1a\n" + b"\0" * (300 * 1024), headers=H).status_code == 413
    r = c.post("/api/appearance/icon", content=png, headers=H).json()
    assert r["icon"] == "custom" and r["icon_url"].startswith("/api/appearance/icon")
    c.cookies.clear()
    ic = c.get("/api/appearance/icon")
    assert ic.status_code == 200 and ic.headers["content-type"] == "image/png" and "sandbox" in ic.headers["content-security-policy"]
    # a tampered config backup can't make it serve or delete other files
    ctx.settings.set("appearance", {**ctx.settings.get("appearance"), "icon_file": "../t.db"})
    assert c.get("/api/appearance/icon").status_code == 404 and c.get("/api/appearance").json()["icon"] == "dot"
    login(c)
    assert c.delete("/api/appearance/icon", headers=H).status_code == 200
    assert os.path.exists(ctx.cfg.db_path)


def test_stats_ssids_capped(env):
    ctx, c = env
    now = time.time()
    for i in range(130):
        ctx.store.process({"t": "wifi_ap", "ts": now - 3000 + i * 10, "mac": f"24:a4:3c:00:{i // 256:02x}:{i % 256:02x}",
                           "ssid": f"Net{i:03d}", "freq": 2412, "band": "2.4", "channel": 1})
    ctx.store.flush()
    login(c)
    s = c.get("/api/stats?days=1").json()
    assert s["ssid_total"] == 130 and len(s["ssids"]) == 100
    assert s["ssids"][0]["ssid"] == "Net129" and s["ssids"][0]["last_seen"] >= s["ssids"][-1]["last_seen"]


def test_status_system(env):
    ctx, c = env
    login(c)
    c.get("/api/status")
    time.sleep(1.1)
    s = c.get("/api/status").json()["system"]
    assert s["cpu"]["cores"] >= 1 and (s["cpu"]["percent"] is None or 0 <= s["cpu"]["percent"] <= 100)
    assert s["memory"]["total"] and 0 < s["memory"]["used"] <= s["memory"]["total"]
    assert s["db"]["bytes"] > 0 and s["disk"]["total"] > 0


def test_clock_setting(env):
    from sniffowireless.alerts import describe
    from sniffowireless.appearance import time_format
    ctx, c = env
    assert c.get("/api/appearance").json()["clock"] == "auto" and time_format(ctx) == "%H:%M"
    login(c)
    base = {"name": "sniffowireless", "icon": "dot", "colors": {}}
    assert c.put("/api/appearance", json={**base, "clock": "13"}, headers=H).status_code == 422
    assert c.put("/api/appearance", json={**base, "clock": "12"}, headers=H).json()["clock"] == "12"
    assert time_format(ctx, seconds=True) == "%I:%M:%S %p"
    ev = {"ts": time.mktime((2026, 11, 3, 15, 4, 5, 0, 0, -1)), "type": "arrived", "mac": "a4:83:e7:00:00:01"}
    _, body = describe(ev, None, None, None, time_format(ctx, seconds=True))
    assert "03:04:05 PM" in body
    _, body = describe(ev, None, None, None)
    assert "15:04:05" in body


def test_stats_per_sensor(env):
    ctx, c = env
    now = time.time()
    ctx.store.process({"t": "wifi_ap", "ts": now, "mac": "aa:bb:cc:00:00:01", "ssid": "A", "rssi": -50, "sensor": "attic"})
    ctx.store.process({"t": "wifi_ap", "ts": now, "mac": "aa:bb:cc:00:00:02", "ssid": "B", "rssi": -50, "sensor": "attic"})
    ctx.store.process({"t": "wifi_ap", "ts": now, "mac": "aa:bb:cc:00:00:02", "ssid": "B", "rssi": -50, "sensor": "cellar"})
    ctx.store.flush()
    login(c)
    got = {(r["id"], r["kind"]): r["n"] for r in c.get("/api/stats?days=1").json()["sensor_kinds"]}
    assert got[("attic", "ap")] == 2 and got[("cellar", "ap")] == 1


def test_sessions_drilldown_and_stats_limit(env):
    ctx, c = env
    now = time.time()
    for i, d in enumerate((30, 120, 400, 400, 5000, 40000)):  # one per bucket, two in the 5-30 min one
        ctx.execute("INSERT INTO sessions(mac,type,peer,start_ts,end_ts,open) VALUES(?,?,?,?,?,0)",
                    (f"aa:bb:cc:00:01:{i:02x}", "assoc", None, now - 100 - d, now - 100))
    login(c)
    assert c.get("/api/sessions", params={"type": "assoc"}).json()["total"] == 6
    assert c.get("/api/sessions", params={"b": 2}).json()["total"] == 2  # 5-30 min
    assert c.get("/api/sessions", params={"b": 5}).json()["total"] == 1  # over 8 h
    items = c.get("/api/sessions", params={"sort": "duration"}).json()["items"]
    assert [round(x["end_ts"] - x["start_ts"]) for x in items][:2] == [40000, 5000]
    # the stats lists honour ?limit=
    for i in range(30):
        ctx.store.process({"t": "wifi_probe", "ts": now, "mac": f"aa:bb:cc:02:00:{i:02x}", "ssid": f"P{i}", "rssi": -60})
    ctx.store.flush()
    assert len(c.get("/api/stats?days=1").json()["probes"]) <= 20
    assert len(c.get("/api/stats?days=1&limit=5").json()["probes"]) <= 5


def test_handshake_api_scope_and_auth(env):
    ctx, c = env
    login(c)
    # Enabling capture for a network not in "My networks" is refused.
    assert c.put("/api/handshakes/HomeNet", json={"enabled": True}, headers=H).status_code == 400
    assert c.put("/api/settings/networks", json={"ssids": ["HomeNet"], "trusted_bssids": []}, headers=H).status_code == 200
    assert c.put("/api/handshakes/HomeNet", json={"enabled": True}, headers=H).status_code == 200
    assert c.get("/api/handshakes").json()["items"][0] == {
        "ssid": "HomeNet", "enabled": True, "bssids": [], "pairs": 0, "usable_pairs": 0, "frames": 0,
        "bytes": 0, "started": None, "updated": None, "downloadable": False}
    # No capture yet, so there's nothing to download.
    assert c.get("/api/handshakes/HomeNet/capture.pcap").status_code == 404

    # A viewer (non-admin) can't see or change any of this.
    c.cookies.clear()
    login(c, "viewer")
    assert c.get("/api/handshakes").status_code == 403
    assert c.put("/api/handshakes/HomeNet", json={"enabled": False}, headers=H).status_code == 403
    assert c.get("/api/handshakes/HomeNet/capture.pcap").status_code == 403
    assert c.delete("/api/handshakes/HomeNet", headers=H).status_code == 403

    c.cookies.clear()
    login(c)
    ctx.handshake.note_ap("24:a4:3c:10:00:01", "HomeNet")
    from tests.test_core import eapol_frame
    STA = "a4:83:e7:01:00:01"
    ctx.handshake.feed(eapol_frame(ack=True, mic=False, secure=False, src="24:a4:3c:10:00:01", dst=STA),
                       "24:a4:3c:10:00:01", STA, 1)
    r = c.get("/api/handshakes/HomeNet/capture.pcap")
    assert r.status_code == 200 and r.headers["content-type"] == "application/vnd.tcpdump.pcap"
    assert len(r.content) > 0

    assert c.delete("/api/handshakes/HomeNet", headers=H).status_code == 200
    assert c.get("/api/handshakes/HomeNet/capture.pcap").status_code == 404


def test_play_sound_api(env, monkeypatch):
    ctx, c = env
    now = time.time()
    AP = "24:a4:3c:10:00:01"
    TAG = "aa:bb:cc:dd:ee:01"
    ctx.store.process({"t": "wifi_ap", "ts": now, "mac": AP, "ssid": "HomeNet"})
    ctx.store.process({"t": "bt", "kind": "ble", "ts": now, "mac": TAG, "rssi": -70, "randomized": True})
    ctx.store.flush()
    login(c)

    # No Bluetooth adapter configured: a clear error, not a hang or a crash.
    assert c.post(f"/api/devices/{AP}/sound", headers=H).status_code == 400  # not a BLE device
    assert c.post(f"/api/devices/{TAG}/sound", headers=H).status_code == 400  # BT_DEVICES unset in this test env
    assert c.post("/api/devices/aa:bb:cc:dd:ee:99/sound", headers=H).status_code == 404

    # With an adapter "configured", the actual radio call is mocked: verify the endpoint wires it up and
    # maps tracker_sound.SoundError to a clear HTTP error rather than a 500.
    ctx.cfg.bt_devices = ["hci0"]
    import sniffowireless.web as web_mod

    def fake_play_sound(iface, mac, addr_type):
        assert iface == "hci0" and mac == TAG and addr_type == 1  # randomized -> non-public address type
        raise web_mod.tracker_sound.SoundError("no sound-alert service")
    monkeypatch.setattr(web_mod.tracker_sound, "play_sound", fake_play_sound)
    r = c.post(f"/api/devices/{TAG}/sound", headers=H)
    assert r.status_code == 502 and "no sound-alert service" in r.json()["detail"]

    monkeypatch.setattr(web_mod.tracker_sound, "play_sound", lambda iface, mac, addr_type: None)
    assert c.post(f"/api/devices/{TAG}/sound", headers=H).json() == {"ok": True}
