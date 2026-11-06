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
    # The per-band and overall series come from one combined query now; they must still add up exactly
    # (each device has one band at a time, so summing the per-band distinct counts for a kind reconstructs
    # the same distinct count the unbanded series reports).
    for i in range(len(r["t"])):
        assert r["series"]["ap"][i] == b["2.4"]["ap"][i] + b["5"]["ap"][i] + b["6"]["ap"][i]
        assert r["series"]["wifi_client"][i] == b["2.4"]["wifi_client"][i] + b["5"]["wifi_client"][i] + b["6"]["wifi_client"][i]


def test_mynet_changes(env):
    ctx, c = env
    login(c)
    assert c.get("/api/mynet/changes").json() == {"configured": False, "items": []}

    AP = "24:a4:3c:00:00:09"
    assert c.put("/api/settings/networks", json={"ssids": ["HomeNet"], "trusted_bssids": []}, headers=H).status_code == 200
    s = ctx.store
    t = time.time() - 60
    # Channel change: an AP on 36 moves to 40, confirmed over a few sightings (no CSA).
    s.process({"t": "wifi_ap", "ts": t, "mac": AP, "ssid": "HomeNet", "band": "5", "channel": 36, "enc": "WPA2/PSK"})
    for i in range(1, 4):
        s.process({"t": "wifi_ap", "ts": t + i, "mac": AP, "ssid": "HomeNet", "band": "5", "channel": 40, "enc": "WPA2/PSK"})
    # Security finding: that same AP is (also) seen broadcasting in the open.
    s.process({"t": "wifi_ap", "ts": t + 5, "mac": AP, "ssid": "HomeNet", "band": "5", "channel": 40, "enc": "OPN"})
    s.flush()

    r = c.get("/api/mynet/changes").json()
    assert r["configured"] and {"channel", "security"} <= {x["type"] for x in r["items"]}
    chg = next(x for x in r["items"] if x["type"] == "channel")
    assert chg["mac"] == AP and "36" in chg["title"] and "40" in chg["title"]
    sec = next(x for x in r["items"] if x["type"] == "security")
    assert sec["mac"] == AP and sec["severity"] == "high"  # open network
    assert r["items"] == sorted(r["items"], key=lambda x: x["ts"], reverse=True)


def test_mynet_weak_ap_choice(env):
    ctx, c = env
    login(c)
    STRONG, WEAK = "24:a4:3c:00:00:01", "24:a4:3c:00:00:02"  # two of my APs, same SSID
    OTHER_SSID = "24:a4:3c:00:00:03"  # a single-AP SSID: no "choice" exists, never counts as weak
    CLIENT = "a4:83:e7:00:00:01"
    assert c.put("/api/settings/networks", json={"ssids": ["HomeNet", "Solo"], "trusted_bssids": []},
                headers=H).status_code == 200
    now = time.time()
    with ctx.wdb() as db:
        for mac, ssid in ((STRONG, "HomeNet"), (WEAK, "HomeNet"), (OTHER_SSID, "Solo")):
            db.execute("INSERT INTO devices(mac, kind, ssid, first_seen, last_seen) VALUES(?, 'ap', ?, ?, ?)",
                      (mac, ssid, now - 3600, now))
        db.execute("INSERT INTO devices(mac, kind, first_seen, last_seen) VALUES(?, 'wifi_client', ?, ?)",
                  (CLIENT, now - 3600, now))
        # A session on the weak sibling (avg rssi -85, well under STICKY_RSSI) ...
        db.execute("INSERT INTO sessions(mac, type, peer, start_ts, end_ts, open, rssi_sum, rssi_count) "
                  "VALUES(?, 'assoc', ?, ?, ?, 0, ?, ?)", (CLIENT, WEAK, now - 600, now - 500, -850, 10))
        # ... and one on the strong sibling (avg rssi -50): not a weak choice.
        db.execute("INSERT INTO sessions(mac, type, peer, start_ts, end_ts, open, rssi_sum, rssi_count) "
                  "VALUES(?, 'assoc', ?, ?, ?, 0, ?, ?)", (CLIENT, STRONG, now - 400, now - 300, -500, 10))
        # A weak session on the single-AP SSID: no sibling exists, so it's not a "choice" at all.
        db.execute("INSERT INTO sessions(mac, type, peer, start_ts, end_ts, open, rssi_sum, rssi_count) "
                  "VALUES(?, 'assoc', ?, ?, ?, 0, ?, ?)", (CLIENT, OTHER_SSID, now - 200, now - 100, -900, 10))

    r = c.get("/api/mynet?days=7").json()
    cl = next(x for x in r["clients"] if x["mac"] == CLIENT)
    assert cl["choice_sessions"] == 2 and cl["weak_choice_sessions"] == 1
    assert r["summary"]["weak_choice_sessions"] == 1


def test_passersby(env):
    ctx, c = env
    login(c)
    PASSER = "a4:83:e7:00:00:01"      # 2 short passes a day for 3 days, signal swings as it moves by
    STATIC = "a4:83:e7:00:00:02"      # 4 short passes on 4 days, but the signal never changes: something standing still
    FLICKER = "a4:83:e7:00:00:03"     # flickers in and out all day, 8 minutes apart: one long episode, not passes
    BUSY = "a4:83:e7:00:00:04"        # 12 short, well separated visits in one day: too frequent for passing by
    RESIDENT = "a4:83:e7:00:00:05"    # short passes, but heard for 15 minutes straight once: it's around
    ONCE = "a4:83:e7:00:00:06"        # only 2 passes
    AP = "0a:00:00:00:00:07"          # access point passing by
    day0 = int(time.time() // 86400) * 86400  # today 00:00 UTC; every visit below is on an earlier day, at a fixed hour

    def at(day, hour, minute=0):
        return day0 - day * 86400 + hour * 3600 + minute * 60

    def visit(mac, start, secs=20, swing=(-80, -50), readings=6):
        db.execute("INSERT INTO sessions(mac, type, start_ts, end_ts, rssi_min, rssi_max, rssi_count, open) VALUES(?, 'presence', ?, ?, ?, ?, ?, 0)",
                   (mac, start, start + secs, *swing, readings))

    with ctx.wdb() as db:
        for mac in (PASSER, STATIC, FLICKER, BUSY, RESIDENT, ONCE, AP):
            db.execute("INSERT INTO devices(mac, kind, first_seen, last_seen) VALUES(?, ?, ?, ?)",
                       (mac, "ap" if mac == AP else "wifi_client", day0 - 5 * 86400, day0))
        for d in (1, 2, 3):
            visit(PASSER, at(d, 9)); visit(PASSER, at(d, 17, 30))
        for d in (1, 2, 3, 4):
            visit(STATIC, at(d, 10), swing=(-71, -69))
        for i in range(40):
            visit(FLICKER, at(1, 8) + i * 480, secs=10)
        for i in range(12):
            visit(BUSY, at(1, 6) + i * 3600)
        for d in (1, 2, 3):
            visit(RESIDENT, at(d, 12))
        visit(RESIDENT, at(4, 12), secs=900)
        for d in (1, 2):
            visit(ONCE, at(d, 11))
        for d in (1, 2, 3, 4):
            visit(AP, at(d, 13))

    def listed(q=""):
        return {x["mac"]: x for x in c.get(f"/api/passersby?days=7&{q}").json()["items"]}

    got = listed()
    assert set(got) == {PASSER, STATIC}
    p = got[PASSER]
    assert (p["visits"], p["days_seen"], p["per_day"]) == (6, 3, 2.0) and 19 <= p["avg_secs"] <= 21 and p["swing_db"] == 30
    assert got[STATIC]["visits"] == 4 and got[STATIC]["swing_db"] == 2

    # Fewer passes needed: the device seen twice shows up. More passes needed: only the ones with that many.
    assert set(listed("min_passes=2")) == {PASSER, STATIC, ONCE}
    assert set(listed("min_passes=5")) == {PASSER}
    # A flickering device is rejected because its visits merge into one long episode. Only with merging switched
    # (almost) off, and any frequency allowed, do its 40 visits count as 40 separate passes in a day.
    assert FLICKER not in listed("max_per_day=1000")
    assert listed("gap=60&max_per_day=1000")[FLICKER]["per_day"] == 40 and FLICKER not in listed("gap=60")
    # Frequency: BUSY appears only once many passes a day are allowed.
    assert BUSY not in listed() and BUSY in listed("max_per_day=12")
    # Only moving devices: the signal has to rise and fall.
    assert set(listed("moving=1")) == {PASSER}
    # A device heard once per pass has no measurable swing, so "moving only" can't claim it moves (and shows no swing).
    with ctx.wdb() as db:
        db.execute("INSERT INTO devices(mac, kind, first_seen, last_seen) VALUES('a4:83:e7:00:00:09', 'wifi_client', ?, ?)", (day0, day0))
        for d in (1, 2, 3):
            visit("a4:83:e7:00:00:09", at(d, 14), secs=0, swing=(-60, -60), readings=1)
    one = listed()["a4:83:e7:00:00:09"]
    assert one["swing_db"] is None and "a4:83:e7:00:00:09" not in listed("moving=1")
    # Access points only when asked for.
    assert AP not in listed("min_passes=3") and AP in listed("min_passes=3&aps=1")
    # A long stay rules the device out entirely.
    assert RESIDENT not in listed("max_per_day=1000&min_passes=2")
    # The pass length limit: a 90 s pass is too long for a 60 s limit.
    with ctx.wdb() as db:
        for d in (1, 2, 3):
            visit("a4:83:e7:00:00:08", at(d, 15), secs=90)
        db.execute("INSERT INTO devices(mac, kind, first_seen, last_seen) VALUES('a4:83:e7:00:00:08', 'wifi_client', ?, ?)", (day0, day0))
    assert "a4:83:e7:00:00:08" in listed("max_secs=120") and "a4:83:e7:00:00:08" not in listed("max_secs=60")

    # hide_known drops it once it's marked known.
    assert c.put(f"/api/devices/{PASSER}/meta", json={"known": True}, headers=H).status_code == 200
    assert PASSER not in listed("hide_known=1") and PASSER in listed()


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


def test_stats_weekly_heat_and_new_vendors(env):
    ctx, c = env
    now = time.time()
    old_vendor_mac = "24:a4:3c:00:00:01"
    ctx.store.process({"t": "wifi_ap", "ts": now - 30 * 86400, "mac": old_vendor_mac, "ssid": "Old", "vendor": "OldCo"})
    ctx.store.flush()
    new_vendor_mac = "a4:83:e7:00:00:02"
    ctx.store.process({"t": "wifi_client", "ts": now, "mac": new_vendor_mac, "vendor": "NewCo", "rssi": -50})
    ctx.store.flush()
    login(c)
    s = c.get("/api/stats?days=7").json()

    heat = {(r["wd"], r["h"]): r["n"] for r in s["weekly_heat"]}
    now_lt = now  # samples are keyed on the raw (unoffset) epoch minute at tz=0
    wd = int((now_lt // 86400 + 3) % 7)
    h = int((now_lt % 86400) // 3600)
    assert heat.get((wd, h), 0) >= 1

    vendors = {v["vendor"]: v for v in s["new_vendors"]}
    assert "NewCo" in vendors and "OldCo" not in vendors  # OldCo's only device is 30 days old
    assert vendors["NewCo"]["devices"] == 1


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
        "ssid": "HomeNet", "enabled": True, "known_bssids": [], "eapol_bssids": [], "pairs": 0, "usable_pairs": 0,
        "frames": 0, "bytes": 0, "started": None, "updated": None, "downloadable": False}
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


def test_compression_and_caching(env):
    ctx, c = env
    now = time.time()
    for i in range(40):
        ctx.store.process({"t": "wifi_client", "ts": now, "mac": f"a4:83:e7:00:00:{i:02x}", "rssi": -50, "frame": "data"})
    ctx.store.flush()
    login(c)
    # TestClient decompresses transparently, so look at the raw headers it saw.
    r = c.get("/api/devices?limit=100", headers={"Accept-Encoding": "gzip"})
    assert r.headers["content-encoding"] == "gzip" and r.headers["vary"] == "Accept-Encoding"
    assert len(r.json()["items"]) == 40
    assert "content-encoding" not in c.get("/api/devices?limit=100", headers={"Accept-Encoding": "identity"}).headers
    # Range requests are never compressed (the byte range would no longer match the body).
    r = c.get("/static/app.js", headers={"Accept-Encoding": "gzip", "Range": "bytes=0-99"})
    assert r.status_code == 206 and "content-encoding" not in r.headers and len(r.content) == 100
    # Only POST-free reads compress (a created API token must never sit in a compressed body).
    r = c.post("/api/tokens", json={"name": "t", "scope": "metrics"}, headers={**H, "Accept-Encoding": "gzip"})
    assert "content-encoding" not in r.headers
    # Versioned static files are kept forever; unversioned ones are still revalidated.
    r = c.get("/static/app.js?v=abc123", headers={"Accept-Encoding": "gzip"})
    assert r.headers["cache-control"] == "public, max-age=31536000, immutable" and r.headers["content-encoding"] == "gzip"
    assert "immutable" not in c.get("/static/app.js").headers.get("cache-control", "")
    assert c.get("/").headers["cache-control"] == "no-store"


def test_devices_slim(env):
    ctx, c = env
    ctx.store.process({"t": "bt", "ts": time.time(), "mac": "a4:83:e7:00:00:01", "kind": "ble", "name": "Pods",
                       "vendor": "Apple", "rssi": -50, "extra": {"company": "Apple"}})
    ctx.store.flush()
    login(c)
    full = c.get("/api/devices").json()["items"][0]
    slim = c.get("/api/devices?slim=1").json()["items"][0]
    assert "evidence" in full["ident"] and "extra" in full
    assert set(slim["ident"]) == {"label"} and slim["ident"]["label"] == full["ident"]["label"] and "extra" not in slim
    assert slim["mac"] == full["mac"] and slim["last_rssi"] == full["last_rssi"]


def _hourly_data(ctx, now):
    """Three devices heard on and off across ~3.5 days, including inside the partial hour at the start of the window."""
    s = ctx.store
    for n, mac in enumerate(("a4:83:e7:00:00:01", "a4:83:e7:00:00:02", "a4:83:e7:00:00:03")):
        kind = "wifi_ap" if n == 0 else "wifi_client"
        t = now - 3.5 * 86400 + n * 97
        while t < now - 60:
            s.process({"t": kind, "ts": t, "mac": mac, "rssi": -50, "frame": "data"} if kind == "wifi_client"
                      else {"t": kind, "ts": t, "mac": mac, "ssid": "Net", "rssi": -50})
            t += 413 + n * 777  # irregular gaps, so some hours are skipped by some devices
    s.flush()


def test_presence_rollup_matches_samples(env, monkeypatch):
    ctx, c = env
    now = 1_760_000_000 + 1234  # fixed, so the endpoint's "since" is known exactly
    _hourly_data(ctx, now)
    assert ctx.one("SELECT COUNT(*) n FROM presence_hours")["n"] < ctx.one("SELECT COUNT(*) n FROM samples")["n"] / 4
    # Every (hour, device) the roll-up holds is in `samples` and the other way round.
    assert (ctx.rows("SELECT DISTINCT minute / 3600 * 3600 hour, mac FROM samples ORDER BY hour, mac")
            == ctx.rows("SELECT hour, mac FROM presence_hours ORDER BY hour, mac"))
    login(c)
    monkeypatch.setattr(time, "time", lambda: now)
    for tz in (-120, 0, 300, -330):  # whole-hour offsets use the roll-up, +5:30 falls back to `samples`
        off, days = tz * 60, 3
        since = now - days * 86400
        got = c.get(f"/api/stats?days={days}&tz={tz}").json()
        raw_hourly = ctx.rows("SELECT h, kind, COUNT(*) n FROM (SELECT DISTINCT s.mac, d.kind, ((s.minute - ?) % 86400) / 3600 h, "
                              "(s.minute - ?) / 86400 day FROM samples s JOIN devices d ON d.mac=s.mac WHERE s.minute>=?) "
                              "GROUP BY h, kind", (off, off, since))
        key = lambda r: tuple(sorted(r.items()))
        assert sorted(got["hourly"]["rows"], key=key) == sorted(raw_hourly, key=key), tz
        assert got["hourly"]["days"] == ctx.one("SELECT COUNT(DISTINCT (minute - ?) / 86400) n FROM samples WHERE minute>=?",
                                                (off, since))["n"]
        raw_heat = ctx.rows("SELECT wd, h, COUNT(*) n FROM (SELECT DISTINCT s.mac, ((s.minute - ?) % 86400) / 3600 h, "
                            "((s.minute - ?) / 86400 + 3) % 7 wd, (s.minute - ?) / 86400 day FROM samples s WHERE s.minute >= ?) "
                            "GROUP BY wd, h", (off, off, off, since))
        assert sorted(got["weekly_heat"], key=key) == sorted(raw_heat, key=key), tz


def test_timeline_long_ranges_use_whole_hours(env, monkeypatch):
    ctx, c = env
    now = 1_760_000_000 + 1234
    _hourly_data(ctx, now)
    login(c)
    monkeypatch.setattr(time, "time", lambda: now)
    t = c.get("/api/timeline?hours=168").json()
    assert t["bucket"] == 3600 and c.get("/api/timeline?hours=720").json()["bucket"] % 3600 == 0
    assert c.get("/api/timeline?hours=24").json()["bucket"] == 300  # short ranges still read the per-minute samples
    since = t["t"][0]
    raw = ctx.rows("SELECT (minute / 3600) * 3600 t, d.kind, COUNT(DISTINCT s.mac) n FROM samples s JOIN devices d ON d.mac=s.mac "
                   "WHERE s.minute >= ? GROUP BY t, d.kind", (since,))
    for kind, series in t["series"].items():
        want = {r["t"]: r["n"] for r in raw if r["kind"] == kind}
        assert series == [want.get(x, 0) for x in t["t"]], kind


def test_presence_rollup_backfill_and_prune(tmp_path):
    cfg = Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path), retention_days=1)
    ctx = build(cfg)
    now = time.time()
    for h in (30, 3):  # one device-hour older than the retention, one recent
        ctx.store.process({"t": "wifi_client", "ts": now - h * 3600, "mac": "a4:83:e7:00:00:09", "frame": "data"})
    ctx.store.flush()
    assert ctx.one("SELECT COUNT(*) n FROM presence_hours")["n"] == 2
    ctx.store.prune(now)
    assert ctx.one("SELECT COUNT(*) n FROM presence_hours")["n"] == 1
    # A database from before the roll-up existed: it's rebuilt from `samples` on the next start.
    with ctx.wdb() as w:
        w.execute("DELETE FROM presence_hours")
        w.execute("DELETE FROM meta WHERE key='presence_hours'")
    assert build(cfg).store.conn.execute("SELECT COUNT(*) FROM presence_hours").fetchone()[0] == 1


def test_performance_switch(env):
    ctx, c = env
    from sniffowireless import store as store_mod
    pragma = lambda conn, p: conn.execute(f"PRAGMA {p}").fetchone()[0]
    drain = lambda: [ctx.store.process(ctx.store.q.get_nowait()) for _ in range(ctx.store.q.qsize())]
    try:
        drain()  # the startup retune
        assert pragma(ctx.db(), "cache_size") == -store_mod.CACHE_KB and pragma(ctx.db(), "mmap_size") == store_mod.MMAP_BYTES
        assert c.put("/api/settings/performance", json={"db_cache": False}, headers=H).status_code == 401  # needs a login
        c.post("/api/auth/login", json={"username": "viewer", "password": PW}, headers=H)
        assert c.put("/api/settings/performance", json={"db_cache": False}, headers=H).status_code == 403
        c.post("/api/auth/login", json={"username": "admin", "password": PW}, headers=H)
        assert c.get("/api/settings/performance").json() == {"db_cache": True}
        assert c.put("/api/settings/performance", json={"db_cache": "no"}, headers=H).status_code == 400
        assert c.put("/api/settings/performance", json={"db_cache": False}, headers=H).json() == {"db_cache": False}
        drain()
        for conn in (ctx.db(), ctx.store.conn):  # new connections and the writer's own
            assert pragma(conn, "cache_size") == -store_mod.SQLITE_DEFAULT_CACHE_KB and pragma(conn, "mmap_size") == 0
        assert c.put("/api/settings/performance", json={"db_cache": True}, headers=H).status_code == 200
        drain()
        assert pragma(ctx.db(), "cache_size") == -store_mod.CACHE_KB and pragma(ctx.store.conn, "mmap_size") == store_mod.MMAP_BYTES
    finally:
        store_mod.set_db_cache(True)


def test_ignore_networks_quick_endpoint(env):
    ctx, c = env
    t = time.time()
    ctx.store.process({"t": "wifi_ap", "ts": t, "mac": "0a:00:00:00:00:01", "ssid": "Neighbour", "enc": "OPN"})
    ctx.store.process({"t": "wifi_ap", "ts": t, "mac": "0a:00:00:00:00:02", "ssid": "HomeNet", "enc": "WPA2/PSK"})
    ctx.store.process({"t": "wifi_client", "ts": t, "mac": "a4:83:e7:00:00:01", "bssid": "0a:00:00:00:00:01", "frame": "assoc"})
    ctx.store.flush()
    ctx.settings.set("networks", {"ssids": ["HomeNet"], "trusted_bssids": []})
    url = "/api/settings/ignore/networks"
    assert c.post(url, json={"ssids": ["Neighbour"]}, headers=H).status_code == 401
    c.post("/api/auth/login", json={"username": "viewer", "password": PW}, headers=H)
    assert c.post(url, json={"ssids": ["Neighbour"]}, headers=H).status_code == 403
    c.post("/api/auth/login", json={"username": "admin", "password": PW}, headers=H)
    assert c.post(url, json={"ssids": []}, headers=H).status_code == 422
    assert c.post(url, json={"ssids": ["x" * 100]}, headers=H).status_code == 422

    # Ignoring: the network joins the list (with its clients by default), but one of my own networks is refused.
    r = c.post(url, json={"ssids": ["Neighbour", "HomeNet", "Neighbour"]}, headers=H).json()
    assert r["changed"] == ["Neighbour"] and r["skipped"] == ["HomeNet"] and r["purged"] == 0
    assert c.get("/api/settings/ignore").json()["ssids"] == [{"ssid": "Neighbour", "clients": True}]
    # It takes effect at once: nothing more is stored for it, nor for its clients.
    ctx.store.process({"t": "wifi_ap", "ts": t + 1, "mac": "0a:00:00:00:00:03", "ssid": "Neighbour"})
    ctx.store.process({"t": "wifi_client", "ts": t + 1, "mac": "a4:83:e7:00:00:02", "bssid": "0a:00:00:00:00:03", "frame": "data"})
    ctx.store.process({"t": "wifi_ap", "ts": t + 1, "mac": "0a:00:00:00:00:04", "ssid": "Other"})
    ctx.store.flush()
    stored = {r["mac"] for r in ctx.rows("SELECT mac FROM devices")}
    assert "0a:00:00:00:00:03" not in stored and "a4:83:e7:00:00:02" not in stored and "0a:00:00:00:00:04" in stored
    # The lists that offer the button know which networks are ignored / mine.
    ssids = {x["ssid"]: x for x in c.get("/api/stats?days=1").json()["ssids"]}
    assert ssids["Neighbour"]["ignored"] and not ssids["Neighbour"]["mine"] and ssids["HomeNet"]["mine"]
    assert c.get("/api/investigations/Neighbour").json()["ignored"] is True
    assert c.get("/api/investigations/Other").json()["ignored"] is False

    # Stop ignoring, then ignore again and delete what was stored (the AP and the client that had connected to it).
    assert c.post(url, json={"ssids": ["Neighbour"], "remove": True}, headers=H).json()["changed"] == ["Neighbour"]
    assert c.get("/api/settings/ignore").json()["ssids"] == []
    r = c.post(url, json={"ssids": ["Neighbour"], "clients": False, "purge": True}, headers=H).json()
    assert r["purged"] == 1 and c.get("/api/settings/ignore").json()["ssids"][0]["clients"] is False
    r = c.post(url, json={"ssids": ["Neighbour"], "clients": True, "purge": True}, headers=H).json()
    assert r["purged"] >= 1  # the client was found through its session with the AP
    # The list has a limit, and the rest of the ignore list is left alone.
    c.put("/api/settings/ignore", json={"macs": ["aa:bb:cc:dd:ee:ff"], "ssids": [{"ssid": "Neighbour"}]}, headers=H)
    c.post(url, json={"ssids": ["Another"]}, headers=H)
    ig = c.get("/api/settings/ignore").json()
    assert ig["macs"] == ["aa:bb:cc:dd:ee:ff"] and {e["ssid"] for e in ig["ssids"]} == {"Neighbour", "Another"}
    many = [f"net-{i}" for i in range(500)]
    assert c.post(url, json={"ssids": many}, headers=H).status_code == 400


def test_restore_chooser_api(env, tmp_path, monkeypatch):
    import os as _os
    from sniffowireless import backup as backup_mod
    ctx, c = env
    monkeypatch.setattr(backup_mod, "RESTART_DELAY", 0)
    kills = []
    monkeypatch.setattr(_os, "kill", lambda pid, sig: kills.append(sig))
    ctx.store.process({"t": "wifi_client", "ts": time.time(), "mac": "a4:83:e7:00:00:01", "frame": "data"})
    ctx.store.flush()
    with ctx.wdb() as w:
        w.execute("INSERT INTO groups(name, kind) VALUES('Sam', 'person')")
    ctx.settings.set("networks", {"ssids": ["HomeNet"], "trusted_bssids": []})
    name = _os.path.basename(backup_mod.create_full_backup(ctx))
    data = open(_os.path.join(ctx.cfg.data_dir, "backups", name), "rb").read()
    staged = _os.path.join(ctx.cfg.data_dir, "restore-pending.tar.gz")
    sidecar = _os.path.join(ctx.cfg.data_dir, "restore-pending.json")
    upload = _os.path.join(ctx.cfg.data_dir, "restore-upload.tar.gz")
    pick = "/api/backup/restore-selected"

    # Admin only.
    for method, url, kw in (("get", f"/api/backup/files/{name}/sections", {}), ("post", "/api/backup/inspect", {"content": data}),
                            ("post", pick, {"json": {"source": name, "sections": ["groups"]}}),
                            ("post", "/api/backup/config/inspect", {"content": b"{}"})):
        assert getattr(c, method)(url, headers=H, **kw).status_code == 401
    c.post("/api/auth/login", json={"username": "viewer", "password": PW}, headers=H)
    assert c.get(f"/api/backup/files/{name}/sections").status_code == 403
    assert c.post(pick, json={"source": name, "sections": ["groups"]}, headers=H).status_code == 403
    c.post("/api/auth/login", json={"username": "admin", "password": PW}, headers=H)

    # What a stored backup, and an uploaded one, holds.
    info = c.get(f"/api/backup/files/{name}/sections").json()
    assert {s["id"]: s["count"] for s in info["sections"]}["groups"] == 1
    assert c.get("/api/backup/files/nope.tar.gz/sections").status_code == 400
    assert c.post("/api/backup/inspect", content=b"not a backup", headers=H).status_code == 400 and not _os.path.exists(upload)
    up = c.post("/api/backup/inspect", content=data, headers=H).json()
    assert up["sections"] == info["sections"] and _os.path.exists(upload)

    # Choosing: nothing / unknown / missing source are refused; a real choice is staged with its sidecar.
    assert c.post(pick, json={"source": name, "sections": []}, headers=H).status_code == 400
    assert c.post(pick, json={"source": name, "sections": ["bogus"]}, headers=H).status_code == 400
    assert c.post(pick, json={"source": name, "sections": "everything"}, headers=H).status_code == 422
    assert c.post(pick, json={"source": "missing.tar.gz", "sections": ["groups"]}, headers=H).status_code == 400  # not a backup name
    assert c.post(pick, json={"source": "sniffowireless-20200101-000000.tar.gz", "sections": ["groups"]}, headers=H).status_code == 404
    assert not _os.path.exists(staged)
    r = c.post(pick, json={"source": name, "sections": ["groups", "labels", "groups"]}, headers=H)
    assert r.status_code == 200 and r.json()["restarting"]
    backup_mod._restart_thread.join()
    assert kills and json.load(open(sidecar))["sections"] == ["groups", "labels"] and _os.path.exists(staged)
    assert _os.path.exists(_os.path.join(ctx.cfg.data_dir, "backups", name))  # a stored backup is copied, not used up

    # An uploaded backup is moved into place; "all" is a whole-database restore, so it leaves no sidecar.
    assert c.post(pick, json={"source": "upload", "sections": "all"}, headers=H).status_code == 200
    backup_mod._restart_thread.join()
    assert _os.path.exists(staged) and not _os.path.exists(sidecar) and not _os.path.exists(upload)
    assert c.post(pick, json={"source": "upload", "sections": ["groups"]}, headers=H).status_code == 404

    # The configuration backup has the same chooser, applied at once.
    cfg = c.get("/api/backup/config").content
    secs = {s["id"]: s["count"] for s in c.post("/api/backup/config/inspect", content=cfg, headers=H).json()["sections"]}
    assert secs["groups"] == 1 and secs["settings"] >= 1 and "history" not in secs
    ctx.settings.set("networks", {"ssids": ["Changed"], "trusted_bssids": []})
    assert c.post("/api/backup/config?sections=bogus", content=cfg, headers=H).status_code == 400
    r = c.post("/api/backup/config?sections=groups", content=cfg, headers=H).json()
    assert r["restored"] == {"groups": 1} and ctx.settings.get("networks")["ssids"] == ["Changed"]
    assert c.post("/api/backup/config?sections=settings", content=cfg, headers=H).json()["restored"] == {}
    assert ctx.settings.get("networks")["ssids"] == ["HomeNet"]
