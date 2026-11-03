"""Security tests: auth, CSRF/origin, headers/CSP, input validation, ingest sanitising, uploads, limits."""
import gzip
import json
import time

import pytest

pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from yolo.auth import hash_password  # noqa: E402
from yolo.config import Config  # noqa: E402
from yolo.main import build  # noqa: E402
from yolo.sanitize import clean_str, remote_observation  # noqa: E402
from yolo.web import create_app  # noqa: E402

PW = "correct-horse-battery"
H = {"X-Yolo": "1"}


@pytest.fixture
def env(tmp_path):
    ctx = build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))
    with ctx.wdb() as c:
        c.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('admin', ?, 'admin', 0)",
                  (hash_password(PW, iterations=1000),))
        c.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('viewer', ?, 'viewer', 0)",
                  (hash_password(PW, iterations=1000),))
    client = TestClient(create_app(ctx), base_url="http://yolo.test")
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
    assert c.put("/api/settings/networks", json={"ssids": ["X"]}).status_code == 403  # no X-Yolo header
    r = c.put("/api/settings/networks", json={"ssids": ["X"]}, headers={**H, "Origin": "https://evil.example"})
    assert r.status_code == 403
    assert c.put("/api/settings/networks", json={"ssids": ["X"]}, headers={**H, "Origin": "http://yolo.test"}).status_code == 200
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
    plain = TestClient(c.app, base_url="http://yolo.test")
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
    from yolo import status
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


def test_allowed_hosts(tmp_path):
    ctx = build(Config(db_path=str(tmp_path / "h.db"), data_dir=str(tmp_path), allowed_hosts=["yolo.lan"]))
    assert TestClient(create_app(ctx), base_url="http://evil.example").get("/api/health").status_code == 421
    assert TestClient(create_app(ctx), base_url="http://yolo.lan").get("/api/health").status_code == 200


def test_clean_str():
    assert clean_str("a\x00b‮c\r\nd") == "abcd"
    assert clean_str("x" * 500, 10) == "x" * 10
    assert clean_str(None) is None and clean_str("\x01") is None


def test_logs_admin_only_and_redacted(env):
    import logging

    from yolo.logs import HANDLER, install
    install("INFO")
    _, c = env
    logging.getLogger("yolo.auth").warning("No accounts exist yet ... setup code: ABCD-1234-EF56")
    logging.getLogger("yolo.test").info("token yolo_%s used", "x" * 30)
    logging.getLogger("yolo.test").info("ssid <script>alert(1)</script>")
    assert c.get("/api/logs").status_code == 401
    login(c, "viewer")
    assert c.get("/api/logs").status_code == 403 and c.get("/api/logs/stream").status_code == 403
    c.post("/api/auth/logout", headers=H)
    login(c)
    items = c.get("/api/logs?limit=50").json()["items"]
    text = "\n".join(i["msg"] for i in items)
    assert "ABCD-1234-EF56" not in text and "setup code: ••••" in text and "yolo_xxx" not in text
    assert "<script>alert(1)</script>" in text  # raw in JSON; the page renders it as text, never HTML
    after = items[-1]["id"]
    logging.getLogger("yolo.test").error("fresh line")
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
    from yolo.sanitize import remote_observation
    base = {"t": "wifi_ap", "ts": time.time(), "mac": "0a:00:00:00:00:01", "channel": 100}
    ok = remote_observation({**base, "csa": {"mode": 1, "new_channel": 36, "count": 5, "x": "<script>"}}, time.time())
    assert ok["csa"] == {"mode": 1, "new_channel": 36, "count": 5}
    assert remote_observation({**base, "csa": {"new_channel": 999}}, time.time()).get("csa") is None
    assert remote_observation({**base, "csa": "36"}, time.time()).get("csa") is None
