"""Web interface hardening (release 31): every write needs an admin, stored file names are never trusted as paths,
sessions end, password checks can't be used to exhaust the CPU, and the security headers are sent."""
import json
import os
import re
import threading
import time

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from sniffowireless import auth, status
from sniffowireless.auth import hash_password
from sniffowireless.config import Config
from sniffowireless.main import build
from sniffowireless.web import create_app

PW = "correct-horse-battery"
# Writes a viewer (or someone not signed in) may make: their own account, and sign in / out.
OWN = ("/api/me/", "/api/auth/")


@pytest.fixture
def ctx(tmp_path):
    status.SENSORS.clear()
    c = build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))
    with c.wdb() as w:
        for name, role in (("admin", "admin"), ("view", "viewer")):
            w.execute("INSERT INTO users(username, pw_hash, role, created) VALUES(?, ?, ?, 0)", (name, hash_password(PW, iterations=1000), role))
    return c


def api_routes(app):
    """Every APIRoute, also those of included routers (newer FastAPI keeps those in a wrapper of their own)."""
    out, todo = [], list(app.routes)
    while todo:
        r = todo.pop(0)
        if isinstance(r, APIRoute):
            out.append(r)
        elif hasattr(r, "original_router"):
            todo.extend(r.original_router.routes)
        elif hasattr(r, "routes") and not hasattr(r, "app"):
            todo.extend(r.routes)
    return out


def client(app, user=None):
    c = TestClient(app, base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    if user:
        assert c.post("/api/auth/login", json={"username": user, "password": PW}).status_code == 200
    return c


def test_no_write_endpoint_accepts_a_viewer_or_anonymous_caller(ctx):
    """Walks every route of the app, so a new endpoint that forgets require_admin fails here."""
    app = create_app(ctx)
    viewer, anon = client(app, "view"), client(app)
    checked, leaks = 0, []
    for r in api_routes(app):
        if r.path.startswith(OWN):
            continue
        for m in sorted(r.methods - {"GET", "HEAD"}):
            path = re.sub(r"\{[^}]+\}", "1", r.path)
            for who, c in (("viewer", viewer), ("anonymous", anon)):
                code = c.request(m, path, json={}).status_code
                if code not in (401, 403):
                    leaks.append(f"{m} {r.path} as {who}: {code}")
            checked += 1
    assert checked > 50
    assert not leaks, "\n".join(leaks)


def test_reads_need_a_sign_in(ctx):
    app = create_app(ctx)
    anon = client(app)
    public = ("/api/health", "/api/appearance", "/api/auth/")
    for r in api_routes(app):
        if "GET" in r.methods and r.path.startswith("/api/") and not r.path.startswith(public):
            code = anon.get(re.sub(r"\{[^}]+\}", "1", r.path)).status_code
            assert code in (401, 403), f"GET {r.path}: {code}"


def test_floorplan_path_from_a_restored_backup_is_not_served_or_deleted(ctx, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("not for you")
    app = create_app(ctx)
    admin, viewer = client(app, "admin"), client(app, "view")
    for evil in (str(secret), "../secret.txt", "floorplan.png/../../secret.txt", "secret.txt"):
        ctx.settings.set("floorplan", {"image": evil, "width": 10, "height": 10})
        assert viewer.get("/api/floorplan/image").status_code == 404
        assert admin.delete("/api/floorplan").status_code == 200
        assert secret.exists()
    # the same through a configuration backup
    cfg = {"format": "sniffowireless-config", "version": 1, "settings": {"floorplan": {"image": str(secret)}}, "tables": {}}
    assert admin.post("/api/backup/config", content=json.dumps(cfg), headers={"content-type": "application/json"}).status_code == 200
    assert ctx.settings.get("floorplan")["image"] == str(secret)  # stored as given, but never used as a path
    assert viewer.get("/api/floorplan/image").status_code == 404
    admin.delete("/api/floorplan")
    assert secret.exists()


def test_a_real_floorplan_still_works(ctx, tmp_path):
    app = create_app(ctx)
    admin = client(app, "admin")
    png = b"\x89PNG\r\n\x1a\n" + b"\0" * 64
    assert admin.post("/api/floorplan?width=10&height=10", content=png, headers={"content-type": "image/png"}).status_code == 200
    assert admin.get("/api/floorplan/image").content == png
    assert admin.delete("/api/floorplan").status_code == 200
    assert not os.path.exists(tmp_path / "floorplan.png")


def test_session_ends_after_the_hard_limit_however_often_it_is_used(ctx):
    app = create_app(ctx)
    c = client(app, "view")
    assert c.get("/api/me/2fa").status_code == 200
    with ctx.wdb() as w:  # signed in 91 days ago and used every day since: still expires
        w.execute("UPDATE auth_sessions SET created=?, expires=?", (time.time() - 91 * 86400, time.time() + 13 * 86400))
    assert c.get("/api/me/2fa").status_code == 401
    with ctx.wdb() as w:
        assert w.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0] == 0


def test_sliding_expiry_never_passes_the_hard_limit(ctx):
    app = create_app(ctx)
    c = client(app, "view")
    created = time.time() - 85 * 86400
    with ctx.wdb() as w:
        w.execute("UPDATE auth_sessions SET created=?, expires=?", (created, time.time() + 3600))
    assert c.get("/api/me/2fa").status_code == 200
    with ctx.wdb() as w:
        expires = w.execute("SELECT expires FROM auth_sessions").fetchone()[0]
    assert expires <= created + auth.SESSION_MAX_DAYS * 86400 + 1


def test_password_checks_at_once_are_capped(ctx, monkeypatch):
    monkeypatch.setattr(auth, "HASH_WAIT", 0.05)
    app = create_app(ctx)
    c = client(app)
    a = ctx.auth
    taken = [a.hashing.acquire() for _ in range(auth.HASH_SLOTS)]
    try:
        r = c.post("/api/auth/login", json={"username": "view", "password": PW})
        assert r.status_code == 429
    finally:
        for _ in taken:
            a.hashing.release()
    assert c.post("/api/auth/login", json={"username": "view", "password": PW}).status_code == 200


def test_parallel_sign_ins_all_finish(ctx):
    app = create_app(ctx)
    codes = []

    def go():
        codes.append(client(app).post("/api/auth/login", json={"username": "view", "password": PW}).status_code)
    ts = [threading.Thread(target=go) for _ in range(auth.HASH_SLOTS * 2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert codes and all(x == 200 for x in codes)


def test_security_headers(ctx):
    app = create_app(ctx)
    r = client(app).get("/login")
    for h in ("content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy",
              "cross-origin-opener-policy", "cross-origin-resource-policy", "permissions-policy", "x-permitted-cross-domain-policies"):
        assert h in r.headers, h
    csp = r.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp and "object-src 'none'" in csp and "unsafe-eval" not in csp
    assert "'unsafe-inline'" not in csp.split("script-src", 1)[1].split(";")[0]


def test_cross_site_writes_are_refused(ctx):
    app = create_app(ctx)
    c = client(app, "admin")
    # no CSRF header
    bare = TestClient(app, base_url="http://sniffowireless.test", cookies=c.cookies)
    assert bare.post("/api/tokens", json={"name": "x", "scope": "read"}).status_code == 403
    # a foreign Origin, also on sign-in
    evil = {"origin": "https://evil.example"}
    assert c.post("/api/tokens", json={"name": "x", "scope": "read"}, headers=evil).status_code == 403
    assert client(app).post("/api/auth/login", json={"username": "admin", "password": PW}, headers=evil).status_code == 403


def test_play_sound_is_admin_only(ctx):
    app = create_app(ctx)
    assert client(app, "view").post("/api/devices/aa:bb:cc:dd:ee:01/sound").status_code == 403
    assert client(app, "admin").post("/api/devices/aa:bb:cc:dd:ee:01/sound").status_code == 404


def test_config_backup_without_secrets_leaves_out_setting_secrets_and_restore_keeps_them(ctx):
    app = create_app(ctx)
    admin = client(app, "admin")
    mqtt = {"enabled": False, "host": "h", "port": 1883, "username": "u", "password": "SECRETMQTT", "tls": False, "topic_prefix": "p", "qos": 0, "retain": True}
    assert admin.put("/api/settings/mqtt", json=mqtt).status_code == 200
    priv = ctx.settings.get("privacy")
    ctx.settings.set("privacy", {**priv, "secret": "SECRETKEY"})
    plain = admin.get("/api/backup/config?secrets=0").text
    assert "SECRETMQTT" not in plain and "SECRETKEY" not in plain
    full = admin.get("/api/backup/config?secrets=1").text
    assert "SECRETMQTT" in full and "SECRETKEY" in full
    # restoring the backup without secrets keeps this server's password and key
    assert admin.post("/api/backup/config", content=plain, headers={"content-type": "application/json"}).status_code == 200
    assert ctx.settings.get("mqtt")["password"] == "SECRETMQTT"
    assert ctx.settings.get("privacy")["secret"] == "SECRETKEY"
