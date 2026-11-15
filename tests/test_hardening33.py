"""Hardening from the security check before release 33: a restored backup only puts back files the app writes itself, and is not
unpacked when the disk can't hold it; restoring a configuration keeps two-factor login; X-Forwarded-Host/-Proto count only from
TRUSTED_PROXIES; ALLOWED_HOSTS understands IPv6 literals; the API docs page has its own CSP; deeply nested sensor JSON is a 400."""
import os
import sqlite3
import tarfile
from collections import namedtuple

from fastapi.testclient import TestClient
from test_hardening import PW, client, ctx  # noqa: F401  (ctx is a fixture)

from sniffowireless import backup, httpsec
from sniffowireless.config import Config
from sniffowireless.httpsec import DOCS_CSP, behind_proxies, host_name
from sniffowireless.web import SWAGGER_JS, create_app


def _crafted(ctx, tmp_path):
    """A real full backup plus what an attacker would add: a database and a stray file under files/, a script under handshakes/."""
    path = backup.create_full_backup(ctx, str(tmp_path))
    evil = tmp_path / "evil.db"
    e = sqlite3.connect(evil)
    e.execute("CREATE TABLE users(username)")
    e.execute("INSERT INTO users VALUES('attacker')")
    e.commit()
    e.close()
    plan = tmp_path / "plan.png"
    plan.write_bytes(b"\x89PNG\r\n\x1a\nplan")
    out = tmp_path / "crafted.tar.gz"
    with tarfile.open(path) as src, tarfile.open(out, "w:gz") as dst:
        for m in src.getmembers():
            dst.addfile(m, src.extractfile(m))
        dst.add(evil, arcname="files/sniffowireless.db")
        dst.add(evil, arcname="files/notes.txt")
        dst.add(plan, arcname="files/floorplan.png")
        dst.add(evil, arcname="handshakes/run.sh")
    return str(out)


def _closed_copy(ctx, tmp_path):
    """A copy of the database with nothing holding it open, as at startup when a staged restore is applied."""
    d = tmp_path / "start"
    d.mkdir()
    cfg = Config(db_path=str(d / "sniffowireless.db"), data_dir=str(d))
    a, b = sqlite3.connect(ctx.cfg.db_path), sqlite3.connect(cfg.db_path)
    a.backup(b)
    a.close()
    b.close()
    return cfg


def test_restoring_only_files_cannot_replace_the_database(ctx, tmp_path):
    archive = _crafted(ctx, tmp_path)
    backup.validate_full_backup(archive)
    cfg = _closed_copy(ctx, tmp_path)
    backup.restore_sections(cfg, archive, ["files", "handshakes"])
    names = [r[0] for r in sqlite3.connect(cfg.db_path).execute("SELECT username FROM users")]
    assert "attacker" not in names and "admin" in names
    left = sorted(f for f in os.listdir(cfg.data_dir) if not f.endswith(("-wal", "-shm")))
    assert left == ["backups", "floorplan.png", "handshakes", "sniffowireless.db"]
    assert os.listdir(os.path.join(cfg.data_dir, "handshakes")) == []


def test_a_full_restore_puts_back_only_known_files(ctx, tmp_path):
    archive = _crafted(ctx, tmp_path)
    cfg = _closed_copy(ctx, tmp_path)
    os.replace(archive, os.path.join(cfg.data_dir, backup.STAGED))
    assert backup.apply_staged_restore(cfg)
    names = [r[0] for r in sqlite3.connect(cfg.db_path).execute("SELECT username FROM users")]
    assert "attacker" not in names and "admin" in names
    assert "notes.txt" not in os.listdir(cfg.data_dir) and "floorplan.png" in os.listdir(cfg.data_dir)


def test_a_backup_larger_than_the_free_space_is_refused(ctx, tmp_path, monkeypatch):
    path = backup.create_full_backup(ctx, str(tmp_path))
    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(backup.shutil, "disk_usage", lambda p: usage(10 ** 12, 10 ** 12, 1024))
    try:
        backup.validate_full_backup(path)
    except ValueError as e:
        assert "free space" in str(e)
    else:
        raise AssertionError("accepted a backup that does not fit")


def _two_factor(ctx, secret="JBSWY3DPEHPK3PXP"):
    with ctx.wdb() as w:
        w.execute("UPDATE users SET totp_secret=?, totp_last=7, recovery='[\"h\"]' WHERE username='admin'", (secret,))


def _totp(ctx):
    return ctx.one("SELECT totp_secret, totp_last, recovery FROM users WHERE username='admin'")


def test_config_restore_without_secrets_keeps_two_factor_login(ctx):
    _two_factor(ctx)
    data = backup.export_config(ctx, include_secrets=False)
    assert all("totp_secret" not in u for u in data["tables"]["users"])
    backup.import_config(ctx, data)
    assert _totp(ctx) == {"totp_secret": "JBSWY3DPEHPK3PXP", "totp_last": 7, "recovery": '["h"]'}


def test_config_backup_with_secrets_carries_two_factor_login(ctx):
    _two_factor(ctx, "AAAABBBBCCCCDDDD")
    data = backup.export_config(ctx, include_secrets=True)
    with ctx.wdb() as w:
        w.execute("UPDATE users SET totp_secret=NULL, totp_last=0, recovery=NULL")
    backup.import_config(ctx, data)
    assert _totp(ctx)["totp_secret"] == "AAAABBBBCCCCDDDD"


def test_forwarded_host_counts_only_from_a_trusted_proxy(ctx):
    """TestClient connects from 'testclient': trusted when TRUSTED_PROXIES names it, a stranger otherwise."""
    app = create_app(ctx)
    login = {"username": "admin", "password": PW}
    fwd = {"origin": "https://monitor.example", "x-forwarded-host": "monitor.example", "x-forwarded-proto": "https"}
    stranger = TestClient(behind_proxies(app, "127.0.0.1"), base_url="http://sniffowireless.test")
    r = stranger.post("/api/auth/login", json=login, headers=fwd)
    assert r.status_code == 403
    proxied = TestClient(behind_proxies(app, "testclient"), base_url="http://sniffowireless.test")
    r = proxied.post("/api/auth/login", json=login, headers=fwd)
    assert r.status_code == 200 and "secure" in r.headers["set-cookie"].lower()
    # the client itself saying https does not make the cookie Secure
    r = stranger.post("/api/auth/login", json=login, headers={"x-forwarded-proto": "https"})
    assert r.status_code == 200 and "secure" not in r.headers["set-cookie"].lower()


def test_host_names_and_ipv6_in_allowed_hosts(ctx):
    assert host_name("Example.org:8080") == "example.org" and host_name("example.org") == "example.org"
    assert host_name("[::1]:8080") == "::1" and host_name("[::1]") == "::1" and host_name("[fe80::1") == "fe80::1"
    ctx.cfg.allowed_hosts = ["::1"]
    app = create_app(ctx)
    c = TestClient(app, base_url="http://sniffowireless.test")
    for host in ("[::1]", "[::1]:8080"):
        assert c.get("/api/health", headers={"host": host}).status_code == 200
    assert c.get("/api/health", headers={"host": "evil.example"}).status_code == 421


def test_api_docs_need_a_sign_in_and_load_only_the_pinned_swagger(ctx):
    app = create_app(ctx)
    assert client(app).get("/api/docs", follow_redirects=False).status_code == 401
    r = client(app, "view").get("/api/docs")
    assert r.status_code == 200 and SWAGGER_JS in r.text and "@5.17.14/" in r.text
    assert r.headers["content-security-policy"] == DOCS_CSP
    assert "frame-ancestors 'none'" in DOCS_CSP and "connect-src 'self'" in DOCS_CSP
    assert httpsec.CSP in client(app, "view").get("/").headers["content-security-policy"]


def test_deeply_nested_sensor_json_is_a_bad_request(ctx):
    tid, token = ctx.auth.create_token("s", "sensor", "s1")
    ctx.execute("INSERT INTO sensors(id, name, token_id, created) VALUES('s1', 's', ?, 0)", (tid,))
    c = TestClient(create_app(ctx), base_url="http://sniffowireless.test", raise_server_exceptions=False)
    r = c.post("/api/ingest", content=b"[" * 200_000, headers={"authorization": "Bearer " + token})
    assert r.status_code == 400
