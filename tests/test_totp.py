import time

import pytest
from fastapi.testclient import TestClient

from sniffowireless import status, totp
from sniffowireless.auth import hash_password
from sniffowireless.config import Config
from sniffowireless.main import build
from sniffowireless.web import create_app

PW = "correct-horse-battery"


def test_rfc_6238_vectors():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890"
    assert totp.code_at(secret, 59 // 30, 8) == "94287082" and totp.code_at(secret, 1111111109 // 30, 8) == "07081804"
    assert totp.code_at(secret, 59 // 30) == "287082"


def test_verify_window_and_replay():
    s = totp.new_secret()
    now = 1_700_000_000
    step = now // 30
    code = totp.code_at(s, step)
    assert totp.verify(s, code, 0, now) == step
    assert totp.verify(s, totp.code_at(s, step - 1), 0, now) == step - 1 and totp.verify(s, totp.code_at(s, step + 1), 0, now) == step + 1
    assert totp.verify(s, totp.code_at(s, step + 2), 0, now) is None and totp.verify(s, totp.code_at(s, step - 2), 0, now) is None
    assert totp.verify(s, code, step, now) is None                         # the step was used: not again
    assert totp.verify(s, "12345", 0, now) is None and totp.verify(s, "abcdef", 0, now) is None and totp.verify(s, "", 0, now) is None
    assert totp.uri("ABC", "alice smith").startswith("otpauth://totp/sniffowireless:alice%20smith?secret=ABC&issuer=sniffowireless")


@pytest.fixture
def ctx(tmp_path):
    status.SENSORS.clear()
    c = build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))
    with c.wdb() as w:
        for name, role in (("admin", "admin"), ("view", "viewer")):
            w.execute("INSERT INTO users(username, pw_hash, role, created) VALUES(?, ?, ?, 0)", (name, hash_password(PW, iterations=1000), role))
    return c


def fresh(ctx):
    return TestClient(create_app(ctx), base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})


def login(c, user="admin", code=None, pw=PW):
    body = {"username": user, "password": pw}
    if code is not None:
        body["code"] = code
    return c.post("/api/auth/login", json=body)


def turn_on(ctx, user="admin"):
    c = fresh(ctx)
    assert login(c, user).status_code == 200
    r = c.post("/api/me/2fa/begin", json={"password": PW}).json()
    code = totp.code_at(r["secret"], int(time.time() // 30))
    done = c.post("/api/me/2fa/enable", json={"code": code})
    assert done.status_code == 200
    return c, r["secret"], done.json()["recovery_codes"], int(time.time() // 30)


def test_turning_it_on_needs_the_password_and_a_working_code(ctx):
    c = fresh(ctx)
    login(c)
    assert c.get("/api/me/2fa").json() == {"enabled": False, "recovery_left": 0}
    assert c.post("/api/me/2fa/begin", json={"password": "wrong"}).status_code == 403
    r = c.post("/api/me/2fa/begin", json={"password": PW}).json()
    assert r["uri"].startswith("otpauth://totp/sniffowireless:admin?secret=" + r["secret"])
    assert c.post("/api/me/2fa/enable", json={"code": "000000"}).status_code == 400
    assert c.get("/api/me/2fa").json()["enabled"] is False
    ok = c.post("/api/me/2fa/enable", json={"code": totp.code_at(r["secret"], int(time.time() // 30))})
    assert ok.status_code == 200 and len(ok.json()["recovery_codes"]) == 10 and all(len(x) == 11 and x[5] == "-" for x in ok.json()["recovery_codes"])
    assert c.get("/api/me/2fa").json() == {"enabled": True, "recovery_left": 10}
    assert c.post("/api/me/2fa/begin", json={"password": PW}).status_code == 409
    row = ctx.one("SELECT totp_secret, recovery FROM users WHERE username='admin'")
    assert row["totp_secret"] == r["secret"] and ok.json()["recovery_codes"][0].replace("-", "") not in row["recovery"]   # recovery codes are stored hashed


def test_signing_in_then_needs_the_code(ctx):
    _, secret, _, step = turn_on(ctx)
    c = fresh(ctx)
    r = login(c)
    assert r.status_code == 401 and r.json()["detail"]["code"] == "totp_required"
    assert c.get("/api/auth/state").json()["user"] is None
    bad = login(c, code="123456")
    assert bad.status_code == 401 and bad.json()["detail"]["code"] == "totp_invalid"
    assert login(c, code=totp.code_at(secret, step + 1)).status_code == 200      # a step ahead is within the window (clock drift)
    assert c.get("/api/auth/state").json()["user"]["username"] == "admin"
    # the same code (or an older one) does not work again
    again = fresh(ctx)
    assert login(again, code=totp.code_at(secret, step + 1)).status_code == 401 and login(again, code=totp.code_at(secret, step)).status_code == 401
    assert login(again, "admin", code="123456", pw="wrong-password").json()["detail"] == "Invalid username or password"   # no hint without the password


def test_a_wrong_password_never_hints_at_the_second_factor(ctx):
    turn_on(ctx)
    r = login(fresh(ctx), pw="nope-nope-nope")
    assert r.status_code == 401 and r.json()["detail"] == "Invalid username or password"
    assert login(fresh(ctx), "view").status_code == 200                         # others are unaffected


def test_wrong_codes_count_toward_the_lockout(ctx):
    turn_on(ctx)
    c = fresh(ctx)
    for _ in range(12):
        login(c, code="000000")
    assert login(c, code="000000").status_code == 429


def test_recovery_codes_work_once(ctx):
    _, _, codes, _ = turn_on(ctx)
    c = fresh(ctx)
    assert login(c, code=codes[0]).status_code == 200
    assert login(fresh(ctx), code=codes[0]).status_code == 401
    assert login(fresh(ctx), code=codes[1].replace("-", "").upper()).status_code == 200   # case and the dash do not matter
    assert fresh(ctx) and login(c, code=codes[2]).status_code == 200
    assert c.get("/api/me/2fa").json()["recovery_left"] == 7


def test_turning_it_off_asks_for_password_and_code(ctx):
    c, secret, codes, step = turn_on(ctx)
    assert c.post("/api/me/2fa/disable", json={"password": "wrong", "code": codes[0]}).status_code == 403
    assert c.post("/api/me/2fa/disable", json={"password": PW, "code": "000000"}).status_code == 403
    assert c.get("/api/me/2fa").json()["enabled"] is True
    assert c.post("/api/me/2fa/disable", json={"password": PW, "code": codes[0]}).status_code == 200
    assert login(fresh(ctx)).status_code == 200                                    # a password is enough again


def test_other_sessions_are_signed_out_when_it_is_turned_on(ctx):
    other = fresh(ctx)
    login(other)
    assert other.get("/api/auth/state").json()["user"]["username"] == "admin"
    c, *_ = turn_on(ctx)
    assert other.get("/api/auth/state").json()["user"] is None
    assert c.get("/api/auth/state").json()["user"]["username"] == "admin"


def test_an_admin_can_reset_someone_elses_second_factor(ctx):
    turn_on(ctx, "view")
    admin = fresh(ctx)
    login(admin)
    users = {u["username"]: u for u in admin.get("/api/users").json()}
    assert users["view"]["totp"] == 1 and users["admin"]["totp"] == 0
    assert login(fresh(ctx), "view").status_code == 401
    assert admin.delete(f"/api/users/{users['view']['id']}/2fa").status_code == 200
    assert login(fresh(ctx), "view").status_code == 200
    v = fresh(ctx)
    login(v, "view")
    assert v.delete(f"/api/users/{users['admin']['id']}/2fa").status_code == 403


def test_the_environment_can_remove_it_for_a_lost_phone(ctx, tmp_path):
    turn_on(ctx)
    from sniffowireless.auth import Auth
    from sniffowireless.store import connect
    Auth(Config(db_path=ctx.cfg.db_path, data_dir=str(tmp_path), reset_2fa_user="admin"), lambda: connect(ctx.cfg.db_path))
    assert login(fresh(ctx)).status_code == 200
