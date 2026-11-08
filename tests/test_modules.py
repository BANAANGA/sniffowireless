import time

import pytest
from fastapi.testclient import TestClient

from sniffowireless import status
from sniffowireless.auth import hash_password
from sniffowireless.config import Config
from sniffowireless.main import build
from sniffowireless.web import create_app

PW = "correct-horse-battery"


@pytest.fixture
def ctx(tmp_path):
    status.SENSORS.clear()
    c = build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))
    with c.wdb() as w:
        for name, role in (("admin", "admin"), ("view", "viewer")):
            w.execute("INSERT INTO users(username, pw_hash, role, created) VALUES(?, ?, ?, 0)", (name, hash_password(PW, iterations=1000), role))
    return c


def client(ctx, user):
    c = TestClient(create_app(ctx), base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    assert c.post("/api/auth/login", json={"username": user, "password": PW}).status_code == 200
    return c


def test_modules_default_to_shown_and_report_what_is_in_use(ctx):
    c = client(ctx, "admin")
    mods = {m["id"]: m for m in c.get("/api/modules").json()["modules"]}
    assert list(mods) == ["wifi", "bluetooth", "lan", "zigbee", "lora"]
    assert all(m["enabled"] for m in mods.values()) and not any(m["in_use"] for m in mods.values())
    # a configured sensor interface, or stored data, counts as in use
    status.register("lora:x", type="lora", iface="/dev/x")
    status.register("wlan1", type="wifi", iface="wlan1")
    status.register("eth1", type="ethernet", iface="eth1")
    ctx.store.process({"t": "ap", "ts": time.time(), "mac": "aa:bb:cc:00:00:01", "ssid": "x", "enc": "WPA2", "rssi": -50, "channel": 1})
    ctx.store.flush()
    mods = {m["id"]: m["in_use"] for m in c.get("/api/modules").json()["modules"]}
    assert mods == {"wifi": True, "bluetooth": False, "lan": True, "zigbee": False, "lora": True}


def test_admin_can_hide_modules_and_it_sticks(ctx):
    c = client(ctx, "admin")
    r = c.put("/api/modules", json={"disabled": ["lora", "zigbee", "lora"]})
    assert r.status_code == 200
    assert {m["id"] for m in r.json()["modules"] if not m["enabled"]} == {"lora", "zigbee"}
    assert ctx.settings.get("modules")["disabled"] == ["lora", "zigbee"]
    # a fresh session (and a viewer) sees the same
    v = client(ctx, "view")
    assert {m["id"] for m in v.get("/api/modules").json()["modules"] if not m["enabled"]} == {"lora", "zigbee"}
    assert c.put("/api/modules", json={"disabled": []}).json()["modules"][0]["enabled"] is True
    assert all(m["enabled"] for m in v.get("/api/modules").json()["modules"])


def test_only_admins_change_modules_and_ids_are_checked(ctx):
    v = client(ctx, "view")
    assert v.put("/api/modules", json={"disabled": ["lora"]}).status_code == 403
    assert TestClient(create_app(ctx), base_url="http://sniffowireless.test").get("/api/modules").status_code == 401
    a = client(ctx, "admin")
    assert a.put("/api/modules", json={"disabled": ["toaster"]}).status_code == 400
    assert a.put("/api/modules", json={"disabled": "lora"}).status_code == 422
    assert ctx.settings.get("modules")["disabled"] == []


def test_a_module_can_keep_its_data_for_a_shorter_time_than_the_rest(ctx):
    from tests.test_lora import PROFILES, frame, meshtastic
    a = client(ctx, "admin")
    r = a.put("/api/modules", json={"disabled": ["zigbee"], "retention": {"lora": 1}})
    assert r.status_code == 200
    d = {m["id"]: m for m in r.json()["modules"]}
    assert d["lora"]["retention"] == 1 and d["lora"]["has_retention"] and d["zigbee"]["retention"] is None and not d["wifi"]["has_retention"]
    assert r.json()["default_retention"] == ctx.cfg.retention_days and not d["zigbee"]["enabled"]
    # the retention survives another change of what is shown
    assert a.put("/api/modules", json={"disabled": []}).json()["modules"][-1]["retention"] == 1
    now = time.time()
    eu = PROFILES["meshtastic-eu868"]
    ctx.store.process(frame(meshtastic(frm=1), eu, now - 2 * 86400))   # older than the module's 1 day, newer than the general 30
    ctx.store.process(frame(meshtastic(frm=2), eu, now - 3600))
    ctx.store.flush()
    ctx.store.prune(now)
    assert [r["addr"] for r in ctx.rows("SELECT addr FROM lora_nodes")] == ["!00000002"]
    assert ctx.one("SELECT COUNT(*) n FROM lora_packets")["n"] == 1
    # no module retention: the general one applies again
    assert a.put("/api/modules", json={"disabled": [], "retention": {"lora": 0}}).json()["modules"][-1]["retention"] is None
    ctx.store.process(frame(meshtastic(frm=3), eu, now - 2 * 86400))
    ctx.store.flush()
    ctx.store.prune(now)
    assert ctx.one("SELECT COUNT(*) n FROM lora_nodes")["n"] == 2


def test_retention_is_validated(ctx):
    a = client(ctx, "admin")
    assert a.put("/api/modules", json={"disabled": [], "retention": {"wifi": 5}}).status_code == 400
    assert a.put("/api/modules", json={"disabled": [], "retention": {"lora": 99999}}).status_code == 400
    assert a.put("/api/modules", json={"disabled": [], "retention": {"lora": -1}}).status_code == 400
    assert ctx.settings.get("modules")["retention"] == {}
