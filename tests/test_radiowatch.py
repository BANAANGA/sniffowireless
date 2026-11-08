import time

import pytest
from fastapi.testclient import TestClient

from sniffowireless import status
from sniffowireless.auth import hash_password
from sniffowireless.config import Config
from sniffowireless.main import build
from sniffowireless.web import create_app
from tests.test_lora import PROFILES, frame, meshtastic

PW = "correct-horse-battery"


@pytest.fixture
def ctx(tmp_path):
    status.SENSORS.clear()
    c = build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))
    with c.wdb() as w:
        for name, role in (("admin", "admin"), ("view", "viewer")):
            w.execute("INSERT INTO users(username, pw_hash, role, created) VALUES(?, ?, ?, 0)", (name, hash_password(PW, iterations=1000), role))
    return c


def client(ctx, user="admin"):
    c = TestClient(create_app(ctx), base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    assert c.post("/api/auth/login", json={"username": user, "password": PW}).status_code == 200
    return c


def events(ctx, *types):
    ctx.store.flush()
    return ctx.rows(f"SELECT type, mac, peer, detail FROM events WHERE type IN ({','.join('?' * len(types))}) ORDER BY id", types)


def sweep(ctx, now):
    ctx.radiowatch.checked = 0
    ctx.radiowatch.sweep(ctx.store, now)


def test_a_watched_node_raises_events_when_it_goes_silent_and_comes_back(ctx):
    c = client(ctx)
    now = time.time()
    eu = PROFILES["meshtastic-eu868"]
    ctx.store.process(frame(meshtastic(frm=0x77), eu, now - 2 * 3600))
    ctx.store.flush()
    r = c.put("/api/radios/watch", json={"kind": "lora", "ref": "meshtastic", "addr": "!00000077", "label": "Garden node", "watch": True, "silent_min": 60})
    assert r.status_code == 200 and r.json()["state"] == "ok" and r.json()["label"] == "Garden node"
    sweep(ctx, now)
    ev = events(ctx, "watched_silent", "watched_back")
    assert [e["type"] for e in ev] == ["watched_silent"] and ev[0]["mac"] == "lora:!00000077" and "Garden node has not been heard for 2 hours" in ev[0]["detail"]
    sweep(ctx, now + 300)
    assert len(events(ctx, "watched_silent")) == 1                          # once, not every minute
    ctx.store.process(frame(meshtastic(frm=0x77, pid=2), eu, now + 400))   # heard again
    ctx.store.flush()
    sweep(ctx, now + 450)
    assert [e["type"] for e in events(ctx, "watched_silent", "watched_back")] == ["watched_silent", "watched_back"]
    sweep(ctx, now + 500)
    assert len(events(ctx, "watched_back")) == 1
    # silent again later: a new event
    sweep(ctx, now + 450 + 3 * 3600)
    assert len(events(ctx, "watched_silent")) == 2


def test_a_node_never_heard_and_a_node_not_watched_raise_nothing(ctx):
    c = client(ctx)
    now = time.time()
    c.put("/api/radios/watch", json={"kind": "lora", "ref": "meshtastic", "addr": "!00000099", "watch": True})       # never heard
    ctx.store.process(frame(meshtastic(frm=0x55), PROFILES["meshtastic-eu868"], now - 5 * 3600))
    ctx.store.flush()
    c.put("/api/radios/watch", json={"kind": "lora", "ref": "meshtastic", "addr": "!00000055", "label": "Only a name", "watch": False})
    sweep(ctx, now)
    assert events(ctx, "watched_silent") == []


def test_zigbee_radios_can_be_watched_too(ctx):
    c = client(ctx)
    now = time.time()
    ctx.store.process({"t": "zb_frames", "ts": now - 3 * 3600, "mac": "-", "undecoded": 0, "channels": {"15": 4},
                       "radios": [[0x1A62, "0x0001", 1 << 15, 4, 0, 0, 1, 1, -70, 150]]})
    ctx.store.flush()
    assert c.put("/api/radios/watch", json={"kind": "zigbee", "ref": "6754", "addr": "0x0001", "label": "Hall sensor", "watch": True, "silent_min": 30}).status_code == 200
    sweep(ctx, now)
    ev = events(ctx, "watched_silent")
    assert len(ev) == 1 and ev[0]["mac"] == "zb:0x0001" and "Hall sensor" in ev[0]["detail"]


def test_names_and_watches_show_in_the_lists(ctx):
    c = client(ctx)
    now = time.time()
    ctx.store.process(frame(meshtastic(frm=0x77), PROFILES["meshtastic-eu868"], now - 60))
    ctx.store.process({"t": "zb_frames", "ts": now - 30, "mac": "-", "undecoded": 0, "channels": {"15": 4}, "radios": [[0x1A62, "0x0001", 1 << 15, 4, 0, 0, 1, 1, -70, 150]]})
    ctx.store.flush()
    c.put("/api/radios/watch", json={"kind": "lora", "ref": "meshtastic", "addr": "!00000077", "label": "Garden node", "watch": True, "silent_min": 120})
    c.put("/api/radios/watch", json={"kind": "zigbee", "ref": str(0x1A62), "addr": "0x0001", "label": "Hall sensor"})
    n = c.get("/api/lora").json()["nodes"][0]
    assert (n["given_name"], n["watch"], n["silent_min"], n["watch_state"]) == ("Garden node", True, 120, "ok")
    z = c.get("/api/zigbee").json()["radios"][0]
    assert (z["given_name"], z["watch"]) == ("Hall sensor", False)
    assert len(c.get("/api/radios/watch").json()["items"]) == 2
    # emptying name and watch forgets it
    assert c.put("/api/radios/watch", json={"kind": "lora", "ref": "meshtastic", "addr": "!00000077"}).json() == {"deleted": True}
    assert c.get("/api/lora").json()["nodes"][0]["given_name"] is None


def test_validation_and_permissions(ctx):
    c = client(ctx)
    assert c.put("/api/radios/watch", json={"kind": "zigbee", "ref": "abc", "addr": "0x0001", "watch": True}).status_code == 400
    assert c.put("/api/radios/watch", json={"kind": "wifi", "ref": "x", "addr": "y"}).status_code == 422
    assert c.put("/api/radios/watch", json={"kind": "lora", "ref": "meshtastic", "addr": "!1", "watch": True, "silent_min": 1}).status_code == 422
    v = client(ctx, "view")
    assert v.put("/api/radios/watch", json={"kind": "lora", "ref": "meshtastic", "addr": "!1", "watch": True}).status_code == 403
    assert v.get("/api/radios/watch").status_code == 200


def test_watch_settings_are_part_of_the_label_backup_and_the_default_rule_exists(ctx):
    from sniffowireless import backup
    assert "radio_watch" in backup.CONFIG_TABLES
    assert "radio_watch" in next(s for s in backup.SECTIONS if s["id"] == "labels")["tables"]
    assert any("go silent" in r["name"] for r in ctx.rows("SELECT name FROM alert_rules"))
