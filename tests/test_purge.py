import time

import pytest
from fastapi.testclient import TestClient

from sniffowireless import logs, status
from sniffowireless.auth import hash_password
from sniffowireless.config import Config
from sniffowireless.main import build
from sniffowireless.purge import SPEC, log_predicate
from sniffowireless.web import create_app
from tests.test_lora import PROFILES, frame, meshtastic

PW = "correct-horse-battery"
AP, CLIENT, BLE, LAN = "a4:83:e7:5c:21:0b", "dc:a6:32:11:22:33", "d4:44:dd:02:00:05", "00:80:77:5d:19:88"


@pytest.fixture
def ctx(tmp_path):
    status.SENSORS.clear()
    c = build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))
    c.store.command = lambda fn: fn(c.store)  # no writer thread in tests: run what is queued for it right away
    with c.wdb() as w:
        for name, role in (("admin", "admin"), ("view", "viewer")):
            w.execute("INSERT INTO users(username, pw_hash, role, created) VALUES(?, ?, ?, 0)", (name, hash_password(PW, iterations=1000), role))
    now = time.time()
    p = c.store.process
    p({"t": "wifi_ap", "ts": now - 50, "mac": AP, "ssid": "HomeNet", "enc": "WPA2", "rssi": -50, "channel": 6, "freq": 2437, "band": "2.4"})
    p({"t": "wifi_client", "ts": now - 40, "mac": CLIENT, "bssid": AP, "frame": "data", "rssi": -60, "channel": 6, "freq": 2437, "band": "2.4"})
    p({"t": "bt", "ts": now - 30, "mac": BLE, "kind": "ble", "rssi": -70, "name": "Keys"})
    p({"t": "lan", "ts": now - 20, "mac": LAN, "ip": "192.168.1.5", "name": "nas", "src": "dhcp"})
    p({"t": "lan", "ts": now - 19, "mac": LAN, "ip": "192.168.1.5", "dns": "example.org", "src": "dns"})
    p({"t": "zb_network", "ts": now - 10, "mac": "-", "ext_pan": "00:12:4b:00:1e:a0:44:01", "pan": 0x1A62, "channel": 15, "permit_join": False,
       "stack_profile": 2, "update_id": 1, "lqi": 200, "rssi": -50, "routers": []})
    p({"t": "zb_frames", "ts": now - 9, "mac": "-", "undecoded": 0, "channels": {"15": 4}, "radios": [[0x1A62, "0x0001", 1 << 15, 4, 0, 0, 1, 1, -70, 150]]})
    p(frame(meshtastic(frm=0xA1), PROFILES["meshtastic-eu868"], now - 5))
    c.security.finding(c.store, now, f"rogue:{AP}", "rogue_ap", "high", AP, "HomeNet", "Rogue", "x")
    c.security.finding(c.store, now, f"rogue_dhcp:{LAN}", "rogue_dhcp", "high", LAN, None, "Rogue DHCP server", "x")
    c.store._event(now, "rf:5", "interference", None, "noise on 5 GHz", always=True)
    c.store.flush()
    with c.wdb() as w:
        w.execute("INSERT INTO device_meta(mac, label, known, updated) VALUES(?, 'Alice phone', 1, 0)", (CLIENT,))
        w.execute("INSERT INTO alert_log(ts, rule_id, rule_name, mac, type, title, body, severity, delivered) VALUES(?, 1, 'r', 'lora:!000000a1', 'lora_new_node', 't', 'b', 'low', '{}')", (now,))
        w.execute("INSERT INTO alert_log(ts, rule_id, rule_name, mac, type, title, body, severity, delivered) VALUES(?, 1, 'r', ?, 'rogue_ap', 't', 'b', 'high', '{}')", (now, AP))
    return c


def client(ctx, user="admin"):
    c = TestClient(create_app(ctx), base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    assert c.post("/api/auth/login", json={"username": user, "password": PW}).status_code == 200
    return c


def n(ctx, sql, *p):
    return ctx.one(sql, p)["n"]


def test_preview_counts_what_would_go(ctx):
    d = {m["id"]: m for m in client(ctx).get("/api/purge").json()["modules"]}
    assert list(d) == ["wifi", "bluetooth", "lan", "zigbee", "lora"]
    assert d["wifi"]["entries"]["devices"] == 2 and d["wifi"]["entries"]["findings"] == 1 and d["bluetooth"]["entries"]["devices"] == 1
    assert d["lan"]["entries"]["devices"] == 1 and d["lan"]["entries"]["findings"] == 1 and d["lan"]["entries"]["lan_dns"] == 1
    assert d["zigbee"]["entries"]["zigbee_radios"] == 1 and d["lora"]["entries"]["lora_nodes"] == 1 and d["lora"]["entries"]["lora_packets"] == 1
    assert d["lora"]["logs"] == {"events": 1, "alert_log": 1} and d["zigbee"]["logs"]["events"] == 1
    assert d["wifi"]["logs"]["events"] >= 3 and d["wifi"]["logs"]["alert_log"] == 1      # the rogue AP finding, interference, ... and the alert for it


def test_clearing_one_module_leaves_the_others_and_your_labels(ctx):
    c = client(ctx)
    r = c.post("/api/purge", json={"module": "wifi", "entries": True, "confirm": "wifi"})
    assert r.status_code == 200 and r.json()["deleted"]["devices"] == 2 and r.json()["entries_total"] == 0
    assert n(ctx, "SELECT COUNT(*) n FROM devices WHERE kind IN ('ap','wifi_client')") == 0
    assert n(ctx, "SELECT COUNT(*) n FROM sessions WHERE mac=? OR peer=?", CLIENT, AP) == 0 and n(ctx, "SELECT COUNT(*) n FROM samples WHERE mac IN (?, ?)", AP, CLIENT) == 0
    assert n(ctx, "SELECT COUNT(*) n FROM findings WHERE type='rogue_ap'") == 0 and n(ctx, "SELECT COUNT(*) n FROM findings WHERE type='rogue_dhcp'") == 1
    # the others are untouched, and so are your labels
    assert n(ctx, "SELECT COUNT(*) n FROM devices WHERE kind IN ('ble','lan')") == 2 and n(ctx, "SELECT COUNT(*) n FROM lora_nodes") == 1
    assert n(ctx, "SELECT COUNT(*) n FROM zigbee_radios") == 1
    assert ctx.one("SELECT label FROM device_meta WHERE mac=?", (CLIENT,))["label"] == "Alice phone"
    assert n(ctx, "SELECT COUNT(*) n FROM events WHERE type='lora_new_node'") == 1       # entries only: the events stay


def test_events_and_alert_history_can_be_cleared_on_their_own(ctx):
    c = client(ctx)
    r = c.post("/api/purge", json={"module": "lora", "logs": True, "confirm": "lora"}).json()
    assert r["deleted"] == {"events": 1, "alert_log": 1}
    assert n(ctx, "SELECT COUNT(*) n FROM lora_nodes") == 1 and n(ctx, "SELECT COUNT(*) n FROM events WHERE type='lora_new_node'") == 0
    assert n(ctx, "SELECT COUNT(*) n FROM alert_log WHERE type='rogue_ap'") == 1         # another module's history stays
    assert n(ctx, "SELECT COUNT(*) n FROM events WHERE type='zigbee_new_network'") == 1


def test_a_cleared_module_starts_over(ctx):
    c = client(ctx)
    assert c.post("/api/purge", json={"module": "lora", "entries": True, "logs": True, "confirm": "lora"}).status_code == 200
    for t in ("lora_nodes", "lora_packets", "lora_stats"):
        assert n(ctx, f"SELECT COUNT(*) n FROM {t}") == 0
    assert n(ctx, "SELECT COUNT(*) n FROM radio_seen WHERE kind='lora'") == 0 and n(ctx, "SELECT COUNT(*) n FROM radio_seen WHERE kind='zigbee'") == 1
    ctx.store.process(frame(meshtastic(frm=0xA1), PROFILES["meshtastic-eu868"], time.time()))  # the same node again counts as new
    ctx.store.flush()
    assert n(ctx, "SELECT COUNT(*) n FROM events WHERE type='lora_new_node'") == 1 and n(ctx, "SELECT COUNT(*) n FROM lora_nodes") == 1
    # zigbee, lan and bluetooth go the same way
    for m in ("zigbee", "lan", "bluetooth"):
        assert c.post("/api/purge", json={"module": m, "entries": True, "confirm": m}).status_code == 200
    assert n(ctx, "SELECT COUNT(*) n FROM zigbee_networks") == 0 and n(ctx, "SELECT COUNT(*) n FROM devices WHERE kind IN ('ble','lan')") == 0
    assert n(ctx, "SELECT COUNT(*) n FROM lan_dns") == 0 and n(ctx, "SELECT COUNT(*) n FROM devices WHERE kind='ap'") == 1


def test_it_asks_for_confirmation_and_only_admins_may(ctx):
    c = client(ctx)
    assert c.post("/api/purge", json={"module": "wifi", "entries": True}).status_code == 400
    assert c.post("/api/purge", json={"module": "wifi", "entries": True, "confirm": "lora"}).status_code == 400
    assert c.post("/api/purge", json={"module": "wifi", "confirm": "wifi"}).status_code == 400
    assert c.post("/api/purge", json={"module": "toaster", "entries": True, "confirm": "toaster"}).status_code == 400
    assert n(ctx, "SELECT COUNT(*) n FROM devices") == 4
    v = client(ctx, "view")
    assert v.get("/api/purge").status_code == 403 and v.post("/api/purge", json={"module": "wifi", "entries": True, "confirm": "wifi"}).status_code == 403
    assert v.delete("/api/purge/app-log").status_code == 403 and n(ctx, "SELECT COUNT(*) n FROM devices") == 4


def test_application_log_can_be_cleared(ctx):
    import logging
    root = logging.getLogger()
    root.addHandler(logs.HANDLER)  # main() does this; the tests don't
    try:
        logging.getLogger("sniffowireless.test").warning("something to clear")
        assert any("something to clear" in r["msg"] for r in logs.HANDLER.since(0))
        r = client(ctx).delete("/api/purge/app-log")
        assert r.status_code == 200 and r.json()["deleted"] >= 1
        assert not any("something to clear" in r["msg"] for r in logs.HANDLER.since(0))
    finally:
        root.removeHandler(logs.HANDLER)


def test_every_module_has_a_log_predicate():
    for m in SPEC:
        where, params = log_predicate(m)
        assert where.startswith("(") and where.count("?") == len(params)
