import csv
import io
import re
import time

import pytest
from fastapi.testclient import TestClient

from sniffowireless import status
from sniffowireless.anonymize import MAC_RE, AnonymizeMiddleware
from sniffowireless.auth import hash_password
from sniffowireless.config import Config
from sniffowireless.main import build
from sniffowireless.web import create_app

PW = "correct-horse-battery"
AP, CLIENT = "a4:83:e7:5c:21:0b", "dc:a6:32:11:22:33"


@pytest.fixture
def ctx(tmp_path):
    status.SENSORS.clear()
    c = build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))
    with c.wdb() as w:
        w.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('admin', ?, 'admin', 0)", (hash_password(PW, iterations=1000),))
    now = time.time()
    c.store.process({"t": "wifi_ap", "ts": now - 20, "mac": AP, "ssid": "HomeNet-Secret", "enc": "WPA2", "rssi": -50, "channel": 6, "freq": 2437, "band": "2.4"})
    c.store.process({"t": "wifi_client", "ts": now - 10, "mac": CLIENT, "bssid": AP, "frame": "data", "rssi": -60, "channel": 6, "freq": 2437, "band": "2.4"})
    c.store.process({"t": "zb_network", "ts": now, "mac": "-", "ext_pan": "00:12:4b:00:1e:a0:44:01", "pan": 0x1A62, "channel": 15, "permit_join": False,
                     "stack_profile": 2, "update_id": 1, "lqi": 200, "rssi": -50, "routers": []})
    c.store.flush()
    return c


def login(ctx):
    c = TestClient(create_app(ctx), base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    assert c.post("/api/auth/login", json={"username": "admin", "password": PW}).status_code == 200
    return c


def set_privacy(c, macs, ssids):
    assert c.put("/api/privacy", json={"macs": macs, "ssids": ssids}).status_code == 200


def test_nothing_changes_while_the_setting_is_off(ctx):
    c = login(ctx)
    text = c.get("/api/devices?limit=50").text
    assert AP in text and CLIENT in text and "HomeNet-Secret" in text


def test_macs_and_ssids_become_stable_pseudonyms(ctx):
    c = login(ctx)
    set_privacy(c, True, True)
    r = c.get("/api/devices?limit=50")
    assert AP not in r.text and CLIENT not in r.text and "HomeNet-Secret" not in r.text
    items = {d["kind"]: d for d in r.json()["items"]}
    ap, cl = items["ap"], items["wifi_client"]
    assert ap["mac"].startswith("a4:83:e7:") and ap["mac"] != AP and MAC_RE.fullmatch(ap["mac"])   # the vendor part stays
    assert cl["mac"].startswith("dc:a6:32:") and re.fullmatch(r"Network-[0-9a-f]{6}", ap["ssid"])
    assert cl["bssid"] == ap["mac"]                                                                  # the same MAC is the same pseudonym everywhere
    assert c.get("/api/devices?limit=50").json()["items"] == r.json()["items"]                      # and on every request
    assert login(ctx).get("/api/devices?limit=50").json()["items"] == r.json()["items"]             # and for every user session


def test_each_setting_works_on_its_own(ctx):
    c = login(ctx)
    set_privacy(c, True, False)
    t = c.get("/api/devices?limit=50").text
    assert AP not in t and "HomeNet-Secret" in t
    set_privacy(c, False, True)
    t = c.get("/api/devices?limit=50").text
    assert AP in t and "HomeNet-Secret" not in t


def test_pseudonyms_in_requests_find_the_real_records(ctx):
    c = login(ctx)
    set_privacy(c, True, True)
    items = {d["kind"]: d for d in c.get("/api/devices?limit=50").json()["items"]}
    ap, cl = items["ap"], items["wifi_client"]
    # in the path
    d = c.get(f"/api/devices/{cl['mac']}")
    assert d.status_code == 200 and d.json()["mac"] == cl["mac"]
    # in the query: by SSID and by MAC search
    by_ssid = c.get("/api/devices", params={"ssid": ap["ssid"], "limit": 50}).json()["items"]
    assert {x["mac"] for x in by_ssid} == {ap["mac"], cl["mac"]}
    assert [x["mac"] for x in c.get("/api/devices", params={"q": cl["mac"]}).json()["items"]] == [cl["mac"]]
    # in a JSON body: the label lands on the real device
    assert c.put(f"/api/devices/{cl['mac']}/meta", json={"label": "Alice phone"}).status_code == 200
    assert ctx.one("SELECT label FROM device_meta WHERE mac=?", (CLIENT,))["label"] == "Alice phone"
    assert ctx.one("SELECT COUNT(*) n FROM device_meta WHERE mac=?", (cl["mac"],))["n"] == 0
    # a pseudonym that belongs to nothing is simply not found
    assert c.get("/api/devices/a4:83:e7:00:00:00").status_code == 404


def test_pseudonyms_survive_a_restart(ctx):
    c = login(ctx)
    set_privacy(c, True, True)
    cl = next(d for d in c.get("/api/devices?limit=50").json()["items"] if d["kind"] == "wifi_client")
    again = login(ctx)  # a new app: nothing remembered in memory, the reverse map is rebuilt from the database
    assert again.get(f"/api/devices/{cl['mac']}").status_code == 200


def test_text_exports_and_events_are_masked_too(ctx):
    c = login(ctx)
    ctx.store._event(time.time(), CLIENT, "new_device", f"ssid:HomeNet-Secret", f"joined “HomeNet-Secret” via {AP}", always=True)
    ctx.store.flush()
    set_privacy(c, True, True)
    ev = c.get("/api/events?limit=20").text
    assert AP not in ev and CLIENT not in ev and "HomeNet-Secret" not in ev and "Network-" in ev
    rows = list(csv.DictReader(io.StringIO(c.get("/api/export/devices.csv").text)))
    flat = " ".join(" ".join(r.values()) for r in rows)
    assert AP not in flat and CLIENT not in flat and "HomeNet-Secret" not in flat and len(rows) == 2


def test_only_unicast_macs_that_stand_alone_are_masked(ctx):
    c = login(ctx)
    set_privacy(c, True, False)
    z = c.get("/api/zigbee").text
    assert "00:12:4b:00:1e:a0:44:01" in z                                  # an 8 byte IEEE address is not a MAC address
    from sniffowireless.anonymize import Anonymizer
    an = Anonymizer(ctx)
    assert an.mac("ff:ff:ff:ff:ff:ff") == "ff:ff:ff:ff:ff:ff" and an.mac("01:00:5e:00:00:fb") == "01:00:5e:00:00:fb"
    assert an.mac(AP) != AP and an.mac(AP.upper()) == an.mac(AP)


def test_sensor_uploads_are_never_touched(ctx):
    m = AnonymizeMiddleware(None, ctx)
    assert not m.applies("/api/ingest") and not m.applies("/api/privacy") and not m.applies("/static/app.js") and not m.applies("/login")
    assert m.applies("/api/devices") and m.applies("/metrics")


def test_only_admins_change_the_setting(ctx):
    with ctx.wdb() as w:
        w.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('view', ?, 'viewer', 0)", (hash_password(PW, iterations=1000),))
    v = TestClient(create_app(ctx), base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    assert v.post("/api/auth/login", json={"username": "view", "password": PW}).status_code == 200
    assert v.put("/api/privacy", json={"macs": True, "ssids": True}).status_code == 403
    assert v.get("/api/privacy").json() == {"macs": False, "ssids": False}
    assert ctx.settings.get("privacy")["secret"] == ""


def test_metrics_labels_are_masked(ctx):
    c = login(ctx)
    plain = c.get("/metrics").text
    assert AP in plain and "HomeNet-Secret" in plain          # there is something to hide
    set_privacy(c, True, True)
    t = c.get("/metrics").text
    assert AP not in t and "HomeNet-Secret" not in t and 'ssid="Network-' in t


def test_macs_inside_text_and_ssid_keyed_dictionaries(ctx):
    from sniffowireless.anonymize import Anonymizer
    an = Anonymizer(ctx)
    ctx.settings.set("networks", {"ssids": ["HomeNet-Secret"], "trusted_bssids": []})
    p = an.mac(AP)
    out = an.mask_json({"detail": f"“HomeNet-Secret” broadcast by BSSID {AP}: locally administered", "key": f"nowpa3:{AP}", "key2": f"rogue:{AP}",
                        "ext": "00:12:4b:00:1e:a0:44:01", "source": "Network name “HomeNet-Secret”", "ssid_time": {"HomeNet-Secret": 12.5}, "series": {"HomeNet-Secret": [1, 2], "ap": [3]},
                        "list": [AP, {"peer": "ssid:HomeNet-Secret", "mac": CLIENT}], AP: 1}, True, True)
    n = an.ssid("HomeNet-Secret")
    assert out["detail"] == f"“{n}” broadcast by BSSID {p}: locally administered"
    assert out["key"] == f"nowpa3:{p}" and out["key2"] == f"rogue:{p}" and out["ext"] == "00:12:4b:00:1e:a0:44:01"
    assert out["source"] == f"Network name “{n}”" and out["ssid_time"] == {n: 12.5} and out["series"] == {n: [1, 2], "ap": [3]}
    assert out["list"][0] == p and out["list"][1] == {"peer": f"ssid:{n}", "mac": an.mac(CLIENT)} and out[p] == 1
    # and back
    assert an.unmask_str(f"/api/x/{p}/y?q=nowpa3:{p}", True, True) == f"/api/x/{AP}/y?q=nowpa3:{AP}"
    assert an.unmask_str(f"ssid:{n}", True, True) == "ssid:HomeNet-Secret"
