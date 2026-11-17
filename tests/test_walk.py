"""Walk survey (release 34.1): tap where you stand, and the readings of the sensor you carry become a point of the heatmap."""
import time

from test_hardening import client, ctx  # noqa: F401  (ctx is a fixture)

from sniffowireless import walk
from sniffowireless.web import create_app

AP1, AP2 = "24:a4:3c:10:00:01", "aa:aa:aa:00:00:01"


def obs(ctx, mac, rssi, sensor=None, ts=None):
    o = {"t": "wifi_ap", "ts": ts or time.time(), "mac": mac, "rssi": rssi, "ssid": "Home" if mac == AP1 else "Other", "channel": 6,
         "freq": 2437, "band": "2.4"}
    if sensor:
        o["sensor"] = sensor
    ctx.store.process(o)


def test_readings_only_while_open_and_only_of_that_sensor(ctx):
    col = ctx.walk
    obs(ctx, AP1, -50)
    assert col.readings("local") == {}   # nothing kept before a survey is open
    col.start("local", 1)
    for r in (-50, -60, -55):
        obs(ctx, AP1, r)
    obs(ctx, AP2, -80)
    obs(ctx, AP2, -40, sensor="office")   # another sensor
    obs(ctx, AP2, -70, ts=time.time() - 30)   # too long ago for a point
    assert col.readings("local") == {AP1: -55, AP2: -80}
    col.stop(1)
    assert col.readings("local") == {}


def test_a_survey(ctx):
    ctx.settings.set("networks", {"ssids": ["Home"], "trusted_bssids": []})
    app = create_app(ctx)
    admin = client(app, "admin")
    sid = admin.post("/api/walk", json={"name": "Ground floor", "sensor": "local"}).json()["id"]
    assert admin.post(f"/api/walk/{sid}/point", json={"x": 0.2, "y": 0.3}).status_code == 409   # nothing heard yet
    obs(ctx, AP1, -52)
    obs(ctx, AP2, -77)
    ctx.store.flush()
    assert admin.get(f"/api/walk/{sid}/now").json() == {"aps": 2, "best_mine": -52, "open": True}
    r = admin.post(f"/api/walk/{sid}/point", json={"x": 0.2, "y": 0.3}).json()
    assert r["aps"] == 2
    d = admin.get(f"/api/walk/{sid}").json()
    assert d["open"] and d["points"][0]["readings"] == {AP1: -52, AP2: -77} and d["aps"][AP1]["mine"] and not d["aps"][AP2]["mine"]
    assert admin.post(f"/api/walk/{sid}/point", json={"x": 1.5, "y": 0.3}).status_code == 422
    admin.delete(f"/api/walk/{sid}/point/{r['id']}")
    assert admin.get(f"/api/walk/{sid}").json()["points"] == []
    admin.post(f"/api/walk/{sid}/stop")
    assert admin.post(f"/api/walk/{sid}/point", json={"x": 0.2, "y": 0.3}).status_code == 409   # closed
    admin.post(f"/api/walk/{sid}/resume")
    assert admin.get("/api/walk").json()["surveys"][0]["name"] == "Ground floor"
    assert client(app, "view").post("/api/walk", json={"sensor": "local"}).status_code == 403
    assert admin.post("/api/walk", json={"sensor": "attic"}).status_code == 404
    admin.delete(f"/api/walk/{sid}")
    assert admin.get(f"/api/walk/{sid}").status_code == 404


def test_the_demo_makes_up_readings_by_place(ctx):
    near = walk.demo_readings(ctx, 0.24, 0.32)   # in the living room, where the demo's 2.4 GHz HomeNet access point is
    far = walk.demo_readings(ctx, 0.78, 0.9)
    assert near["24:a4:3c:10:00:01"] > far.get("24:a4:3c:10:00:01", -200)
