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


# ---- release 34.2: the analysis of a survey, and comparing two

def fake_survey(ctx, name, ap_at, width=20, without=False):
    """A 9 x 7 walk over a floor with my access point AP1 at ap_at (log-distance path loss, exponent 3) and the
    neighbour AP2 about as loud everywhere."""
    import json
    import math
    with ctx.wdb() as w:
        sid = w.execute("INSERT INTO walk_sessions(name, sensor, created, width_m) VALUES(?, 'local', ?, ?)", (name, time.time(), width)).lastrowid
        for i in range(9):
            for j in range(7):
                x, y = 0.06 + 0.11 * i, 0.08 + 0.14 * j
                d = max(1, math.hypot((x - ap_at[0]) * width, (y - ap_at[1]) * width * 0.64))
                rd = {AP2: -80} if without else {AP1: round(-38 - 30 * math.log10(d)), AP2: -80}
                w.execute("INSERT INTO walk_points(session, ts, x, y, readings) VALUES(?, ?, ?, ?, ?)", (sid, time.time(), x, y, json.dumps(rd)))
    return sid


def mine_ap(ctx):
    ctx.settings.set("networks", {"ssids": ["Home"], "trusted_bssids": []})
    obs(ctx, AP1, -50)
    obs(ctx, AP2, -80)
    ctx.store.flush()


def test_the_model_is_fitted_to_the_survey(ctx):
    mine_ap(ctx)
    sid = fake_survey(ctx, "x", (0.1, 0.2))
    d = client(create_app(ctx), "view").get(f"/api/walk/{sid}").json()
    a = d["analysis"]
    assert a["suggest"]["model"]["fitted"] and 2.5 <= a["suggest"]["model"]["n"] <= 3.5
    assert a["dead"] and all(p["best"] < -75 for p in a["dead"])
    assert all(p["x"] > 0.4 for p in a["dead"])            # far from the access point in the corner
    assert a["suggest"]["x"] > 0.45                         # the extra one goes to the other side
    assert a["suggest"]["area_after"] > a["area_good"]


def test_a_well_covered_floor_needs_nothing(ctx):
    mine_ap(ctx)
    sid = fake_survey(ctx, "x", (0.5, 0.5), width=6)
    a = client(create_app(ctx), "view").get(f"/api/walk/{sid}").json()["analysis"]
    assert a["dead"] == [] and a["suggest"] is None and a["area_good"] == 100


def test_compare(ctx):
    mine_ap(ctx)
    before = fake_survey(ctx, "before", (0.1, 0.2))
    after = fake_survey(ctx, "after", (0.5, 0.5))
    app = create_app(ctx)
    c = client(app, "view").get(f"/api/walk/{after}/compare/{before}").json()
    assert c["cells"] and c["better"] > 0 and c["worse"] > 0 and c["good_after"] > c["good_before"]
    # nothing of mine heard before: every spot got better
    gone = fake_survey(ctx, "gone", (0, 0), without=True)
    assert client(app, "view").get(f"/api/walk/{after}/compare/{gone}").json()["cells"] == []   # no value to compare with
    admin = client(app, "admin")
    admin.put(f"/api/walk/{after}", json={"name": "Moved", "width_m": 12})
    s = admin.get(f"/api/walk/{after}").json()
    assert s["name"] == "Moved" and s["width_m"] == 12


def test_the_phone_walks_its_own_survey_with_its_sensor_token(ctx):
    """Release 34.2: the Android app shows the floor plan and adds points itself, with the token it sends its readings with."""
    import gzip
    import json

    from fastapi.testclient import TestClient
    mine_ap(ctx)
    app = create_app(ctx)
    admin = client(app, "admin")
    r = admin.post("/api/sensors", json={"name": "Phone"}).json()
    other = admin.post("/api/sensors", json={"name": "Shed"}).json()
    phone = TestClient(app, base_url="http://sniffowireless.test", headers={"authorization": f"Bearer {r['token']}"})
    shed = TestClient(app, base_url="http://sniffowireless.test", headers={"authorization": f"Bearer {other['token']}"})
    assert phone.get("/api/ingest/walk").json()["survey"] is None
    sid = phone.post("/api/ingest/walk", json={"name": "Upstairs", "width_m": 12}).json()["id"]
    body = {"sent_at": time.time(), "obs": [{"t": "wifi_ap", "ts": time.time(), "mac": AP1, "rssi": -58, "ssid": "Home", "channel": 6, "freq": 2437, "band": "2.4"}]}
    assert phone.post("/api/ingest", content=gzip.compress(json.dumps(body).encode()), headers={"content-encoding": "gzip", "content-type": "application/json"}).status_code == 200
    while ctx.store.q.qsize():
        ctx.store.process(ctx.store.q.get_nowait())
    ctx.store.flush()
    st = phone.get("/api/ingest/walk").json()
    assert st["open"] == sid and st["survey"]["name"] == "Upstairs" and st["now"]["aps"] == 1 and st["now"]["best_mine"] == -58
    pid = phone.post(f"/api/ingest/walk/{sid}/point", json={"x": 0.5, "y": 0.5}).json()["id"]
    st = phone.get("/api/ingest/walk").json()
    assert st["survey"]["points"] == [{"id": pid, "x": 0.5, "y": 0.5, "aps": 1, "best": -58}] and st["survey"]["width_m"] == 12
    # another sensor's token sees nothing of it and can't add to it; users can't use these endpoints
    assert shed.get(f"/api/ingest/walk?survey={sid}").status_code == 404
    assert shed.post(f"/api/ingest/walk/{sid}/point", json={"x": 0.1, "y": 0.1}).status_code == 404
    assert admin.get("/api/ingest/walk").status_code == 401
    assert phone.get("/api/walk").status_code == 403          # nor can the sensor token use the admin side
    assert phone.get("/api/ingest/walk/floorplan").status_code == 404   # none uploaded
    phone.delete(f"/api/ingest/walk/{sid}/point/{pid}")
    phone.post(f"/api/ingest/walk/{sid}/stop")
    st = phone.get(f"/api/ingest/walk?survey={sid}").json()
    assert st["open"] is None and st["survey"]["points"] == [] and not st["survey"]["open"]
    phone.post(f"/api/ingest/walk/{sid}/resume")
    assert phone.get("/api/ingest/walk").json()["open"] == sid
    assert admin.get(f"/api/walk/{sid}").json()["name"] == "Upstairs"   # the same surveys as on the web page
