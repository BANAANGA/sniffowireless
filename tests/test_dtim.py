"""Power save (release 34.2): the DTIM period from the TIM element, and what it means for battery and multicast."""
import json
import time

from test_hardening import ctx  # noqa: F401  (ctx is a fixture)

from sniffowireless import audit, beacons, wifiattrs


def test_tim_element():
    assert wifiattrs.ap_attributes([(5, [0, 3, 0, 0])], beacon_tu=100)["dtim"] == 3
    assert "dtim" not in wifiattrs.ap_attributes([(5, [0, 0, 0, 0])])   # a DTIM period of 0 is not valid


def ap(ctx, mac, ssid, dtim, tu=100, ch=6):
    ctx.execute("INSERT INTO devices(mac, kind, ssid, channel, band, last_rssi, last_seen, first_seen, extra) VALUES(?, 'ap', ?, ?, '2.4', -50, ?, 0, ?)",
                (mac, ssid, ch, time.time(), json.dumps({"ap": {"beacon_tu": tu, "dtim": dtim}})))


def test_power_save(ctx):
    ctx.settings.set("networks", {"ssids": ["Home", "IoT", "Fast", "Mixed"], "trusted_bssids": []})
    ap(ctx, "24:a4:3c:10:00:01", "Home", 3)
    ap(ctx, "24:a4:3c:10:00:02", "IoT", 10)
    ap(ctx, "24:a4:3c:10:00:03", "Fast", 1)
    ap(ctx, "24:a4:3c:10:00:04", "Mixed", 2)
    ap(ctx, "24:a4:3c:10:00:05", "Mixed", 2, tu=300, ch=11)
    ap(ctx, "aa:aa:aa:00:00:01", "Neighbour", 50)   # not mine
    p = {x["ssid"]: x for x in beacons.overhead(ctx, time.time() - 3600)["power"]}
    assert set(p) == {"Home", "IoT", "Fast", "Mixed"}
    assert p["Home"]["level"] == "ok" and p["Home"]["ms"] == [307]
    assert p["IoT"]["level"] == "high" and "1.0 s" in p["IoT"]["text"]
    assert p["Fast"]["level"] == "info" and "every beacon" in p["Fast"]["text"]
    assert p["Mixed"]["level"] == "info" and p["Mixed"]["ms"] == [205, 614] and "differ" in p["Mixed"]["text"]
    titles = [f["title"] for f in audit.build(ctx, 7)["findings"]]
    assert any(t.startswith("Power save of “IoT”") for t in titles) and not any("“Home”: multicast" in t for t in titles)
