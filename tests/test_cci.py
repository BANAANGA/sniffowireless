"""Co-channel interference between my own access points and a channel plan for all of them (release 34)."""
import time

from test_hardening import client, ctx  # noqa: F401  (ctx is a fixture)

from sniffowireless import cci
from sniffowireless.web import create_app


def ap(ctx, mac, ssid, ch, band="2.4", heard=None):
    now = time.time()
    ctx.execute("INSERT INTO devices(mac, kind, ssid, channel, band, last_seen, first_seen) VALUES(?, 'ap', ?, ?, ?, ?, 0)", (mac, ssid, ch, band, now))
    for sensor, rssi in (heard or {}).items():
        ctx.execute("INSERT INTO sightings(mac, sensor, last_seen, rssi) VALUES(?,?,?,?)", (mac, sensor, now, rssi))


def test_conflict():
    assert cci.conflict("2.4", 6, 6) == 1 and cci.conflict("2.4", 1, 6) == 0 and cci.conflict("2.4", 1, 3) == 0.5
    assert cci.conflict("5", 36, 44) == 0.5 and cci.conflict("5", 36, 149) == 0
    assert cci.conflict("6", 5, 21) == 0 and cci.conflict("6", 5, 9) == 0.5


def setup_site(ctx):
    ctx.settings.set("networks", {"ssids": ["Home", "Home-IoT"], "trusted_bssids": []})
    ap(ctx, "24:a4:3c:10:00:01", "Home", 6, heard={"local": -50, "office": -75})
    ap(ctx, "26:a4:3c:10:00:02", "Home-IoT", 6, heard={"local": -51, "office": -76})   # the same radio, another SSID
    ap(ctx, "24:a4:3c:20:00:01", "Home", 6, heard={"local": -70, "office": -48})       # another radio on the same channel
    ap(ctx, "24:a4:3c:30:00:01", "Home", 11, heard={"office": -90})                    # too weak where it is heard
    ap(ctx, "24:a4:3c:10:00:05", "Home", 36, band="5", heard={"local": -55})
    ap(ctx, "aa:aa:aa:00:00:01", "Neighbour", 6, heard={"local": -60})


def test_overlaps_and_spots(ctx):
    setup_site(ctx)
    r = cci.analyze(ctx)
    two_four = [x for x in r["radios"] if x["band"] == "2.4"]
    assert len(two_four) == 3   # the two SSIDs of one radio count once
    first = next(x for x in two_four if "Home-IoT" in x["ssids"])
    assert sorted(first["bssids"]) == ["24:a4:3c:10:00:01", "26:a4:3c:10:00:02"] and first["heard"]["local"] == -50
    p = r["pairs"]
    assert len(p) == 1 and p[0]["overlap"] == -70 and p[0]["sensor"] == "local" and p[0]["same_channel"] and p[0]["conflict"] == 1
    spot = next(s for s in r["spots"] if s["sensor"] == "local" and s["channel"] == 6)
    assert len(spot["mine"]) == 2 and spot["others"] == 1
    assert not [s for s in r["spots"] if s["channel"] == 11]


def test_the_plan_keeps_overlapping_radios_apart(ctx):
    setup_site(ctx)
    r = cci.analyze(ctx)
    plan = r["plan"]["2.4"]
    assert plan["change"] and plan["after"] < plan["before"]
    a, b = sorted((x for x in plan["radios"] if x["current"] == 6), key=lambda x: x["id"])
    assert a["suggested"] != b["suggested"]   # the two radios heard together no longer share a channel
    assert all(x["suggested"] in (1, 6, 11) for x in plan["radios"])
    assert not r["plan"]["5"]["change"]   # one radio on 5 GHz: nothing to keep apart


def test_a_dfs_channel_may_stay(ctx):
    ctx.settings.set("networks", {"ssids": ["Home"], "trusted_bssids": []})
    ap(ctx, "24:a4:3c:10:00:01", "Home", 100, band="5", heard={"local": -50})
    r = cci.analyze(ctx)
    assert r["plan"]["5"]["radios"][0]["suggested"] == 100


def test_no_networks_of_mine(ctx):
    ap(ctx, "aa:aa:aa:00:00:01", "Neighbour", 6, heard={"local": -60})
    r = cci.analyze(ctx)
    assert r["radios"] == [] and r["plan"] == {}


def test_route(ctx):
    setup_site(ctx)
    d = client(create_app(ctx), "view").get("/api/channels/cci").json()
    assert d["cca"] == -82 and len(d["pairs"]) == 1
