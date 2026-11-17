"""Beacon overhead per channel (release 34): the airtime beacons alone take, from each access point's beacon interval, lowest basic
rate and beacon size."""
import json
import time

import pytest
from test_hardening import client, ctx  # noqa: F401  (ctx is a fixture)

from sniffowireless import beacons, wifiattrs
from sniffowireless.web import create_app


def test_frame_time():
    assert beacons.frame_us(300, 1.0, "2.4") == 192 + 2400                 # DSSS, long preamble
    assert beacons.frame_us(300, 6.0, "5") == 20 + 4 * 101                  # OFDM: 2422 bits in 24-bit symbols
    assert beacons.frame_us(300, 6.0, "2.4") == 20 + 4 * 101 + 6            # plus the 2.4 GHz signal extension
    assert beacons.airtime(300, 1.0, 100, "2.4") == pytest.approx(2592 / 102400)   # about 2.5 % for one SSID at 1 Mb/s


def test_the_beacon_says_its_rate_and_size():
    rates = bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24])        # 1, 2, 5.5, 11 basic; 6..18 not
    a = wifiattrs.ap_attributes([(0, b"HomeNet"), (1, rates), (50, bytes([0x30, 0x48])), (3, b"\x06")], 100)
    assert a["basic_rate"] == 1.0 and a["beacon_len"] == 40 + 9 + 10 + 4 + 3
    ofdm = wifiattrs.ap_attributes([(1, bytes([0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C, 0xFF]))])   # 0xFF: HT PHY membership
    assert ofdm["basic_rate"] == 6.0
    assert "basic_rate" not in wifiattrs.ap_attributes([(0, b"x")])


def add_ap(ctx, mac, ssid, ch, band="2.4", rssi=-60, rate=1.0, tu=100, size=300, seen=None):
    info = {"beacon_tu": tu} | ({"basic_rate": rate, "beacon_len": size} if rate else {})
    ctx.execute("INSERT INTO devices(mac, kind, ssid, channel, band, last_rssi, last_seen, first_seen, extra) VALUES(?,?,?,?,?,?,?,?,?)",
                (mac, "ap", ssid, ch, band, rssi, seen or time.time(), 0, json.dumps({"ap": info})))


def test_overhead_per_channel(ctx):
    for i, ssid in enumerate(["Home", "Home-IoT", "Home-Guest", "Home-Cams"]):   # one radio, four SSIDs at 1 Mb/s
        add_ap(ctx, f"24:a4:3c:10:00:0{i}", ssid, 1)
    add_ap(ctx, "a0:40:a0:30:00:04", "Neighbour", 1, rate=12.0)
    add_ap(ctx, "a0:40:a0:30:00:05", "Far away", 1, rssi=-88)               # below the CCA level: not counted
    add_ap(ctx, "a0:40:a0:30:00:06", "Gone", 1, seen=time.time() - 7200)     # not heard in the last hour
    add_ap(ctx, "a0:40:a0:30:00:07", "Fast", 36, band="5", rate=None)        # an older sensor: assumed values
    ctx.settings.set("networks", {"ssids": ["Home", "Home-IoT", "Home-Guest", "Home-Cams"], "trusted_bssids": []})
    r = beacons.overhead(ctx, time.time() - 3600)
    ch1 = next(c for c in r["channels"] if c["channel"] == 1)
    assert ch1["aps"] == 5 and ch1["weak"] == 1 and ch1["ssids"] == 5 and ch1["radios"] == 2
    assert ch1["airtime"] == pytest.approx(4 * 2592 / 102400 + beacons.frame_us(300, 12, "2.4") / 102400, abs=1e-4)
    assert ch1["level"] == "high" and ch1["mine"] == pytest.approx(4 * 2592 / 102400, abs=1e-4)
    assert ch1["beacons_per_s"] == pytest.approx(5 / 0.1024, abs=0.1)
    fast = next(a for a in r["aps"] if a["mac"].endswith("07"))
    assert not fast["known"] and fast["rate"] == 6.0 and fast["length"] == 300
    texts = " ".join(a["text"] for a in r["advice"])
    assert "With 12 Mb/s as its lowest basic rate" in texts and "seems to offer 4 SSIDs" in texts
    assert "Neighbour" not in texts   # advice is for my own networks


def test_a_crowded_channel_is_a_problem(ctx):
    for i in range(10):
        add_ap(ctx, f"0{i}:11:22:33:44:5{i}", f"Net{i}", 6)
    r = beacons.overhead(ctx, time.time() - 3600)
    ch = r["channels"][0]
    assert ch["level"] == "bad" and ch["airtime"] > 0.2
    assert r["advice"][0]["level"] == "bad" and "Beacons alone take 25 % of channel 6" in r["advice"][0]["text"]


def test_route(ctx):
    add_ap(ctx, "24:a4:3c:10:00:01", "Home", 1)
    app = create_app(ctx)
    d = client(app, "view").get("/api/channels/beacons?hours=1").json()
    assert d["channels"][0]["channel"] == 1 and d["cca"] == -82
