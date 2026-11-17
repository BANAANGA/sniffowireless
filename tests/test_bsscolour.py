"""BSS colour collisions and channel widths (release 35)."""
import json
import struct
import time

from test_hardening import client, ctx  # noqa: F401  (ctx is a fixture)

from sniffowireless import bsscolour, wifiattrs
from sniffowireless.web import create_app


def test_width_from_the_operation_elements():
    w = lambda elts: wifiattrs.ap_attributes(elts).get("width")   # noqa: E731
    assert w([(61, bytes([6, 0x05]) + bytes(20))]) == 40                       # HT: secondary above, any width
    assert w([(61, bytes([6, 0x00]) + bytes(20))]) is None                     # HT: 20 MHz
    assert w([(192, bytes([1, 42, 0, 0, 0]))]) == 80                           # VHT: 80
    assert w([(192, bytes([1, 42, 50, 0, 0]))]) == 160                         # VHT: 80 with the second centre 8 away = 160
    he6 = bytes([36]) + struct.pack("<I", (1 << 17) | (5 << 24))[:3] + bytes([5]) + bytes(2) + bytes([37, 0x03, 39, 47, 0])
    a = wifiattrs.ap_attributes([(255, he6)])
    assert a["width"] == 160 and a["bss_color"] == 5                           # HE with 6 GHz operation information
    eht = bytes([106, 0x01]) + bytes(4) + bytes([0x04, 31, 63])
    assert w([(255, eht)]) == 320                                              # EHT: 320 MHz
    assert w([(61, bytes([6, 0x05]) + bytes(20)), (192, bytes([1, 42, 0, 0, 0]))]) == 80   # the widest wins


def ap(ctx, mac, ssid, ch, band="2.4", rssi=-60, colour=None, width=None):
    info = {k: v for k, v in (("bss_color", colour), ("width", width)) if v}
    ctx.execute("INSERT INTO devices(mac, kind, ssid, channel, band, last_rssi, last_seen, first_seen, extra) VALUES(?, 'ap', ?, ?, ?, ?, ?, 0, ?)",
                (mac, ssid, ch, band, rssi, time.time(), json.dumps({"ap": info})))


def test_collisions_and_widths(ctx):
    ctx.settings.set("networks", {"ssids": ["Home"], "trusted_bssids": []})
    ap(ctx, "24:a4:3c:10:00:01", "Home", 1, colour=12)
    ap(ctx, "26:a4:3c:10:00:02", "Home-IoT", 1, colour=12)      # the same radio, another SSID: no collision
    ap(ctx, "aa:aa:aa:00:00:01", "Neighbour", 1, colour=12)     # another network: a collision
    ap(ctx, "aa:aa:aa:00:00:02", "Far", 6, colour=12, rssi=-90)  # too weak to count
    ap(ctx, "aa:aa:aa:00:00:03", "Wide", 11, width=40)
    ap(ctx, "24:a4:3c:10:00:05", "Home", 36, band="5", width=160)
    for i, ch in enumerate((40, 52)):
        ap(ctx, f"bb:bb:bb:00:00:0{i}", f"N{i}", ch, band="5")
    r = bsscolour.analyze(ctx, time.time() - 3600)
    assert len(r["collisions"]) == 1
    c = r["collisions"][0]
    assert c["mine"] and c["colour"] == 12 and {a["ssid"] for a in c["aps"]} == {"Home", "Home-IoT", "Neighbour"}
    texts = {w["mac"]: w for w in r["warnings"]}
    assert "40 MHz on 2.4 GHz" in texts["aa:aa:aa:00:00:03"]["text"] and texts["aa:aa:aa:00:00:03"]["level"] == "info"
    assert texts["24:a4:3c:10:00:05"]["level"] == "warn" and "2 other networks" in texts["24:a4:3c:10:00:05"]["text"]
    assert r["widths"]["5"] == {"160": 1, "20": 2} and r["wifi6"] == 3


def test_route(ctx):
    ap(ctx, "24:a4:3c:10:00:01", "Home", 1, colour=12)
    d = client(create_app(ctx), "view").get("/api/channels/colours").json()
    assert d["near"] == 1 and d["collisions"] == []
