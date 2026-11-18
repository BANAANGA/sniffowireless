"""Hidden nodes (release 34.2): clients that send at good rates and still lose many frames, while what they receive gets through,
and other clients far from them send on the same channel."""
import json
import time

from test_hardening import client, ctx  # noqa: F401  (ctx is a fixture)

from sniffowireless import hiddennode
from sniffowireless.web import create_app

AP, AP_B = "24:a4:3c:10:00:01", "24:a4:3c:10:00:02"
A, B, C = "02:00:00:00:00:0a", "02:00:00:00:00:0b", "02:00:00:00:00:0c"


def dev(ctx, mac, kind="client", **kw):
    cols = {"mac": mac, "kind": kind, "last_seen": time.time(), "first_seen": 0, **kw}
    ctx.execute(f"INSERT INTO devices({','.join(cols)}) VALUES({','.join('?' * len(cols))})", list(cols.values()))


def link(ctx, mac, way, frames, retries, mcs=7, rssi=-55, bssid=AP):
    hour = int(time.time() // 3600) * 3600
    ctx.execute("INSERT INTO link_stats(hour, mac, dir, bssid, frames, retries, rssi_sum, rssi_n, rates, mcs) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (hour, mac, way, bssid, frames, retries, rssi * 10 if way == "up" else 0, 10 if way == "up" else 0, json.dumps({"65": frames}),
                 json.dumps({f"HT MCS {mcs} 1SS 20": frames})))


def setup(ctx):
    dev(ctx, AP, "ap", ssid="Home", band="2.4", channel=6)
    dev(ctx, AP_B, "ap", ssid="Home", band="2.4", channel=6)
    dev(ctx, A, pos_x=0.1, pos_y=0.5)
    dev(ctx, B, pos_x=0.9, pos_y=0.5)
    dev(ctx, C, pos_x=0.15, pos_y=0.5)
    link(ctx, A, "up", 1000, 300)        # loses 30% of what it sends at MCS 7
    link(ctx, A, "down", 3000, 90)       # but gets what the access point sends
    link(ctx, B, "up", 800, 40)
    link(ctx, C, "up", 600, 30, bssid=AP_B)


def test_a_hidden_node(ctx):
    setup(ctx)
    r = hiddennode.analyze(ctx, time.time() - 86400)["clients"]
    assert [c["mac"] for c in r] == [A]
    assert r[0]["level"] == "likely" and [f["mac"] for f in r[0]["far"]] == [B] and r[0]["far"][0]["same_ap"]


def test_not_when_the_signal_is_weak_or_both_ways_lose(ctx):
    setup(ctx)
    ctx.execute("UPDATE link_stats SET retries=900 WHERE mac=? AND dir='down'", (A,))   # both ways: interference, not a hidden node
    assert hiddennode.analyze(ctx, time.time() - 86400)["clients"] == []
    ctx.execute("UPDATE link_stats SET retries=90, mcs=?, rssi_sum=-800 WHERE mac=?", (json.dumps({"HT MCS 1 1SS 20": 1000}), A))
    assert hiddennode.analyze(ctx, time.time() - 86400)["clients"] == []   # far away: the link adapts, that is distance


def test_by_sensors_and_alone(ctx):
    setup(ctx)
    ctx.execute("UPDATE devices SET pos_x=NULL, pos_y=NULL")
    assert hiddennode.analyze(ctx, time.time() - 86400)["clients"][0]["level"] == "possible"   # 30% but nothing says the others are far
    for mac, sensor in ((A, "living"), (B, "office"), (C, "living")):
        ctx.execute("INSERT INTO sightings(mac, sensor, last_seen, rssi) VALUES(?, ?, ?, -60)", (mac, sensor, time.time()))
    c = hiddennode.analyze(ctx, time.time() - 86400)["clients"][0]
    assert c["level"] == "likely" and c["far"][0]["why"] == "heard well by other sensors only"
    ctx.execute("DELETE FROM link_stats WHERE mac != ?", (A,))   # nobody else sends: nothing to collide with
    assert hiddennode.analyze(ctx, time.time() - 86400)["clients"] == []


def test_route_and_audit(ctx):
    setup(ctx)
    ctx.settings.set("networks", {"ssids": ["Home"], "trusted_bssids": []})
    app = create_app(ctx)
    assert client(app, "view").get("/api/channels/hidden-nodes").json()["clients"][0]["mac"] == A
    from sniffowireless import audit
    assert any("hidden node" in f["title"] for f in audit.build(ctx, 7)["findings"])
