"""Client readiness (release 35): what the clients of my networks can do, and who a change would leave behind."""
import json
import time

from test_hardening import client, ctx  # noqa: F401  (ctx is a fixture)

from sniffowireless import readiness, wifiattrs
from sniffowireless.web import create_app

AP, AP24 = "24:a4:3c:10:00:01", "24:a4:3c:10:00:02"


def test_client_caps_reads_the_association_request():
    rsn = bytes.fromhex("0100" "000fac04" "0100" "000fac04" "0100" "000fac08" "8000")   # SAE, PMF capable
    c = wifiattrs.client_caps([(1, bytes([0x82, 0x84, 0x8B, 0x96])), (48, rsn), (59, bytes([81, 115, 131]))])
    assert c["akm"] == ["SAE"] and c["pmf"] == "optional" and c["b_only"] and c["opcls"] == [81, 115, 131]
    assert "b_only" not in wifiattrs.client_caps([(1, bytes([0x82, 0x0C, 0x12]))])


def dev(ctx, mac, gen, capinfo, band="5", name=None):
    ident = {"wifi_caps": {"gen": gen if gen != 66 else 6, "ss": 2, "width": 80, "capinfo": capinfo}}
    ctx.execute("INSERT INTO devices(mac, kind, wifi_gen, ident, band, name, last_seen, first_seen) VALUES(?, 'wifi_client', ?, ?, ?, ?, ?, 0)",
                (mac, gen, json.dumps(ident), band, name, time.time()))
    ctx.execute("INSERT INTO sessions(mac, type, peer, start_ts, end_ts) VALUES(?, 'assoc', ?, ?, ?)",
                (mac, AP if band == "5" else AP24, time.time() - 600, time.time()))


def setup(ctx, ap_akm=("PSK", "SAE")):
    ctx.settings.set("networks", {"ssids": ["Home"], "trusted_bssids": []})
    ctx.execute("INSERT INTO devices(mac, kind, ssid, band, last_seen, first_seen, extra) VALUES(?, 'ap', 'Home', '5', ?, 0, ?)",
                (AP, time.time(), json.dumps({"ap": {"rsn": {"akm": list(ap_akm)}}})))
    ctx.execute("INSERT INTO devices(mac, kind, ssid, band, last_seen, first_seen, extra) VALUES(?, 'ap', 'Home', '2.4', ?, 0, ?)",
                (AP24, time.time(), json.dumps({"ap": {"rsn": {"akm": list(ap_akm)}}})))
    dev(ctx, "aa:00:00:00:00:01", 66, {"akm": ["SAE"], "pmf": "optional", "opcls": [81, 115, 131], "caps": ["802.11r fast roaming"]}, name="Phone")
    dev(ctx, "aa:00:00:00:00:02", 5, {"akm": ["PSK"], "pmf": "optional", "opcls": [81, 115]}, name="Speaker")
    dev(ctx, "aa:00:00:00:00:03", 4, {"akm": ["PSK"], "pmf": "off", "opcls": [81, 83], "dsss": True}, band="2.4", name="Plug")
    dev(ctx, "aa:00:00:00:00:04", 3, {"b_only": True, "dsss": True}, band="2.4", name="Old scale")
    dev(ctx, "aa:00:00:00:00:05", 4, {}, band="2.4", name="Unknown")


def test_who_each_change_leaves_behind(ctx):
    setup(ctx)
    r = readiness.analyze(ctx, time.time() - 86400)
    q = {x["key"]: x for x in r["questions"]}
    assert r["scope"] == "mine" and r["offered_sae"] and len(r["clients"]) == 5
    assert (q["wpa3"]["ready"], q["wpa3"]["drop"], q["wpa3"]["unknown"]) == (1, 2, 2)
    assert {c["name"] for c in q["wpa3"]["drop_clients"]} == {"Speaker", "Plug"}
    assert q["no24"]["drop"] == 1 and q["no24"]["drop_clients"][0]["name"] == "Plug" and q["no24"]["unknown"] == 2
    assert q["six"]["ready"] == 1
    assert q["pmf"]["drop"] == 1 and q["nob"]["drop"] == 1 and q["nob"]["drop_clients"][0]["name"] == "Old scale"
    assert r["summary"]["roaming"]["802.11r"] == 1 and r["summary"]["generations"]["Wi-Fi 6E"] == 1


def test_wpa3_unknown_where_it_was_not_offered(ctx):
    setup(ctx, ap_akm=("PSK",))
    q = {x["key"]: x for x in readiness.analyze(ctx, time.time() - 86400)["questions"]}
    assert q["wpa3"]["drop"] == 0 and q["wpa3"]["ready"] == 1   # choosing WPA2 says nothing when WPA3 wasn't on offer


def test_sae_seen_in_the_connection_steps(ctx):
    setup(ctx, ap_akm=("PSK",))
    ctx.execute("INSERT INTO join_events(ts, mac, bssid, step, algo) VALUES(?, 'aa:00:00:00:00:02', ?, 'auth', 3)", (time.time(), AP))
    c = {x["mac"]: x for x in readiness.analyze(ctx, time.time() - 86400)["clients"]}
    assert c["aa:00:00:00:00:02"]["wpa3"] is True


def test_route(ctx):
    setup(ctx)
    d = client(create_app(ctx), "view").get("/api/readiness?days=1").json()
    assert len(d["clients"]) == 5 and d["questions"][0]["key"] == "wpa3"
