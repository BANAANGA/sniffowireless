"""The audit report (release 35): what sniffowireless found about my networks, as findings in order of how much they matter."""
import json
import time

from test_hardening import client, ctx  # noqa: F401  (ctx is a fixture)

from sniffowireless import audit
from sniffowireless.web import create_app


def ap(ctx, mac, ssid, ch, enc="WPA2/PSK", rsn=None, **info):
    extra = {"ap": {**({"rsn": rsn} if rsn else {}), **info}}
    ctx.execute("INSERT INTO devices(mac, kind, ssid, channel, band, enc, last_rssi, last_seen, first_seen, extra) VALUES(?, 'ap', ?, ?, ?, ?, -50, ?, 0, ?)",
                (mac, ssid, ch, "2.4" if ch <= 14 else "5", enc, time.time(), json.dumps(extra)))


def test_findings_in_order(ctx):
    ctx.settings.set("networks", {"ssids": ["Home", "Guest", "Lab"], "trusted_bssids": []})
    ap(ctx, "24:a4:3c:10:00:01", "Home", 6, rsn={"akm": ["PSK", "SAE"], "pmf": "optional", "transition": True, "pairwise": ["CCMP"]})
    ap(ctx, "24:a4:3c:10:00:02", "Guest", 1, enc="OPN")
    ap(ctx, "24:a4:3c:10:00:03", "Lab", 11, rsn={"akm": ["PSK"], "pmf": "off", "pairwise": ["TKIP", "CCMP"]}, wps_configured=True)
    ap(ctx, "aa:aa:aa:00:00:01", "Neighbour", 6, enc="OPN")   # not mine: not in the report
    m = int(time.time() // 60) * 60
    ctx.execute("INSERT INTO channel_stats(minute, sensor, freq, dwell_ms, frames, bytes, airtime_us, retries) VALUES(?, 'local', 2437, 10000, 1000, 1, 7000000, 300)", (m,))
    ctx.execute("INSERT INTO findings(key, type, severity, title, detail, first_seen, last_seen, status) VALUES('x', 'wps_enabled', 'medium', 'dup', '', 0, ?, 'open')",
                (time.time(),))
    ctx.execute("INSERT INTO findings(key, type, severity, title, detail, first_seen, last_seen, status) VALUES('y', 'rogue_ap', 'high', 'Rogue AP', 'd', 0, ?, 'open')",
                (time.time(),))
    ctx.execute("INSERT INTO events(ts, mac, type, detail) VALUES(?, 'x', 'rogue_ap', 'd')", (time.time(),))
    r = audit.build(ctx, 7)
    titles = [f["title"] for f in r["findings"]]
    sev = [f["severity"] for f in r["findings"]]
    assert sev == sorted(sev, key=lambda s: audit.ORDER[s])
    assert "“Guest” is open" in titles and "“Lab” still offers TKIP / WPA 1" in titles and "WPS is on for “Lab”" in titles
    assert "“Lab” has no management frame protection" in titles and "“Lab” has no WPA3" in titles
    assert "“Home” runs WPA3 + WPA2 transition mode" in titles
    assert "Channel 6 (2.4 GHz) is busy" in titles and "Many retransmissions on channel 6 (2.4 GHz)" in titles
    assert "Rogue AP" in titles and "dup" not in titles                # own checks are not repeated from the Security page
    assert not any(t.endswith("rogue / evil-twin access point") for t in titles)   # nor the events of an open finding
    assert {a["ssid"] for a in r["aps"]} == {"Home", "Guest", "Lab"} and r["counts"]["high"] >= 3
    assert r["channels"][0]["channel"] == 6


def test_without_networks(ctx):
    r = audit.build(ctx, 7)
    assert r["findings"][0]["title"] == "No networks of yours are set" and r["aps"] == []


def test_route(ctx):
    d = client(create_app(ctx), "view").get("/api/audit?days=14").json()
    assert d["days"] == 14 and "findings" in d and "readiness" in d
