"""The audit report (release 34.1): what sniffowireless found about my networks, as findings in order of how much they matter."""
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


def test_snapshots_and_what_changed(ctx):
    ctx.settings.set("networks", {"ssids": ["Home", "Guest", "Lab"], "trusted_bssids": []})
    ap(ctx, "24:a4:3c:10:00:01", "Home", 6, rsn={"akm": ["PSK"], "pmf": "off", "pairwise": ["CCMP"]})
    ap(ctx, "24:a4:3c:10:00:02", "Guest", 1, enc="OPN")
    for i in range(3):
        ctx.execute("INSERT INTO interference(start_ts, end_ts, kind, band) VALUES(?, ?, 'microwave', '2.4')", (time.time() - 60 - i, time.time() - i))
    app = create_app(ctx)
    admin = client(app, "admin")
    assert admin.get("/api/audit").json()["changes"] is None
    assert audit.report_lines(ctx, audit.build(ctx, 7))[0][1][0].startswith("Open: ")
    assert client(app, "view").post("/api/audit/snapshot").status_code == 403
    assert admin.post("/api/audit/snapshot").json()["findings"] >= 3
    # the guest network gets a password, Lab appears, and one more microwave (the count in the title changes: the same finding)
    ctx.execute("UPDATE devices SET enc='WPA2/PSK', extra=? WHERE mac='24:a4:3c:10:00:02'", (json.dumps({"ap": {"rsn": {"akm": ["SAE"], "pmf": "required"}}}),))
    ap(ctx, "24:a4:3c:10:00:03", "Lab", 11, enc="OPN")
    ctx.execute("INSERT INTO interference(start_ts, end_ts, kind, band) VALUES(?, ?, 'microwave', '2.4')", (time.time() - 30, time.time()))
    ch = admin.get("/api/audit").json()["changes"]
    assert "“Lab” is open" in [f["title"] for f in ch["new"]] and all("Guest" not in f["title"] and "Home" not in f["title"] for f in ch["new"])
    assert [f["title"] for f in ch["fixed"]] == ["“Guest” is open"]
    assert ch["still"] >= 2 and not any("microwave" in f["title"] for f in ch["new"] + ch["fixed"])
    lines = audit.report_lines(ctx, audit.build(ctx, 7))[0][1]
    assert lines[0].endswith("still open") and "New [high]: “Lab” is open" in lines and "Fixed: “Guest” is open" in lines


def test_the_scheduled_report_carries_it_and_keeps_a_snapshot(ctx, monkeypatch):
    from sniffowireless import reports
    ctx.settings.set("networks", {"ssids": ["Guest"], "trusted_bssids": []})
    ap(ctx, "24:a4:3c:10:00:02", "Guest", 1, enc="OPN")
    ctx.execute("INSERT INTO notifiers(name, type, config) VALUES('mail', 'email', '{}')")
    sent = []
    monkeypatch.setattr(reports, "send", lambda kind, cfg, title, body, html=None: sent.append(body))
    ctx.settings.set("report", {**ctx.settings.get("report"), "notifier_id": ctx.one("SELECT id FROM notifiers")["id"]})
    rs = reports.ReportScheduler(ctx)
    rs.send_now()
    assert "Wi-Fi audit" in sent[0] and "“Guest” is open" in sent[0]
    assert audit.last_snapshot(ctx)["reason"] == "report"
    rs.send_now()
    assert "0 new, 0 fixed, 2 still open" in sent[1]
    ctx.settings.set("report", {**ctx.settings.get("report"), "audit": False})
    rs.send_now()
    assert "Wi-Fi audit" not in sent[2]
