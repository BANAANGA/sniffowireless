"""The audit report: one page per site that puts together what sniffowireless found about my networks, with findings in order of
how much they matter and what to do about them. It is what a Wi-Fi consultant hands over; the page (#/audit) prints to PDF.

Everything comes from the other analyses: the access points' security settings (their beacons), the channel survey, beacon
overhead, co-channel interference and the channel plan, BSS colours and widths, who uses the airtime, link quality, connection
failures and roams, client readiness, interference, radar, and the open security findings.
"""
import json
import time

from fastapi import APIRouter, Depends

from .auth import current_user

ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
OWN_CHECKS = {"open_network", "weak_security", "wps_enabled", "no_wpa3"}   # security findings this report works out itself
NOT_WIFI = {"unknown_tracker"}   # Bluetooth trackers (they name people): not part of a Wi-Fi audit


def _safe(fn, default):
    try:
        return fn()
    except Exception:
        return default


def build(ctx, days=7):
    now = time.time()
    since = now - days * 86400
    n = ctx.settings.get("networks")
    my_ssids, trusted = list(n["ssids"]), set(n["trusted_bssids"])
    findings = []

    def find(area, severity, title, detail, advice=None):
        findings.append({"area": area, "severity": severity, "title": title, "detail": detail, "advice": advice})

    # ---- my access points and their security, from their beacons
    aps = []
    if my_ssids:
        for r in ctx.rows(f"SELECT mac, ssid, channel, band, enc, last_rssi, last_seen, extra, wifi_gen FROM devices WHERE kind='ap' "
                          f"AND ssid IN ({','.join('?' * len(my_ssids))}) AND last_seen >= ? ORDER BY ssid, band, channel", [*my_ssids, since]):
            if trusted and r["mac"] not in trusted:
                continue
            try:
                extra = json.loads(r["extra"] or "{}")
            except ValueError:
                extra = {}
            info = extra.get("ap") or {}
            wps_element = (((extra.get("fp") or {}).get("wifi") or {}).get("wps"))   # a WPS element in its beacons (as security.py reads it)
            rsn = info.get("rsn") or {}
            aps.append({"mac": r["mac"], "ssid": r["ssid"], "band": r["band"], "channel": r["channel"], "enc": r["enc"], "rssi": r["last_rssi"],
                        "akm": rsn.get("akm") or [], "pmf": rsn.get("pmf"), "transition": bool(rsn.get("transition")),
                        "ciphers": rsn.get("pairwise") or [], "wpa1": bool(info.get("wpa1")), "wps": bool(info.get("wps_configured") or wps_element),
                        "wps_locked": info.get("wps_locked"), "roaming": info.get("roaming") or [], "width": info.get("width"),
                        "colour": info.get("bss_color"), "basic_rate": info.get("basic_rate"), "beacon_tu": info.get("beacon_tu"),
                        "model": info.get("ap_name"), "gen": r["wifi_gen"]})
    if not my_ssids:
        find("Setup", "info", "No networks of yours are set", "The report covers your own networks: add them under Settings → My networks.")
    by_ssid = {}
    for a in aps:
        by_ssid.setdefault(a["ssid"], []).append(a)
    for ssid, group in by_ssid.items():
        enc = " ".join(a["enc"] or "" for a in group).upper()
        akms = {k for a in group for k in a["akm"]}
        if "OPN" in enc or (not akms and "WEP" not in enc and "WPA" not in enc):
            find("Security", "high", f"“{ssid}” is open", "Anyone nearby can join it and read what is not encrypted otherwise.",
                 "Use WPA2/WPA3 with a password, or OWE (Enhanced Open) for a guest network.")
        if "WEP" in enc:
            find("Security", "high", f"“{ssid}” uses WEP", "WEP is broken: its key can be recovered in minutes.", "Switch to WPA2 or WPA3.")
        if any("TKIP" in a["ciphers"] or a["wpa1"] for a in group):
            find("Security", "high", f"“{ssid}” still offers TKIP / WPA 1", "TKIP and WPA 1 have known weaknesses and limit the speed to 54 Mb/s.",
                 "Offer AES (CCMP) only.")
        if any(a["wps"] and not a["wps_locked"] for a in group):
            find("Security", "medium", f"WPS is on for “{ssid}”", "Its PIN can be guessed on many access points.", "Turn WPS off.")
        if akms and not akms & {"SAE", "FT-SAE", "SAE-EXT", "FT-SAE-EXT"}:
            find("Security", "low", f"“{ssid}” has no WPA3", "WPA2 passwords can be guessed offline from one captured handshake.",
                 "Turn on WPA3 + WPA2 transition mode; Client readiness then shows which clients choose WPA3.")
        elif any(a["transition"] for a in group):
            find("Security", "info", f"“{ssid}” runs WPA3 + WPA2 transition mode", "Clients that connect with WPA2 get no WPA3 protection.",
                 "Switch to WPA3 only once Client readiness shows no client would drop off.")
        if any(a["pmf"] == "off" for a in group):
            find("Security", "medium", f"“{ssid}” has no management frame protection",
                 "Anyone nearby can disconnect its clients with forged deauthentication frames.", "Set PMF to optional (or required with WPA3).")

    # ---- open security findings and attacks in the period
    sec = _safe(lambda: ctx.rows("SELECT type, severity, title, detail, last_seen FROM findings WHERE status='open' AND last_seen >= ? "
                                 "ORDER BY last_seen DESC LIMIT 50", (since,)), [])
    for f in sec:
        if f["type"] in OWN_CHECKS or f["type"] in NOT_WIFI:   # worked out above from the beacons / not about Wi-Fi
            continue
        sev = f["severity"] if f["severity"] in ORDER else "medium"
        find("Security", sev, f["title"] or f["type"], f["detail"] or "", "See the Security page.")
    found = {f["type"] for f in sec}
    attacks = {r["type"]: r["n"] for r in ctx.rows("SELECT type, COUNT(*) n FROM events WHERE ts >= ? AND type IN ('rogue_ap', 'deauth_flood', "
                                                   "'karma_ap', 'handshake_attack', 'ap_downgrade') GROUP BY type", (since,))}
    names = {"rogue_ap": "rogue / evil-twin access point", "deauth_flood": "deauthentication flood", "karma_ap": "KARMA access point",
             "handshake_attack": "possible handshake-capture attack", "ap_downgrade": "security of my access point got weaker"}
    for t, cnt in attacks.items():
        if t in found:   # already an open finding of its own
            continue
        find("Security", "high", f"{cnt}× {names[t]}", f"Seen in the last {days:g} days.", "See the Security page and the event log.")

    # ---- the radio side
    from . import beacons, bsscolour, cci, joins, linkstats, readiness, survey
    util = _safe(lambda: survey.utilization(ctx, since), [])
    my_ch = {(a["band"], a["channel"]) for a in aps}
    for c in util:
        if (c["band"], c["channel"]) in my_ch:
            if (c["utilization"] or 0) >= 0.5:
                find("Channels", "medium", f"Channel {c['channel']} ({c['band']} GHz) is busy", f"On the air {c['utilization'] * 100:.0f}% of the time.",
                     "See the channel plan below; on 5 GHz a free channel is often near.")
            if (c["retry_rate"] or 0) >= 0.2 and (c["frames"] or 0) >= 500:
                find("Channels", "medium", f"Many retransmissions on channel {c['channel']} ({c['band']} GHz)",
                     f"{c['retry_rate'] * 100:.0f}% of the frames were sent again.", "See Interference and Who uses the airtime.")
    bo = _safe(lambda: beacons.overhead(ctx, now - 3600), {"channels": [], "advice": []})
    for c in bo["channels"]:
        if (c["band"], c["channel"]) in my_ch and c["level"] != "ok":
            find("Channels", "medium" if c["level"] == "bad" else "low", f"Beacons take {c['airtime'] * 100:.0f}% of channel {c['channel']}",
                 f"{c['aps']} BSSIDs, {c['ssids']} SSIDs on about {c['radios']} radios.", "Fewer SSIDs, and 12 Mb/s as the lowest basic rate on 2.4 GHz.")
    for a in bo["advice"]:
        if a.get("mac"):
            find("Channels", "low", "Beacon settings", a["text"])
    plan = _safe(lambda: cci.analyze(ctx, since, now), {"pairs": [], "plan": {}, "radios": []})
    shared = [p for p in plan["pairs"] if p["same_channel"]]
    if shared:
        find("Channels", "medium", f"{len(shared)} pair{'s' if len(shared) > 1 else ''} of your radios share a channel where both are heard",
             "They take turns on the air there.", "See the channel plan below.")
    changes = [(b, x) for b, p in plan["plan"].items() if p["change"] for x in p["radios"] if x["suggested"] != x["current"]]
    col = _safe(lambda: bsscolour.analyze(ctx, now - 3600), {"collisions": [], "warnings": []})
    for c in col["collisions"]:
        if c["mine"]:
            find("Channels", "medium", f"BSS colour {c['colour']} is used twice on channel {c['channel']}",
                 ", ".join(a["ssid"] or a["mac"] for a in c["aps"]), "Give your access point another colour.")
    for w in col["warnings"]:
        if w["level"] == "warn":
            find("Channels", "low", f"Channel width of “{w['ssid']}” on channel {w['channel']}", w["text"])
    air = _safe(lambda: linkstats.airtime(ctx, since), {"slow": []})
    for d in air["slow"][:5]:
        if (d["band"], d["channel"]) in my_ch:
            find("Clients", "medium", f"{d['name'] or d['mac']} takes {d['share'] * 100:.0f}% of channel {d['channel']}",
                 f"At a median {d['median_rate']} Mb/s.", "A weak signal or an old radio: move it, or give it an access point of its own.")
    link = _safe(lambda: linkstats.clients(ctx, since), [])
    my_bssids = {a["mac"] for a in aps}
    link = [x for x in link if x["bssid"] in my_bssids] if my_bssids else []
    bad_links = [x for x in link if x["verdict"]["level"] == "bad"]
    if bad_links:
        find("Clients", "medium", f"{len(bad_links)} client{'s' if len(bad_links) > 1 else ''} with a poor link",
             ", ".join(f"{x['name'] or x['mac']} ({x['verdict']['short']})" for x in bad_links[:6]), "See Link quality on their device pages.")
    from . import hiddennode
    hidden = [c for c in _safe(lambda: hiddennode.analyze(ctx, since), {"clients": []})["clients"] if c["bssid"] in my_bssids]
    for c in hidden[:5]:
        find("Clients", "medium" if c["level"] == "likely" else "low", f"{c['name'] or c['mac']} may be a hidden node on channel {c['channel']}",
             f"{c['retry_up'] * 100:.0f}% of what it sends is sent again at a good rate, while what it receives gets through"
             + (f"; it is {c['far'][0]['why']} from {c['far'][0]['name'] or c['far'][0]['mac']}" if c["far"] else "") + ".",
             "Set an RTS threshold (e.g. 500 bytes) on the access point, move it more central, or add one for the far clients.")
    js = _safe(lambda: joins.site(ctx, since, my_bssids or None), {"counts": {}, "causes": [], "roam_stats": {}})
    for c in js["causes"][:5]:
        find("Clients", "medium" if c["count"] >= 3 else "low", f"{c['count']}× connection failed: {c['cause']}",
             f"{c['clients']} client{'s' if c['clients'] > 1 else ''}; {c['example']}")
    rs = js.get("roam_stats") or {}
    if rs.get("slow"):
        find("Clients", "medium", f"{rs['slow']} of {rs['timed']} roams took longer than 150 ms", "Calls can drop out during them.",
             "Turn on 802.11r (fast transition) where the clients support it.")
    ready = _safe(lambda: readiness.analyze(ctx, since), {"questions": [], "summary": {}, "clients": []})
    eps = _safe(lambda: ctx.rows("SELECT kind, band, COUNT(*) n FROM interference WHERE end_ts >= ? GROUP BY kind, band", (since,)), [])
    for e in eps:
        find("Interference", "low", f"{e['n']}× {e['kind']} ({e['band']} GHz)", "Non-Wi-Fi energy on the channel.", "See Interference on the Channels page.")
    radar = _safe(lambda: ctx.one("SELECT COUNT(*) n FROM dfs_events WHERE ts >= ? AND dfs=1 AND mine=1", (since,))["n"], 0)
    if radar:
        find("Interference", "info", f"Your access points left a DFS channel {radar}× for radar", "Each time clients lose the network for a moment.",
             "Prefer a non-DFS channel where radar is common.")
    findings.sort(key=lambda f: ORDER[f["severity"]])
    sensors = [{"id": r["id"], "name": r["name"] or r["id"], "room": r["room"]} for r in ctx.rows("SELECT id, name, room FROM sensors ORDER BY name")]
    from .appearance import current as appearance
    site = _safe(lambda: appearance(ctx)["name"], "sniffowireless")
    return {"generated": now, "days": days, "site": site, "networks": my_ssids, "sensors": sensors,
            "counts": {s: sum(1 for f in findings if f["severity"] == s) for s in ORDER}, "findings": findings,
            "aps": aps, "channels": [c for c in util if (c["band"], c["channel"]) in my_ch],
            "plan": [{"band": b, **x, "label": next((r["label"] for r in plan["radios"] if r["id"] == x["id"]), "")} for b, x in changes],
            "link": {"total": len(link), "by": {k: sum(1 for x in link if x["verdict"]["level"] == k) for k in ("ok", "warn", "bad", "none")},
                     "worst": link[:10]},
            "joins": {"counts": js.get("counts"), "causes": js.get("causes", [])[:8], "roams": rs},
            "readiness": {"questions": ready["questions"], "summary": ready["summary"], "clients": len(ready["clients"])},
            "interference": eps, "radar": radar}


def routes(ctx):
    r = APIRouter()

    @r.get("/api/audit")
    def audit(days: float = 7, _=Depends(current_user)):
        """Everything about my networks in one report, with findings in order of how much they matter."""
        return build(ctx, days)

    return r
