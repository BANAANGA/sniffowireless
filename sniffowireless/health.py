"""Health of the admin's own Wi-Fi networks: clients, band use, roaming, sticky clients, disconnects."""
import re
import time
from collections import Counter, defaultdict

from fastapi import APIRouter, Depends

from .auth import current_user
from .web_util import overlap_counts

STICKY_RSSI = -75      # connected this weakly while a better AP exists -> "sticky"
PINGPONG_GAP = 120     # A -> B -> A within this many seconds counts as ping-pong roaming


def routes(ctx):
    r = APIRouter()

    @r.get("/api/mynet/changes")
    def mynet_changes(days: float = 30, _=Depends(current_user)):
        """A readable, chronological log of what's changed on the admin's own networks: channel moves
        (from the DFS monitor, which already tracks every AP's channel history), and security findings
        (open/weak encryption, WPS, evil twins) raised specifically for one of these SSIDs. Pulls from
        detection that already runs continuously, rather than taking a fresh snapshot — a config dropped
        back to how it was before still shows as two separate changes, which is what actually happened."""
        n = ctx.settings.get("networks")
        if not n["ssids"]:
            return {"configured": False, "items": []}
        since = time.time() - days * 86400
        items = []
        for r_ in ctx.rows("SELECT ts, mac, ssid, from_ch, to_ch, csa, dfs FROM dfs_events "
                           "WHERE mine=1 AND ts >= ? ORDER BY ts DESC LIMIT 300", (since,)):
            how = "radar forced it off" if r_["dfs"] else "it announced the move" if r_["csa"] else "noticed on the new channel"
            items.append({"ts": r_["ts"], "mac": r_["mac"], "ssid": r_["ssid"], "type": "channel",
                         "title": f"Channel {r_['from_ch']} → {r_['to_ch']} on “{r_['ssid'] or r_['mac']}”",
                         "detail": how, "severity": "medium" if r_["dfs"] else "low"})
        # Findings whose ssid is one of mine: config issues (open/WEP/WPS/no-WPA3) on my own APs, and
        # rogue/evil-twin APs impersonating one of my SSIDs (both already keyed by "my" ssid, not the
        # impostor's) — one query covers both.
        q = ",".join("?" * len(n["ssids"]))
        for r_ in ctx.rows(f"SELECT first_seen ts, mac, ssid, type, title, detail, severity, status FROM findings "
                          f"WHERE ssid IN ({q}) AND first_seen >= ? ORDER BY first_seen DESC LIMIT 300",
                          n["ssids"] + [since]):
            items.append({"ts": r_["ts"], "mac": r_["mac"], "ssid": r_["ssid"],
                         "type": "security" if r_["type"] != "rogue_ap" else "rogue_ap",
                         "title": r_["title"], "detail": r_["detail"], "severity": r_["severity"],
                         "status": r_["status"]})
        items.sort(key=lambda x: x["ts"], reverse=True)
        return {"configured": True, "items": items[:300]}

    @r.get("/api/mynet")
    def mynet(days: float = 7, _=Depends(current_user)):
        now = time.time()
        since = now - days * 86400
        n = ctx.settings.get("networks")
        if not n["ssids"]:
            return {"configured": False}
        q = ",".join("?" * len(n["ssids"]))
        aps = ctx.rows(f"SELECT mac, ssid, channel, band, enc, wifi_gen, vendor, last_rssi, last_seen FROM devices "
                       f"WHERE kind='ap' AND ssid IN ({q}) ORDER BY ssid, band, channel", n["ssids"])
        if not aps:
            return {"configured": True, "ssids": n["ssids"], "aps": [], "clients": []}
        trusted = set(n["trusted_bssids"])
        for a in aps:
            a["trusted"] = not trusted or a["mac"] in trusted
        ap_by = {a["mac"]: a for a in aps}
        bq = ",".join("?" * len(aps))
        bssids = list(ap_by)
        sess = ctx.rows(f"SELECT mac, peer, start_ts, end_ts, open, end_reason, rssi_sum, rssi_count, packets "
                        f"FROM sessions WHERE type='assoc' AND peer IN ({bq}) AND end_ts >= ? ORDER BY start_ts",
                        bssids + [since])
        devs = {d["mac"]: ctx.jsonf(d, "ident") for d in ctx.rows(
            f"SELECT d.mac, d.kind, d.vendor, d.name, d.dev_type, d.wifi_gen, d.randomized, d.ident, d.last_rssi, "
            f"d.last_seen, m.label FROM devices d LEFT JOIN device_meta m ON m.mac=d.mac WHERE d.mac IN "
            f"(SELECT DISTINCT mac FROM sessions WHERE type='assoc' AND peer IN ({bq}) AND end_ts >= ?)",
            bssids + [since])}

        # How many of my APs broadcast each SSID — a client connecting to one of several has a choice.
        ssid_siblings = Counter(a["ssid"] for a in aps)
        per = defaultdict(lambda: {"sessions": 0, "secs": 0.0, "rsum": 0, "rcnt": 0, "roams": 0, "pingpong": 0,
                                   "kicked": 0, "timeouts": 0, "bands": Counter(), "aps": set(), "connected": None,
                                   "choice_sessions": 0, "weak_choice_sessions": 0})
        by_client = defaultdict(list)
        band_time, ssid_time = Counter(), Counter()
        for s in sess:
            p = per[s["mac"]]
            dur = min(s["end_ts"], now) - max(s["start_ts"], since)
            ap = ap_by[s["peer"]]
            p["sessions"] += 1
            p["secs"] += max(0, dur)
            p["rsum"] += s["rssi_sum"] or 0
            p["rcnt"] += s["rssi_count"] or 0
            p["bands"][ap["band"]] += max(0, dur)
            p["aps"].add(s["peer"])
            p["roams"] += s["end_reason"] == "roamed"
            p["kicked"] += s["end_reason"] in ("deauth", "disassoc")
            p["timeouts"] += s["end_reason"] == "timeout"
            if s["open"]:
                p["connected"] = s["peer"]
            band_time[ap["band"]] += max(0, dur)
            ssid_time[ap["ssid"]] += max(0, dur)
            by_client[s["mac"]].append(s)
            # "Stuck" on a weak AP: this session had another AP for the same SSID to choose from, and the
            # signal to the one it picked averaged below STICKY_RSSI for the whole session (not just now).
            if ssid_siblings.get(ap["ssid"], 0) > 1:
                p["choice_sessions"] += 1
                avg = s["rssi_sum"] / s["rssi_count"] if s["rssi_count"] else None
                if avg is not None and avg < STICKY_RSSI:
                    p["weak_choice_sessions"] += 1
        for mac, lst in by_client.items():  # ping-pong: A -> B -> A with a short stay on B
            for a, b, c in zip(lst, lst[1:], lst[2:]):
                if a["peer"] == c["peer"] != b["peer"] and b["end_ts"] - b["start_ts"] < PINGPONG_GAP:
                    per[mac]["pingpong"] += 1

        # Current signal over the last 15 minutes, for sticky-client detection.
        recent = {x["mac"]: x for x in ctx.rows(
            "SELECT mac, SUM(rssi_sum)*1.0/NULLIF(SUM(rssi_count),0) rssi FROM samples WHERE minute >= ? GROUP BY mac",
            (now - 900,))}
        clients = []
        for mac, p in per.items():
            d = devs.get(mac) or {"mac": mac}
            cur_ap = ap_by.get(p["connected"]) if p["connected"] else None
            rssi_now = (recent.get(mac) or {}).get("rssi")
            siblings = [a for a in aps if cur_ap and a["ssid"] == cur_ap["ssid"] and a["mac"] != cur_ap["mac"]]
            sticky = bool(cur_ap and rssi_now is not None and rssi_now < STICKY_RSSI and siblings)
            clients.append({
                "mac": mac, "label": d.get("label"), "name": d.get("name"), "vendor": d.get("vendor"),
                "kind": d.get("kind"), "dev_type": d.get("dev_type"), "wifi_gen": d.get("wifi_gen"),
                "ident": (d.get("ident") or {}).get("label"), "randomized": d.get("randomized"),
                "connected_to": p["connected"], "connected_ssid": cur_ap["ssid"] if cur_ap else None,
                "connected_band": cur_ap["band"] if cur_ap else None, "rssi_now": round(rssi_now) if rssi_now else None,
                "avg_rssi": round(p["rsum"] / p["rcnt"]) if p["rcnt"] else None, "secs": round(p["secs"]),
                "sessions": p["sessions"], "aps": len(p["aps"]), "roams": p["roams"], "pingpong": p["pingpong"],
                "kicked": p["kicked"], "timeouts": p["timeouts"], "sticky": sticky,
                "choice_sessions": p["choice_sessions"], "weak_choice_sessions": p["weak_choice_sessions"],
                "band_share": {b: round(v / p["secs"], 3) for b, v in p["bands"].items()} if p["secs"] else {},
                "last_seen": d.get("last_seen"),
            })
        clients.sort(key=lambda c: (c["connected_to"] is None, -c["secs"]))

        for a in aps:
            a["clients_now"] = sum(1 for c in clients if c["connected_to"] == a["mac"])
            a["clients_total"] = len({s["mac"] for s in sess if s["peer"] == a["mac"]})
        reasons = Counter()
        for e in ctx.rows(f"SELECT detail FROM events WHERE type='disconnected' AND peer IN ({bq}) AND ts >= ?",
                          bssids + [since]):
            d = e["detail"] or "unknown"
            m = re.match(r"(deauth|disassoc) reason (\w+)", d)
            reasons[f"{m.group(1)} (reason {m.group(2)})" if m else d] += 1
        bucket = 3600 if days > 1 else 900
        start = int(since // bucket * bucket)
        series = {}
        for ssid in n["ssids"]:
            rows = [(s["mac"], s["start_ts"], s["end_ts"]) for s in sess if ap_by[s["peer"]]["ssid"] == ssid]
            series[ssid] = [c for _, c in overlap_counts(rows, start, now, bucket)]
        total = sum(band_time.values()) or 1
        return {
            "configured": True, "ssids": n["ssids"], "aps": aps, "clients": clients,
            "band_share": {b: round(v / total, 3) for b, v in band_time.items()},
            "ssid_time": dict(ssid_time), "disconnect_reasons": reasons.most_common(12),
            "timeline": {"t": [start + i * bucket for i in range(len(next(iter(series.values()), [])))],
                         "series": series, "bucket": bucket},
            "summary": {"clients": len(clients), "connected_now": sum(1 for c in clients if c["connected_to"]),
                        "roams": sum(c["roams"] for c in clients), "pingpong": sum(c["pingpong"] for c in clients),
                        "sticky": sum(1 for c in clients if c["sticky"]),
                        "kicked": sum(c["kicked"] for c in clients),
                        "weak_choice_sessions": sum(c["weak_choice_sessions"] for c in clients)},
        }

    return r
