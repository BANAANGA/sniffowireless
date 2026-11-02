"""Wireless security monitoring (defensive): rogue / evil-twin APs, deauthentication floods,
KARMA-style APs, and configuration issues on the admin's own networks (open, WEP/TKIP, WPS)."""
import time
from collections import defaultdict, deque
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .auth import current_user, require_admin

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE NOT NULL, type TEXT NOT NULL, severity TEXT,
  mac TEXT, ssid TEXT, title TEXT, detail TEXT, first_seen REAL, last_seen REAL, count INTEGER DEFAULT 1,
  status TEXT DEFAULT 'open');
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status, last_seen);
"""
SECURITY_EVENTS = ("rogue_ap", "deauth_flood", "karma_ap", "deauth_broadcast", "security_finding")


class SecurityMonitor:
    """Store plugin: observe() runs on the store's writer thread for every observation."""

    def __init__(self, ctx):
        self.ctx = ctx
        ctx.store.conn.executescript(SCHEMA)
        self.deauths = defaultdict(deque)   # bssid -> timestamps of deauth/disassoc frames
        self.ap_ssids = defaultdict(dict)   # bssid -> {ssid: last seen} (KARMA detection)
        self.pending = {}                   # finding key -> finding dict to upsert
        self.status = {r["key"]: r["status"] for r in ctx.rows("SELECT key, status FROM findings")}
        self.reload()
        ctx.settings.on_change(lambda k: self.reload() if k in ("networks", "security") else None)

    def reload(self):
        n = self.ctx.settings.get("networks")
        self.my_ssids = set(n["ssids"])
        self.trusted = set(n["trusted_bssids"])
        self.cfg = self.ctx.settings.get("security")
        self.trusted_info = {}
        if self.trusted:
            q = ",".join("?" * len(self.trusted))
            for r in self.ctx.rows(f"SELECT mac, enc, vendor FROM devices WHERE mac IN ({q})", list(self.trusted)):
                self.trusted_info[r["mac"]] = r

    # ---------------------------------------------------------------- findings
    def finding(self, store, ts, key, type_, severity, mac, ssid, title, detail, event=None):
        f = self.pending.get(key)
        if f:
            f["last_seen"], f["count"] = ts, f["count"] + 1
            return
        self.pending[key] = {"key": key, "type": type_, "severity": severity, "mac": mac, "ssid": ssid,
                             "title": title, "detail": detail, "first_seen": ts, "last_seen": ts, "count": 1}
        prev = self.status.get(key)
        if prev in (None, "resolved"):  # new, or came back after being resolved
            self.status[key] = "open"
            store._event(ts, mac, event or "security_finding", None, title, always=True)

    def flush(self, store, c):
        for f in self.pending.values():
            c.execute("INSERT INTO findings(key, type, severity, mac, ssid, title, detail, first_seen, last_seen, count) "
                      "VALUES(:key,:type,:severity,:mac,:ssid,:title,:detail,:first_seen,:last_seen,:count) "
                      "ON CONFLICT(key) DO UPDATE SET last_seen=excluded.last_seen, count=count+excluded.count, "
                      "detail=excluded.detail, severity=excluded.severity, "
                      "status=CASE WHEN status='resolved' THEN 'open' ELSE status END", f)
        self.pending.clear()

    # ------------------------------------------------------------- detection
    def observe(self, store, o, dev):
        t = o["t"]
        if t == "wifi_ap":
            self._ap(store, o, dev)
        elif t == "wifi_client" and o.get("frame") in ("deauth", "disassoc") and o.get("bssid"):
            self._deauth(store, o["bssid"], o["ts"], o.get("mac"))
        elif t == "event" and o.get("type") == "deauth_broadcast":
            self._deauth(store, o["mac"], o["ts"], None, weight=1)

    def _deauth(self, store, bssid, ts, target, weight=1):
        q = self.deauths[bssid]
        q.append(ts)
        win = self.cfg["deauth_window"]
        while q and ts - q[0] > win:
            q.popleft()
        if len(q) >= self.cfg["deauth_threshold"]:
            ap = store.devices.get(bssid) or {}
            mine = ap.get("ssid") in self.my_ssids
            detail = f"{len(q)} deauth/disassoc frames in {win}s for {ap.get('ssid') or bssid}" + \
                     (" (one of my networks)" if mine else "")
            store._event(ts, bssid, "deauth_flood", None, detail, always=True)
            self.finding(store, ts, f"deauth_flood:{bssid}", "deauth_flood", "high" if mine else "medium", bssid,
                         ap.get("ssid"), "Deauthentication flood", detail, event="deauth_flood")
            q.clear()
        if len(self.deauths) > 10_000:
            self.deauths.clear()

    def _ap(self, store, o, dev):
        mac, ts, ssid = o["mac"], o["ts"], o.get("ssid")
        if not ssid:
            return
        # KARMA / "Pineapple": one BSSID answering for many different network names.
        seen = self.ap_ssids[mac]
        seen[ssid] = ts
        win = self.cfg["karma_window"]
        for s in [s for s, t0 in seen.items() if ts - t0 > win]:
            del seen[s]
        if len(seen) >= self.cfg["karma_ssids"]:
            names = ", ".join(sorted(seen)[:8])
            store._event(ts, mac, "karma_ap", None, f"answers for {len(seen)} SSIDs: {names}", always=True)
            self.finding(store, ts, f"karma:{mac}", "karma_ap", "high", mac, None, "KARMA-style access point",
                         f"One BSSID advertises {len(seen)} different networks: {names}", event="karma_ap")
        if len(self.ap_ssids) > 20_000:
            self.ap_ssids.clear()
        if ssid not in self.my_ssids:
            return
        enc = o.get("enc") or (dev or {}).get("enc") or ""
        # Evil twin: my SSID broadcast by a BSSID that isn't on the trusted list.
        if self.trusted and mac not in self.trusted:
            t_enc = {i["enc"] for i in self.trusted_info.values() if i.get("ssid", ssid) and i.get("enc")}
            t_vendor = {i["vendor"] for i in self.trusted_info.values() if i.get("vendor")}
            why = []
            if t_enc and enc and enc not in t_enc:
                why.append(f"different security ({enc} vs {', '.join(sorted(t_enc))})")
            vendor = (dev or {}).get("vendor")
            if t_vendor and vendor and vendor not in t_vendor:
                why.append(f"different vendor ({vendor})")
            if (dev or {}).get("randomized"):
                why.append("locally administered BSSID")
            sev = "high" if why else "medium"
            detail = f"“{ssid}” broadcast by untrusted BSSID {mac}" + (f": {'; '.join(why)}" if why else "")
            store._event(ts, mac, "rogue_ap", None, detail, always=True)
            self.finding(store, ts, f"rogue:{mac}", "rogue_ap", sev, mac, ssid, f"Unknown access point for “{ssid}”",
                         detail + ". Trust it in Security → My networks if it's yours.", event="rogue_ap")
            return
        # Configuration issues on my own (trusted or not-yet-configured) APs.
        if "OPN" in enc:
            self.finding(store, ts, f"open:{mac}", "open_network", "high", mac, ssid, f"“{ssid}” is an open network",
                         "Anyone nearby can join and read unencrypted traffic. Enable WPA2/WPA3.")
        if "WEP" in enc:
            self.finding(store, ts, f"wep:{mac}", "weak_security", "high", mac, ssid, f"“{ssid}” uses WEP",
                         "WEP can be cracked in minutes. Switch to WPA2/WPA3.")
        elif enc and "WPA/" in enc and "WPA2" not in enc:
            self.finding(store, ts, f"wpa1:{mac}", "weak_security", "high", mac, ssid, f"“{ssid}” uses WPA (TKIP)",
                         "WPA1/TKIP is deprecated and weak. Switch to WPA2/WPA3.")
        elif enc and "WPA3" not in enc and "OPN" not in enc:
            self.finding(store, ts, f"nowpa3:{mac}", "no_wpa3", "low", mac, ssid, f"“{ssid}” doesn't offer WPA3",
                         "WPA3 (SAE) protects against offline password guessing. Enable WPA2/WPA3 transition mode.")
        wps = (((o.get("fp") or {}).get("wifi") or {}).get("wps")
               or ((((dev or {}).get("extra") or {}).get("fp") or {}).get("wifi") or {}).get("wps"))
        if wps:
            self.finding(store, ts, f"wps:{mac}", "wps_enabled", "medium", mac, ssid, f"WPS is enabled on “{ssid}”",
                         "WPS PIN mode is brute-forceable on many routers. Disable WPS in the router settings.")
        if not self.trusted:
            self.finding(store, ts, f"untrusted:{ssid}", "no_baseline", "low", None, ssid,
                         f"No trusted access points set for “{ssid}”",
                         "Mark your own BSSIDs as trusted so impostors (evil twins) can be detected.")


class TrustBody(BaseModel):
    bssids: List[str]
    trust: bool = True


class StatusBody(BaseModel):
    status: str


def routes(ctx):
    r = APIRouter()

    @r.get("/api/security")
    def overview(days: float = 7, _=Depends(current_user)):
        since = time.time() - days * 86400
        n = ctx.settings.get("networks")
        bssids = []
        if n["ssids"]:
            q = ",".join("?" * len(n["ssids"]))
            bssids = ctx.rows(f"SELECT mac, ssid, channel, band, enc, vendor, first_seen, last_seen, last_rssi, randomized "
                              f"FROM devices WHERE kind='ap' AND ssid IN ({q}) ORDER BY ssid, first_seen", n["ssids"])
            for b in bssids:
                b["trusted"] = b["mac"] in n["trusted_bssids"]
        q = ",".join("?" * len(SECURITY_EVENTS))
        return {
            "networks": n, "bssids": bssids,
            "findings": ctx.rows("SELECT * FROM findings ORDER BY status = 'resolved', CASE severity WHEN 'high' THEN 0 "
                                 "WHEN 'medium' THEN 1 ELSE 2 END, last_seen DESC LIMIT 300"),
            "events": ctx.rows(f"SELECT e.*, d.ssid, d.kind, m.label FROM events e LEFT JOIN devices d ON d.mac=e.mac "
                               f"LEFT JOIN device_meta m ON m.mac=e.mac "
                               f"WHERE e.type IN ({q}) AND e.ts >= ? ORDER BY e.id DESC LIMIT 200",
                               list(SECURITY_EVENTS) + [since]),
            "counts": ctx.rows("SELECT severity, COUNT(*) n FROM findings WHERE status='open' GROUP BY severity"),
        }

    @r.post("/api/security/trust")
    def trust(body: TrustBody, _=Depends(require_admin)):
        n = ctx.settings.get("networks")
        cur = set(n["trusted_bssids"])
        macs = {b.strip().lower() for b in body.bssids}
        cur = cur | macs if body.trust else cur - macs
        n["trusted_bssids"] = sorted(cur)
        ctx.settings.set("networks", {"ssids": n["ssids"], "trusted_bssids": n["trusted_bssids"]})
        if body.trust:  # trusting an AP resolves its rogue finding
            for m in macs:
                ctx.execute("UPDATE findings SET status='resolved' WHERE key=?", (f"rogue:{m}",))
                ctx.security.status[f"rogue:{m}"] = "resolved"
        return {"ok": True, "trusted": n["trusted_bssids"]}

    @r.post("/api/security/findings/{fid}")
    def set_status(fid: int, body: StatusBody, _=Depends(require_admin)):
        if body.status not in ("open", "acknowledged", "resolved"):
            raise HTTPException(400, "bad status")
        f = ctx.one("SELECT key FROM findings WHERE id=?", (fid,))
        if not f:
            raise HTTPException(404)
        ctx.execute("UPDATE findings SET status=? WHERE id=?", (body.status, fid))
        ctx.security.status[f["key"]] = body.status
        return {"ok": True}

    return r
