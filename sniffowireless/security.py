"""Wireless security monitoring (defensive): rogue / evil-twin APs, deauthentication floods,
KARMA-style APs, configuration issues on the admin's own networks (open, WEP/TKIP, WPS), and a known
device's radio fingerprint changing (its MAC address may have been reused by, or spoofed onto, a
different physical device), a targeted deauth-and-rejoin pattern against one of the admin's networks (a
handshake-capture attack), one of the admin's own access points advertising weaker security than it used
to, a client probing for an implausibly long list of networks, and one MAC address behind two devices."""
import time
from collections import defaultdict, deque

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .auth import current_user, require_admin
from .identify import probe_hash
from .sanitize import MacList

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE NOT NULL, type TEXT NOT NULL, severity TEXT,
  mac TEXT, ssid TEXT, title TEXT, detail TEXT, first_seen REAL, last_seen REAL, count INTEGER DEFAULT 1,
  status TEXT DEFAULT 'open');
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status, last_seen);
CREATE TABLE IF NOT EXISTS ap_enc(mac TEXT PRIMARY KEY, enc TEXT, rank INTEGER, ts REAL);
"""
SECURITY_EVENTS = ("rogue_ap", "deauth_flood", "karma_ap", "deauth_broadcast", "security_finding", "rogue_dhcp",
                   "arp_spoof", "tracker_following", "fingerprint_changed", "handshake_attack", "ap_downgrade",
                   "probe_scan", "mac_duplicate")
KNOWN_MACS_REFRESH = 15  # seconds between re-reading device_meta.known (no on_change hook for device_meta)
REJOIN_GAP = 15          # a client that reassociates within this many seconds of being kicked completed a "cycle"
DOWNGRADE_FRAMES = 3     # consecutive beacons showing weaker security before it's believed (one glitchy frame isn't)
# Same MAC, two devices: its probe-request fingerprint flips back and forth within one band, or one sensor hears
# it jump between very strong and very weak signal from one frame to the next, over and over.
DUP_FP_CHANGES, DUP_FP_WINDOW = 3, 600
RSSI_JUMP_DB, RSSI_JUMP_GAP, RSSI_JUMPS, RSSI_JUMP_WINDOW = 35, 3, 6, 120


def enc_rank(enc):
    """How strong an access point's advertised security is: 0 open ... 5 WPA3-only; None if it says nothing."""
    if not enc:
        return None
    if "OPN" in enc:
        return 0
    if "WEP" in enc:
        return 1
    if "WPA3" in enc:
        return 4 if "WPA2" in enc else 5
    if "WPA2" in enc:
        return 3
    if "WPA/" in enc:
        return 2
    return None


class SecurityMonitor:
    """Store plugin: observe() runs on the store's writer thread for every observation."""

    def __init__(self, ctx):
        self.ctx = ctx
        ctx.store.conn.executescript(SCHEMA)
        self.deauths = defaultdict(deque)   # bssid -> timestamps of deauth/disassoc frames
        self.ap_ssids = defaultdict(dict)   # bssid -> {ssid: last seen} (KARMA detection)
        self.pending = {}                   # finding key -> finding dict to upsert
        self.status = {r["key"]: r["status"] for r in ctx.rows("SELECT key, status FROM findings")}
        # Fingerprint drift: last probe fingerprint per (known device, band), learned as probes arrive.
        self.known_macs = {r["mac"] for r in ctx.rows("SELECT mac FROM device_meta WHERE known=1")}
        self.fp_seen = {}
        self.known_refreshed = 0
        self.kicks = {}                     # (bssid, station) -> (ts, reason) of the last AP-sent deauth/disassoc
        self.cycles = defaultdict(deque)    # (bssid, station) -> timestamps of kick-then-rejoin cycles
        self.probes = defaultdict(dict)     # mac -> {directed-probe ssid: last seen}
        self.fp_flips = {}                  # (mac, band) -> [last fp, deque of change timestamps]
        self.rssi_last = {}                 # (mac, sensor) -> (ts, rssi)
        self.rssi_jumps = defaultdict(deque)
        # Strongest security each of my access points has advertised, so a later drop is a downgrade.
        # Seeded from what the device table last saw so the first run after an upgrade has a baseline too.
        self.enc_base, self.enc_dirty, self.down_count = {}, {}, {}
        for r in ctx.rows("SELECT mac, enc, rank FROM ap_enc"):
            self.enc_base[r["mac"]] = (r["rank"], r["enc"])
        for r in ctx.rows("SELECT mac, enc FROM devices WHERE kind='ap' AND enc IS NOT NULL AND enc != ''"):
            rk = enc_rank(r["enc"])
            if rk is not None and r["mac"] not in self.enc_base:
                self.enc_base[r["mac"]] = (rk, r["enc"])
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
                      "title=excluded.title, detail=excluded.detail, severity=excluded.severity, "
                      "status=CASE WHEN status='resolved' THEN 'open' ELSE status END", f)
        self.pending.clear()
        for mac, (enc, rank, ts) in self.enc_dirty.items():
            c.execute("INSERT OR REPLACE INTO ap_enc(mac, enc, rank, ts) VALUES(?,?,?,?)", (mac, enc, rank, ts))
        self.enc_dirty.clear()

    def accept_security(self, mac):
        """The admin resolved a downgrade finding: whatever the AP advertises now is the new normal."""
        self.enc_base.pop(mac, None)
        self.enc_dirty.pop(mac, None)
        self.down_count.pop(mac, None)
        self.ctx.execute("DELETE FROM ap_enc WHERE mac=?", (mac,))

    def sweep(self, store, now):
        if now - self.known_refreshed > KNOWN_MACS_REFRESH:
            self.known_macs = {r["mac"] for r in self.ctx.rows("SELECT mac FROM device_meta WHERE known=1")}
            self.known_refreshed = now

    # ------------------------------------------------------------- detection
    def observe(self, store, o, dev):
        t = o["t"]
        if t == "wifi_ap":
            self._ap(store, o, dev)
        elif t == "wifi_client":
            frame = o.get("frame")
            if frame in ("deauth", "disassoc") and o.get("bssid"):
                self._deauth(store, o["bssid"], o["ts"], o.get("mac"))
                if o.get("from_ap"):
                    self._kick(store, o)
            elif frame == "assoc" and o.get("bssid"):
                self._rejoin(store, o)
            elif frame == "probe" and o.get("probe"):
                self._probe(store, o, dev)
        elif t == "event" and o.get("type") == "deauth_broadcast":
            self._deauth(store, o["mac"], o["ts"], None, weight=1)
        if t in ("wifi_ap", "wifi_client"):
            self._check_dup(store, o, dev)
        if dev and dev["mac"] in self.known_macs:
            self._check_drift(store, o, dev)

    def _check_drift(self, store, o, dev):
        """A known device's probe-request fingerprint (chipset + OS build signature) changed to a
        different, previously-unseen value: the MAC may now belong to a different physical device, either
        because it was reassigned (the usual, harmless reason) or because it's being spoofed. Compared per
        band, since one device legitimately sends different probe layouts on 2.4, 5 and 6 GHz."""
        fpd = o.get("fp") or {}
        sig = (fpd.get("wifi") or {}).get("sig")
        if fpd.get("src") != "probe" or not sig:
            return
        mac, fp, key = dev["mac"], probe_hash(sig), (dev["mac"], o.get("band"))
        prev = self.fp_seen.get(key)
        self.fp_seen[key] = fp
        if not prev or prev == fp:
            return
        ts = o["ts"]
        ssid = dev.get("ssid")
        detail = (f"Its fingerprint changed from {prev} to {fp}. This usually just means a software "
                 "update changed the device's probe-request signature, but it can also mean this MAC "
                 "address now belongs to a different device.")
        store._event(ts, mac, "fingerprint_changed", None, detail, dev=dev, always=True)
        self.finding(store, ts, f"fpdrift:{mac}:{fp}", "fingerprint_changed", "medium", mac, ssid,
                     "A known device's fingerprint changed", detail, event="fingerprint_changed")
        if len(self.fp_seen) > 50_000:
            self.fp_seen.clear()

    # A handshake-capture attack forces a client off the network so it reconnects and re-sends the WPA
    # handshake, which is then cracked offline. Done to one client a few times it stays far below the
    # deauth-flood threshold, so it's caught here instead: the same station, kicked by (what claims to be)
    # my AP and straight back again, over and over.
    def _kick(self, store, o):
        bssid, sta = o["bssid"], o["mac"]
        if ((store.devices.get(bssid) or {}).get("ssid")) in self.my_ssids:
            self.kicks[(bssid, sta)] = (o["ts"], o.get("reason"))
            if len(self.kicks) > 20_000:
                self.kicks.clear()

    def _rejoin(self, store, o):
        key = (o["bssid"], o["mac"])
        kick = self.kicks.pop(key, None)
        ts = o["ts"]
        if not kick or not 0 <= ts - kick[0] <= REJOIN_GAP:
            return
        q = self.cycles[key]
        q.append(ts)
        win = self.cfg["hs_window"]
        while q and ts - q[0] > win:
            q.popleft()
        if len(q) >= self.cfg["hs_cycles"]:
            bssid, sta = key
            ssid = (store.devices.get(bssid) or {}).get("ssid")
            why = f" (reason {kick[1]})" if kick[1] is not None else ""
            detail = (f"{sta} was thrown off “{ssid}” via {bssid}{why} and reconnected {len(q)} times in "
                      f"{win // 60 or 1} min. Each reconnect hands an attacker a fresh WPA handshake to crack offline; "
                      "this is well below the deauth-flood threshold. If it's your own testing or a flaky client, resolve it.")
            self.finding(store, ts, f"hsattack:{bssid}:{sta}", "handshake_attack", "high", bssid, ssid,
                         f"Possible handshake-capture attack on “{ssid}”", detail, event="handshake_attack")
            q.clear()
        if len(self.cycles) > 20_000:
            self.cycles.clear()

    # A scanner (wardriving, Wi-Fi recon) asks for far more networks by name than any one device remembers.
    def _probe(self, store, o, dev):
        mac, ts, seen = o["mac"], o["ts"], self.probes[o["mac"]]
        seen[o["probe"]] = ts
        win = self.cfg["probe_window"]
        for s in [s for s, t0 in seen.items() if ts - t0 > win]:
            del seen[s]
        if len(seen) >= self.cfg["probe_ssids"]:
            names = ", ".join(sorted(seen)[:8])
            detail = (f"{mac} sent directed probe requests for {len(seen)} different networks in {win}s "
                      f"(e.g. {names}). That's more than a normal device's saved-network list: usually a scanning "
                      "tool, though an old device with a very long list of remembered networks can do it too.")
            self.finding(store, ts, f"probescan:{mac}", "probe_scan", "medium", mac, None,
                         f"{mac} is probing for {len(seen)} networks", detail, event="probe_scan")
            seen.clear()
        if len(self.probes) > 20_000:
            self.probes.clear()

    # One MAC, two devices (a clone or a spoof, not a device that was merely reassigned): its probe
    # fingerprint keeps flipping within one band, or one sensor keeps hearing it jump between very strong
    # and very weak from one frame to the next — a single radio can't do either.
    def _check_dup(self, store, o, dev):
        mac, ts = o["mac"], o["ts"]
        sig = ((o.get("fp") or {}).get("wifi") or {}).get("sig")
        if sig and (o.get("fp") or {}).get("src") == "probe":
            fp = probe_hash(sig)
            key = (mac, o.get("band"))
            st = self.fp_flips.get(key)
            if st is None:
                self.fp_flips[key] = [fp, deque()]
            elif st[0] != fp:
                st[0] = fp
                q = st[1]
                q.append(ts)
                while q and ts - q[0] > DUP_FP_WINDOW:
                    q.popleft()
                if len(q) >= DUP_FP_CHANGES:
                    self._dup(store, ts, mac, dev, f"its probe-request fingerprint flipped {len(q)} times in "
                              f"{DUP_FP_WINDOW // 60} min on the same band, which one chipset doesn't do")
                    q.clear()
            if len(self.fp_flips) > 50_000:
                self.fp_flips.clear()
        rssi = o.get("rssi")
        if rssi is None:
            return
        k = (mac, o.get("sensor") or "local")
        prev = self.rssi_last.get(k)
        self.rssi_last[k] = (ts, rssi)
        if prev and 0 <= ts - prev[0] <= RSSI_JUMP_GAP and abs(rssi - prev[1]) >= RSSI_JUMP_DB:
            q = self.rssi_jumps[mac]
            q.append(ts)
            while q and ts - q[0] > RSSI_JUMP_WINDOW:
                q.popleft()
            if len(q) >= RSSI_JUMPS:
                self._dup(store, ts, mac, dev, f"one sensor heard its signal jump by {RSSI_JUMP_DB}+ dB between "
                          f"consecutive frames {len(q)} times in {RSSI_JUMP_WINDOW}s, as if two transmitters at "
                          "different distances were sharing the address")
                q.clear()
        if len(self.rssi_last) > 50_000:
            self.rssi_last.clear()
            self.rssi_jumps.clear()

    def _dup(self, store, ts, mac, dev, why):
        name = (dev or {}).get("ssid") or (dev or {}).get("name")
        detail = (f"{mac}{f' ({name})' if name else ''}: {why}. This can mean the address is cloned or spoofed "
                  "onto a second device; a repeater or a glitchy driver can look similar.")
        self.finding(store, ts, f"macdup:{mac}", "mac_duplicate", "medium", mac, (dev or {}).get("ssid"),
                     f"{mac} looks like two devices", detail, event="mac_duplicate")

    def _check_downgrade(self, store, ts, mac, ssid, enc):
        rank = enc_rank(enc)
        if rank is None:
            return
        base = self.enc_base.get(mac)
        if base is None or rank > base[0]:
            self.enc_base[mac] = (rank, enc)
            self.enc_dirty[mac] = (enc, rank, ts)
            self.down_count.pop(mac, None)
            return
        if rank >= base[0]:
            self.down_count.pop(mac, None)
            return
        n = self.down_count[mac] = self.down_count.get(mac, 0) + 1
        if n < DOWNGRADE_FRAMES:
            return
        sev = "high" if rank <= 2 else "medium" if rank == 3 else "low"
        detail = (f"{mac} used to advertise {base[1]} for “{ssid}” and now advertises {enc}. Either the access "
                  "point was reconfigured, or something is impersonating its address with weaker security. "
                  "Resolve this finding to accept the new setting as normal.")
        self.finding(store, ts, f"downgrade:{mac}", "ap_downgrade", sev, mac, ssid,
                     f"“{ssid}” security dropped ({base[1]} → {enc})", detail, event="ap_downgrade")

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
        self._check_downgrade(store, ts, mac, ssid, enc)
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
    bssids: MacList
    trust: bool = True


class StatusBody(BaseModel):
    status: str = Field(pattern="^(open|acknowledged|resolved)$")


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
        macs = set(body.bssids)
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
        if body.status == "resolved" and f["key"].startswith("downgrade:"):
            ctx.security.accept_security(f["key"].split(":", 1)[1])
        return {"ok": True}

    return r
