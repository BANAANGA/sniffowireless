"""Networks under investigation, plus the SSID catalogue used by the network pickers.

An admin puts SSIDs on the investigation list (e.g. an unknown network that appeared nearby, a suspected rogue
hotspot, a neighbour's network a device keeps joining). sniffowireless then raises events when such a network is on the
air, when a device connects to it and when a device looks for it, and builds a dossier per SSID."""
import time
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .auth import current_user, require_admin
from .sanitize import Notes, Ssid, clean_str

EVENTS = ("investigated_seen", "investigated_connect", "investigated_probe")
PROBE_REPEAT = 6 * 3600   # report the same device probing for the same SSID at most this often
CONNECT_REPEAT = 1800


class InvestigationMonitor:
    """Store plugin (writer thread)."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.ssids = {}        # ssid -> note
        self.bssids = {}       # bssid -> ssid (learned from beacons / database)
        self.last_ap = {}      # bssid -> last sighting
        self.last = {}         # (kind, mac, key) -> last event time
        self.reload()
        ctx.settings.on_change(lambda k: self.reload() if k == "investigate" else None)

    def reload(self):
        self.ssids = {e["ssid"]: e.get("note") for e in self.ctx.settings.get("investigate")["ssids"]}
        self.bssids = {}
        if self.ssids:
            q = ",".join("?" * len(self.ssids))
            for r in self.ctx.rows(f"SELECT mac, ssid FROM devices WHERE kind='ap' AND ssid IN ({q})", list(self.ssids)):
                self.bssids[r["mac"]] = r["ssid"]

    def _once(self, key, ts, every):
        if ts - self.last.get(key, 0) < every:
            return False
        self.last[key] = ts
        if len(self.last) > 100_000:
            self.last.clear()
        return True

    def observe(self, store, o, dev):
        if not self.ssids:
            return
        t, mac, ts = o["t"], o.get("mac"), o["ts"]
        if t == "wifi_ap":
            ssid = o.get("ssid")
            if ssid not in self.ssids:
                return
            self.bssids[mac] = ssid
            prev = self.last_ap.get(mac, 0)
            self.last_ap[mac] = ts
            if ts - prev > store.cfg.wifi_session_timeout:  # (re)appeared
                ch = o.get("channel")
                store._event(ts, mac, "investigated_seen", f"ssid:{ssid}",
                             f"“{ssid}” on the air ({mac}{f', ch {ch}' if ch else ''}, {o.get('enc') or 'unknown security'})",
                             always=True)
        elif t == "wifi_client":
            bssid, frame = o.get("bssid"), o.get("frame")
            if bssid in self.bssids and frame in ("data", "assoc"):
                ssid = self.bssids[bssid]
                if self._once(("c", mac, bssid), ts, CONNECT_REPEAT) and (store.assoc.get(mac) is None or
                                                                           store.assoc[mac].start >= ts - 1):
                    store._event(ts, mac, "investigated_connect", f"ssid:{ssid}", f"connected to “{ssid}” via {bssid}",
                                 always=True)
            probe = o.get("probe")
            if probe in self.ssids and self._once(("p", mac, probe), ts, PROBE_REPEAT):
                store._event(ts, mac, "investigated_probe", f"ssid:{probe}", f"looking for “{probe}”", always=True)


# ------------------------------------------------------------------ routes
class InvestigatedSsid(BaseModel):
    ssid: Ssid
    note: Optional[Notes] = None
    added: Optional[float] = None


class InvestigateList(BaseModel):
    ssids: List[InvestigatedSsid] = Field([], max_length=200)


def ssid_catalogue(ctx, q="", limit=200, days=30):
    """Every SSID seen: broadcast by access points and/or probed for by devices, with flags for the lists."""
    since = time.time() - days * 86400
    like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    out = {}
    for r in ctx.rows("SELECT ssid, COUNT(*) aps, MAX(last_seen) last_seen, MAX(last_rssi) best_rssi, "
                      "GROUP_CONCAT(DISTINCT enc) enc, GROUP_CONCAT(DISTINCT band) bands FROM devices WHERE kind='ap' "
                      "AND ssid IS NOT NULL AND ssid != '' AND last_seen >= ? AND ssid LIKE ? ESCAPE '\\' GROUP BY ssid",
                      (since, like)):
        out[r["ssid"]] = {**r, "probers": 0, "clients": 0}
    for r in ctx.rows("SELECT ssid, COUNT(DISTINCT mac) probers, MAX(last_seen) last_seen FROM probes "
                      "WHERE last_seen >= ? AND ssid LIKE ? ESCAPE '\\' GROUP BY ssid", (since, like)):
        e = out.setdefault(r["ssid"], {"ssid": r["ssid"], "aps": 0, "last_seen": r["last_seen"], "best_rssi": None,
                                       "enc": None, "bands": None, "clients": 0})
        e["probers"] = r["probers"]
        e["last_seen"] = max(e["last_seen"] or 0, r["last_seen"] or 0)
    for r in ctx.rows("SELECT a.ssid, COUNT(DISTINCT s.mac) n FROM sessions s JOIN devices a ON a.mac=s.peer "
                      "WHERE s.type='assoc' AND s.end_ts >= ? AND a.ssid LIKE ? ESCAPE '\\' GROUP BY a.ssid", (since, like)):
        if r["ssid"] in out:
            out[r["ssid"]]["clients"] = r["n"]
    mine = set(ctx.settings.get("networks")["ssids"])
    ignored = {e["ssid"] for e in ctx.settings.get("ignore")["ssids"]}
    inv = {e["ssid"] for e in ctx.settings.get("investigate")["ssids"]}
    for e in out.values():
        e.update(mine=e["ssid"] in mine, ignored=e["ssid"] in ignored, investigated=e["ssid"] in inv)
    items = sorted(out.values(), key=lambda e: (-(e["aps"] > 0), -(e["last_seen"] or 0)))
    return items[:limit]


def routes(ctx):
    r = APIRouter()

    @r.get("/api/ssids")
    def ssids(q: str = Query("", max_length=64), limit: int = 200, days: float = 30, _=Depends(current_user)):
        return {"items": ssid_catalogue(ctx, q.strip(), max(1, min(limit, 1000)), days)}

    @r.get("/api/settings/investigate")
    def get_list(_=Depends(current_user)):
        return ctx.settings.get("investigate")

    @r.put("/api/settings/investigate")
    def put_list(body: InvestigateList, _=Depends(require_admin)):
        old = {e["ssid"]: e for e in ctx.settings.get("investigate")["ssids"]}
        out, seen = [], set()
        for e in body.ssids:
            if e.ssid in seen:
                continue
            seen.add(e.ssid)
            out.append({"ssid": e.ssid, "note": e.note or None, "added": (old.get(e.ssid) or {}).get("added") or time.time()})
        ctx.settings.set("investigate", {"ssids": out})
        return {"ok": True, "count": len(out)}

    @r.get("/api/investigations")
    def overview(days: float = 7, _=Depends(current_user)):
        lst = ctx.settings.get("investigate")["ssids"]
        if not lst:
            return {"items": []}
        since = time.time() - days * 86400
        cat = {e["ssid"]: e for e in ssid_catalogue(ctx, "", 100_000, 400)}
        counts = {}
        seen_aps = {row["peer"]: row["n"] for row in ctx.rows(
            "SELECT peer, COUNT(DISTINCT mac) n FROM events WHERE type='investigated_seen' GROUP BY peer")}
        q = ",".join("?" * len(EVENTS))
        for row in ctx.rows(f"SELECT peer, type, COUNT(*) n, MAX(ts) last FROM events WHERE type IN ({q}) AND ts >= ? "
                            f"GROUP BY peer, type", list(EVENTS) + [since]):
            counts.setdefault(row["peer"], {})[row["type"]] = row["n"]
        items = []
        for e in lst:
            c = cat.get(e["ssid"], {})
            ev = counts.get(f"ssid:{e['ssid']}", {})
            items.append({**e, "aps": max(c.get("aps", 0), seen_aps.get(f"ssid:{e['ssid']}", 0)), "clients": c.get("clients", 0), "probers": c.get("probers", 0),
                          "last_seen": c.get("last_seen"), "enc": c.get("enc"), "bands": c.get("bands"),
                          "events": {k.split("_", 1)[1]: v for k, v in ev.items()}})
        return {"items": items, "days": days}

    @r.get("/api/investigations/{ssid}")
    def dossier(ssid: str, days: float = 30, _=Depends(current_user)):
        ssid = clean_str(ssid, 64)
        entry = next((e for e in ctx.settings.get("investigate")["ssids"] if e["ssid"] == ssid), None)
        if not ssid:
            raise HTTPException(404)
        now = time.time()
        since = now - days * 86400
        aps = ctx.rows("SELECT d.mac, d.channel, d.band, d.enc, d.vendor, d.first_seen, d.last_seen, d.last_rssi, d.best_rssi, "
                       "d.randomized, d.wifi_gen, d.room, d.ident, d.ssid current_ssid, m.label FROM devices d "
                       "LEFT JOIN device_meta m ON m.mac=d.mac WHERE d.kind='ap' AND (d.ssid=? OR d.mac IN "
                       # an AP's record keeps only its latest name; APs that rotate names (KARMA) are found via events
                       "(SELECT mac FROM events WHERE type='investigated_seen' AND peer=?)) ORDER BY d.last_seen DESC",
                       (ssid, f"ssid:{ssid}"))
        for a in aps:
            ctx.jsonf(a, "ident")
            a["ident"] = (a["ident"] or {}).get("label")
        bss = [a["mac"] for a in aps]
        clients, sessions, presence = [], [], []
        if bss:
            q = ",".join("?" * len(bss))
            clients = ctx.rows(
                f"SELECT s.mac, COUNT(*) sessions, SUM(MIN(s.end_ts, ?) - MAX(s.start_ts, ?)) secs, MIN(s.start_ts) first, "
                f"MAX(s.end_ts) last, MAX(s.open) connected, d.kind, d.name, d.vendor, d.randomized, d.ident, m.label "
                f"FROM sessions s LEFT JOIN devices d ON d.mac=s.mac LEFT JOIN device_meta m ON m.mac=s.mac "
                f"WHERE s.type='assoc' AND s.peer IN ({q}) AND s.end_ts >= ? GROUP BY s.mac ORDER BY last DESC LIMIT 200",
                [now, since] + bss + [since])
            sessions = ctx.rows(f"SELECT mac, peer, start_ts, end_ts FROM sessions WHERE type='assoc' AND peer IN ({q}) "
                                f"AND end_ts >= ? ORDER BY start_ts LIMIT 5000", bss + [since])
            presence = ctx.rows(f"SELECT mac, start_ts, end_ts FROM sessions WHERE type='presence' AND mac IN ({q}) "
                                f"AND end_ts >= ? ORDER BY start_ts LIMIT 5000", bss + [since])
        for c in clients:
            ctx.jsonf(c, "ident")
            c["ident"] = (c["ident"] or {}).get("label")
        probers = ctx.rows("SELECT p.mac, p.first_seen, p.last_seen, p.count, d.kind, d.name, d.vendor, d.randomized, "
                           "d.fp_hash, m.label FROM probes p LEFT JOIN devices d ON d.mac=p.mac LEFT JOIN device_meta m ON "
                           "m.mac=p.mac WHERE p.ssid=? ORDER BY p.last_seen DESC LIMIT 200", (ssid,))
        q = ",".join("?" * len(EVENTS))
        events = ctx.rows(f"SELECT e.*, d.kind, d.name, d.vendor, m.label FROM events e LEFT JOIN devices d ON d.mac=e.mac "
                          f"LEFT JOIN device_meta m ON m.mac=e.mac WHERE e.type IN ({q}) AND e.peer=? "
                          f"ORDER BY e.id DESC LIMIT 200", list(EVENTS) + [f"ssid:{ssid}"])
        return {"ssid": ssid, "entry": entry, "investigated": entry is not None, "since": since, "now": now,
                "aps": aps, "clients": clients, "probers": probers, "sessions": sessions, "presence": presence,
                "events": events, "mine": ssid in ctx.settings.get("networks")["ssids"]}

    return r
