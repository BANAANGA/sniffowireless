"""DFS (Dynamic Frequency Selection) / radar detection, passively from beacons.

5 GHz channels 52–144 are shared with weather, airport and military radar. An access point on such a channel must
watch for radar and, when it hears it, leave within seconds and stay off that channel for 30 minutes. It usually
tells its clients first with a Channel Switch Announcement in its beacons. sniffowireless watches every access point's
channel: a CSA or a move away from a DFS channel is recorded as a radar hit for that channel. A neighbour's access
point detecting radar is just as useful: radar is a property of the location, not of the network.
"""
import time

from fastapi import APIRouter, Depends

from .auth import current_user

SCHEMA = """
CREATE TABLE IF NOT EXISTS dfs_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, mac TEXT NOT NULL, ssid TEXT, from_ch INTEGER,
  to_ch INTEGER, csa INTEGER DEFAULT 0, dfs INTEGER DEFAULT 0, mine INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_dfs_events_ts ON dfs_events(ts);
"""
DFS_CHANNELS = frozenset(range(52, 145, 4))
NON_OCCUPANCY = 1800   # seconds a channel stays closed after radar
CONFIRM = 3            # sightings on a new channel before it counts as a channel change (no CSA seen)
CSA_LINK = 900         # a channel change this soon after a CSA belongs to it


def is_dfs(ch):
    return ch in DFS_CHANNELS


def is_5ghz(ch):
    return ch is not None and 32 <= ch <= 177


class DfsMonitor:
    """Store plugin (writer thread)."""

    def __init__(self, ctx):
        self.ctx = ctx
        ctx.store.conn.executescript(SCHEMA)
        self.chan = {}     # bssid -> confirmed channel
        self.cand = {}     # bssid -> [channel, sightings]
        self.csa = {}      # bssid -> (ts, from_ch, to_ch) of the last announcement
        self.rows = []     # dfs_events waiting for flush
        self.counts = {"radar": 0, "csa": 0, "change": 0}
        self.pending = False
        for r in ctx.rows("SELECT mac, channel FROM devices WHERE kind='ap' AND band='5' AND channel IS NOT NULL"):
            self.chan[r["mac"]] = r["channel"]

    def mine(self, mac, ssid):
        n = self.ctx.settings.get("networks") if self.ctx.settings else {}
        return mac in (n.get("trusted_bssids") or []) or (ssid is not None and ssid in (n.get("ssids") or []))

    def _record(self, store, ts, mac, ssid, frm, to, csa):
        mine = self.mine(mac, ssid)
        name = f"“{ssid}”" if ssid else mac
        self.rows.append((ts, mac, ssid, frm, to, int(csa), int(is_dfs(frm)), int(mine)))
        self.pending = True
        if is_dfs(frm):
            self.counts["radar"] += 1
            how = "announced a channel switch" if csa else "left without announcing it"
            store._event(ts, mac, "dfs_radar", f"ssid:{ssid}" if ssid else None,
                         f"DFS channel {frm}: {name} {how}, moving to {to}"
                         f"{' (my network)' if mine else ''}; channel {frm} is closed for 30 min", always=True)

    def observe(self, store, o, dev):
        if o["t"] != "wifi_ap" or o.get("band") == "6":
            return
        mac, ts, ch, csa = o["mac"], o["ts"], o.get("channel"), o.get("csa")
        if not is_5ghz(ch):
            return
        ssid = o.get("ssid") or (dev or {}).get("ssid")
        cur = self.chan.get(mac)
        if cur is None:
            self.chan[mac] = ch
            cur = ch
        if csa and csa.get("new_channel") and csa["new_channel"] != cur:
            to = csa["new_channel"]
            last = self.csa.get(mac)
            if not last or last[2] != to or ts - last[0] > CSA_LINK:
                self.csa[mac] = (ts, cur, to)
                self.counts["csa"] += 1
                store._event(ts, mac, "channel_switch_announced", None,
                             f"announced a switch from channel {cur} to {to}"
                             f"{f' in {csa.get('count')} beacons' if csa.get('count') else ''}", always=True)
                self._record(store, ts, mac, ssid, cur, to, True)
            return
        if ch == cur:
            self.cand.pop(mac, None)
            return
        c = self.cand.get(mac)
        if not c or c[0] != ch:
            self.cand[mac] = [ch, 1]
            return
        c[1] += 1
        if c[1] < CONFIRM:
            return
        del self.cand[mac]
        self.chan[mac] = ch
        self.counts["change"] += 1
        store._event(ts, mac, "channel_change", None, f"moved from channel {cur} to {ch}", always=True)
        last = self.csa.pop(mac, None)
        if not (last and last[2] == ch and ts - last[0] <= CSA_LINK):  # an announced move was recorded already
            self._record(store, ts, mac, ssid, cur, ch, False)

    def flush(self, store, c):
        if self.rows:
            c.executemany("INSERT INTO dfs_events(ts, mac, ssid, from_ch, to_ch, csa, dfs, mine) VALUES(?,?,?,?,?,?,?,?)",
                          self.rows)
            self.rows = []
        self.pending = False

    def prune(self, store, c, cutoff):
        c.execute("DELETE FROM dfs_events WHERE ts < ?", (cutoff,))


def routes(ctx):
    r = APIRouter()

    @r.get("/api/dfs")
    def overview(days: float = 7, _=Depends(current_user)):
        now = time.time()
        since = now - max(0.01, min(days, 365)) * 86400
        events = ctx.rows("SELECT e.*, d.vendor FROM dfs_events e LEFT JOIN devices d ON d.mac=e.mac "
                          "WHERE e.ts >= ? ORDER BY e.ts DESC LIMIT 500", (since,))
        per = {ch: {"channel": ch, "radar": 0, "aps_now": 0, "last": None, "closed_until": None} for ch in sorted(DFS_CHANNELS)}
        for e in events:
            if e["dfs"] and e["from_ch"] in per:
                p = per[e["from_ch"]]
                p["radar"] += 1
                p["last"] = max(p["last"] or 0, e["ts"])
                if e["ts"] + NON_OCCUPANCY > now:
                    p["closed_until"] = max(p["closed_until"] or 0, e["ts"] + NON_OCCUPANCY)
        nets = ctx.settings.get("networks")
        ssids, trusted = set(nets["ssids"]), set(nets["trusted_bssids"])
        aps = ctx.rows("SELECT mac, ssid, channel, vendor, last_seen, last_rssi, enc FROM devices WHERE kind='ap' "
                       "AND band='5' AND channel BETWEEN 52 AND 144 AND last_seen >= ? ORDER BY channel, ssid",
                       (now - 3600,))
        for a in aps:
            a["mine"] = a["mac"] in trusted or a["ssid"] in ssids
            if a["channel"] in per:
                per[a["channel"]]["aps_now"] += 1
        for e in events:
            e["mine"] = bool(e["mine"])
        return {"channels": list(per.values()), "events": events, "aps": aps, "now": now,
                "radar_total": sum(p["radar"] for p in per.values()),
                "mine_radar": sum(1 for e in events if e["dfs"] and e["mine"])}

    return r
