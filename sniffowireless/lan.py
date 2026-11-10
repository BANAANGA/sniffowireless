"""LAN (Ethernet) analytics: per-device traffic, conversations, DNS lookups, DHCP servers, plus
rogue-DHCP and ARP-spoofing detection. Runs as a store plugin on the writer thread."""
import time
from collections import defaultdict, deque

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .auth import current_user, require_admin
from .modules import cutoff_for
from .sanitize import Mac, clean_str

SCHEMA = """
CREATE TABLE IF NOT EXISTS lan_traffic(
  mac TEXT NOT NULL, minute INTEGER NOT NULL, bytes_out INTEGER DEFAULT 0, bytes_in INTEGER DEFAULT 0,
  pkts INTEGER DEFAULT 0, PRIMARY KEY(mac, minute)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_lan_traffic_minute ON lan_traffic(minute);
CREATE TABLE IF NOT EXISTS lan_flows(
  mac TEXT NOT NULL, hour INTEGER NOT NULL, peer TEXT NOT NULL, proto INTEGER NOT NULL, port INTEGER NOT NULL,
  peer_name TEXT, bytes_out INTEGER DEFAULT 0, bytes_in INTEGER DEFAULT 0, pkts INTEGER DEFAULT 0,
  PRIMARY KEY(mac, hour, peer, proto, port)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_lan_flows_hour ON lan_flows(hour);
CREATE TABLE IF NOT EXISTS lan_dns(
  mac TEXT NOT NULL, name TEXT NOT NULL, first_seen REAL, last_seen REAL, count INTEGER DEFAULT 0,
  PRIMARY KEY(mac, name)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_lan_dns_last ON lan_dns(last_seen);
CREATE TABLE IF NOT EXISTS dhcp_servers(
  mac TEXT PRIMARY KEY, ip TEXT, router TEXT, first_seen REAL, last_seen REAL, replies INTEGER DEFAULT 0);
"""
PORTS = {20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp", 80: "http",
         110: "pop3", 123: "ntp", 137: "netbios", 138: "netbios", 139: "netbios", 143: "imap", 161: "snmp",
         443: "https", 445: "smb", 465: "smtps", 514: "syslog", 554: "rtsp", 587: "submission", 631: "ipp",
         853: "dns-over-tls", 993: "imaps", 995: "pop3s", 1883: "mqtt", 1900: "ssdp", 3389: "rdp", 3478: "stun",
         5000: "upnp/http", 5060: "sip", 5223: "apple-push", 5228: "google-push", 5353: "mdns", 5355: "llmnr",
         8008: "cast", 8009: "cast", 8080: "http-alt", 8443: "https-alt", 8883: "mqtt-tls", 9100: "printer",
         32400: "plex", 51820: "wireguard"}
PROTOS = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}
ARP_FLIPS = 3         # IP claimed by this many MAC changes...
ARP_WINDOW = 300      # ...within this many seconds -> ARP spoofing


def service(proto, port):
    return PORTS.get(port) or (f"{PROTOS.get(proto, proto)}/{port}" if port else PROTOS.get(proto, str(proto)))


class LanMonitor:
    def __init__(self, ctx):
        self.ctx = ctx
        ctx.store.conn.executescript(SCHEMA)
        self.traffic = {}     # (mac, minute) -> [out, in, pkts]
        self.flows = {}       # (mac, hour, peer, proto, port) -> [out, in, pkts, name]
        self.dns = {}         # (mac, name) -> [first, last, count]
        self.servers = {}     # mac -> [ip, router, first, last, replies]
        self.ip_owner = {}    # ip -> (mac, ts)
        self.ip_changes = defaultdict(deque)
        self.gateway = {}     # gateway ip -> mac (learned from DHCP router option + ARP)
        self.pending = False
        self.trusted = set()
        self.reload()
        ctx.settings.on_change(lambda k: self.reload() if k == "lan" else None)

    def reload(self):
        self.trusted = set(self.ctx.settings.get("lan")["trusted_dhcp"])

    # ------------------------------------------------------------- observe
    def observe(self, store, o, dev):
        t = o["t"]
        if t == "lan_traffic":
            self._traffic(store, o)
        elif t == "dhcp_server":
            self._dhcp_server(store, o)
        elif t == "lan":
            if o.get("dns"):
                k = (o["mac"], clean_str(o["dns"], 253))
                d = self.dns.get(k)
                if d:
                    d[1], d[2] = o["ts"], d[2] + 1
                else:
                    self.dns[k] = [o["ts"], o["ts"], 1]
                self.pending = True
            if o.get("ip") and o.get("src") == "arp":
                self._arp(store, o)

    def _traffic(self, store, o):
        ts = o["ts"]
        minute, hour = int(ts // 60) * 60, int(ts // 3600) * 3600
        for mac, peer, proto, port, b_out, b_in, pkts, name in o.get("items") or []:
            if store.ignore.mac(mac):
                continue
            t = self.traffic.setdefault((mac, minute), [0, 0, 0])
            t[0] += b_out
            t[1] += b_in
            t[2] += pkts
            f = self.flows.get((mac, hour, peer, proto, port))
            if f is None:
                f = self.flows[(mac, hour, peer, proto, port)] = [0, 0, 0, name]
            f[0] += b_out
            f[1] += b_in
            f[2] += pkts
            if name:
                f[3] = name
        sensor = o.get("sensor")
        for mac, ip in (o.get("hosts") or {}).items():  # senders of IP traffic are present on the LAN
            store.process({"t": "lan", "ts": ts, "mac": mac, "ip": ip, "src": "traffic", "sensor": sensor})
        self.pending = True

    def _dhcp_server(self, store, o):
        mac, ts = o["mac"], o["ts"]
        s = self.servers.get(mac)
        if s is None:
            row = store.conn.execute("SELECT ip, router, first_seen, last_seen, replies FROM dhcp_servers WHERE mac=?",
                                     (mac,)).fetchone()
            s = self.servers[mac] = list(row) if row else [o.get("ip"), None, ts, ts, 0]
        s[0], s[3], s[4] = o.get("ip") or s[0], ts, s[4] + 1
        router = o.get("router")
        if router:
            s[1] = router if isinstance(router, str) else str(router)
        self.pending = True
        store.process({"t": "lan", "ts": ts, "mac": mac, "ip": o.get("ip"), "src": "dhcp-server"})
        sec = self.ctx.security
        known = store.conn.execute("SELECT COUNT(*) FROM dhcp_servers WHERE mac != ?", (mac,)).fetchone()[0] + \
            sum(1 for m in self.servers if m != mac)
        if self.trusted and mac not in self.trusted:
            sec.finding(store, ts, f"rogue_dhcp:{mac}", "rogue_dhcp", "high", mac, None, "Rogue DHCP server",
                        f"{mac} ({o.get('ip')}) answered DHCP requests but isn't a trusted DHCP server. A rogue DHCP "
                        f"server can redirect clients' traffic (gateway/DNS hijack).", event="rogue_dhcp")
        elif not self.trusted and known:
            sec.finding(store, ts, f"multi_dhcp:{mac}", "rogue_dhcp", "medium", mac, None, "More than one DHCP server",
                        f"{mac} ({o.get('ip')}) is answering DHCP besides another server. Mark your real DHCP server "
                        f"as trusted on the LAN page.", event="rogue_dhcp")

    def _arp(self, store, o):
        ip, mac, ts = o["ip"], o["mac"], o["ts"]
        prev = self.ip_owner.get(ip)
        self.ip_owner[ip] = (mac, ts)
        if not prev or prev[0] == mac:
            return
        q = self.ip_changes[ip]
        q.append((ts, prev[0], mac))
        while q and ts - q[0][0] > ARP_WINDOW:
            q.popleft()
        gw = any(ip == (s[1] or "") for s in self.servers.values())
        if len(q) >= ARP_FLIPS or (gw and ts - prev[1] < ARP_WINDOW):
            macs = sorted({m for _, a, b in q for m in (a, b)} | {mac})
            detail = f"{ip}{' (the gateway)' if gw else ''} is being claimed by several MACs: {', '.join(macs)}. " \
                     f"This is typical of ARP spoofing / man-in-the-middle attacks."
            store._event(ts, mac, "arp_spoof", None, detail, always=True)
            self.ctx.security.finding(store, ts, f"arp_spoof:{ip}", "arp_spoof", "high", mac, None,
                                      f"ARP spoofing of {ip}", detail, event="arp_spoof")
            q.clear()
        if len(self.ip_owner) > 100_000:
            self.ip_owner.clear()

    # --------------------------------------------------------------- flush
    def reset(self, module):
        if module == "lan":
            self.traffic, self.flows, self.dns, self.servers, self.pending = {}, {}, {}, {}, False

    def flush(self, store, c):
        if not self.pending:
            return
        c.executemany("INSERT INTO lan_traffic VALUES(?,?,?,?,?) ON CONFLICT(mac, minute) DO UPDATE SET "
                      "bytes_out=bytes_out+excluded.bytes_out, bytes_in=bytes_in+excluded.bytes_in, "
                      "pkts=pkts+excluded.pkts", [(m, mi, *v) for (m, mi), v in self.traffic.items()])
        c.executemany("INSERT INTO lan_flows VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(mac, hour, peer, proto, port) DO UPDATE "
                      "SET bytes_out=bytes_out+excluded.bytes_out, bytes_in=bytes_in+excluded.bytes_in, "
                      "pkts=pkts+excluded.pkts, peer_name=COALESCE(excluded.peer_name, peer_name)",
                      [(m, h, p, pr, po, v[3], v[0], v[1], v[2]) for (m, h, p, pr, po), v in self.flows.items()])
        c.executemany("INSERT INTO lan_dns VALUES(?,?,?,?,?) ON CONFLICT(mac, name) DO UPDATE SET "
                      "last_seen=MAX(last_seen, excluded.last_seen), count=count+excluded.count",
                      [(m, n, *v) for (m, n), v in self.dns.items()])
        c.executemany("INSERT OR REPLACE INTO dhcp_servers VALUES(?,?,?,?,?,?)",
                      [(m, *v) for m, v in self.servers.items()])
        self.traffic.clear()
        self.flows.clear()
        self.dns.clear()
        self.pending = False

    def prune(self, store, c, cutoff):
        cutoff = cutoff_for(self.ctx, "lan", cutoff)
        c.execute("DELETE FROM lan_traffic WHERE minute < ?", (cutoff,))
        c.execute("DELETE FROM lan_flows WHERE hour < ?", (cutoff,))
        c.execute("DELETE FROM lan_dns WHERE last_seen < ?", (cutoff,))


# ------------------------------------------------------------------ routes
class TrustBody(BaseModel):
    mac: Mac
    trust: bool = True


def routes(ctx):
    r = APIRouter()

    def bucket_for(hours):
        return 300 if hours <= 24 else 3600

    @r.get("/api/lan")
    def overview(hours: float = 24, _=Depends(current_user)):
        now = time.time()
        since = now - hours * 3600
        b = bucket_for(hours)
        series = ctx.rows("SELECT (minute/?)*? t, SUM(bytes_out) out_b, SUM(bytes_in) in_b FROM lan_traffic "
                          "WHERE minute >= ? GROUP BY t ORDER BY t", (b, b, since))
        talkers = ctx.rows(
            "SELECT t.mac, SUM(t.bytes_out) bytes_out, SUM(t.bytes_in) bytes_in, d.ip, d.name, d.kind, d.vendor, "
            "d.ident, m.label FROM lan_traffic t LEFT JOIN devices d ON d.mac=t.mac LEFT JOIN device_meta m "
            "ON m.mac=t.mac WHERE t.minute >= ? GROUP BY t.mac ORDER BY SUM(t.bytes_out)+SUM(t.bytes_in) DESC LIMIT 25",
            (since,))
        for t in talkers:
            ctx.jsonf(t, "ident")
            t["ident"] = (t["ident"] or {}).get("label")
        peers = ctx.rows("SELECT peer, MAX(peer_name) peer_name, port, proto, SUM(bytes_out+bytes_in) bytes, "
                         "COUNT(DISTINCT mac) devices FROM lan_flows WHERE hour >= ? GROUP BY peer, proto, port "
                         "ORDER BY bytes DESC LIMIT 200", (since - 3600,))
        from .ethernet import is_private
        external = [p for p in peers if not is_private(p["peer"])][:25]
        for p in external:
            p["service"] = service(p["proto"], p["port"])
        services = {}
        for p in peers:
            k = service(p["proto"], p["port"])
            services[k] = services.get(k, 0) + p["bytes"]
        dns = ctx.rows("SELECT name, COUNT(DISTINCT mac) devices, SUM(count) queries, MAX(last_seen) last_seen FROM lan_dns "
                       "WHERE last_seen >= ? GROUP BY name ORDER BY devices DESC, queries DESC LIMIT 40", (since,))
        servers = ctx.rows("SELECT s.*, d.vendor, d.name FROM dhcp_servers s LEFT JOIN devices d ON d.mac=s.mac "
                           "ORDER BY s.last_seen DESC")
        trusted = set(ctx.settings.get("lan")["trusted_dhcp"])
        for s in servers:
            s["trusted"] = s["mac"] in trusted
        online = ctx.rows(
            "SELECT d.mac, d.kind, d.ip, d.name, d.vendor, d.dev_type, d.os, d.ident, d.last_seen, d.first_seen, "
            "m.label, m.watch, (SELECT SUM(bytes_out+bytes_in) FROM lan_traffic t WHERE t.mac=d.mac AND t.minute >= ?) "
            "bytes FROM devices d LEFT JOIN device_meta m ON m.mac=d.mac WHERE d.ip IS NOT NULL AND d.last_seen >= ? "
            "ORDER BY d.ip", (since, now - ctx.cfg.lan_session_timeout))
        for d in online:
            ctx.jsonf(d, "ident")
            d["ident"] = (d["ident"] or {}).get("label")
        online.sort(key=lambda d: tuple(int(x) if x.isdigit() else 0 for x in (d["ip"] or "").split(".")))
        return {"since": since, "now": now, "bucket": b, "series": series, "talkers": talkers, "external": external,
                "services": sorted(services.items(), key=lambda kv: -kv[1])[:12], "dns": dns, "dhcp_servers": servers,
                "online": online, "total_out": sum(s["out_b"] or 0 for s in series),
                "total_in": sum(s["in_b"] or 0 for s in series), "has_traffic": bool(series)}

    @r.get("/api/devices/{mac}/lan")
    def device_lan(mac: str, hours: float = 24, _=Depends(current_user)):
        mac = mac.lower()
        since = time.time() - hours * 3600
        b = bucket_for(hours)
        peers = ctx.rows("SELECT peer, MAX(peer_name) peer_name, proto, port, SUM(bytes_out) bytes_out, "
                         "SUM(bytes_in) bytes_in, SUM(pkts) pkts FROM lan_flows WHERE mac=? AND hour >= ? "
                         "GROUP BY peer, proto, port ORDER BY SUM(bytes_out+bytes_in) DESC LIMIT 50",
                         (mac, since - 3600))
        from .ethernet import is_private
        for p in peers:
            p["service"] = service(p["proto"], p["port"])
            p["local"] = is_private(p["peer"])
            if p["local"]:
                d = ctx.one("SELECT d.mac, d.name, m.label FROM devices d LEFT JOIN device_meta m ON m.mac=d.mac "
                            "WHERE d.ip=? LIMIT 1", (p["peer"],))
                if d:
                    p["peer_mac"], p["peer_name"] = d["mac"], d["label"] or d["name"] or p["peer_name"]
        return {
            "bucket": b,
            "series": ctx.rows("SELECT (minute/?)*? t, SUM(bytes_out) out_b, SUM(bytes_in) in_b FROM lan_traffic "
                               "WHERE mac=? AND minute >= ? GROUP BY t ORDER BY t", (b, b, mac, since)),
            "peers": peers,
            "dns": ctx.rows("SELECT name, first_seen, last_seen, count FROM lan_dns WHERE mac=? ORDER BY last_seen DESC "
                            "LIMIT 100", (mac,)),
            "dhcp_server": ctx.one("SELECT * FROM dhcp_servers WHERE mac=?", (mac,)),
        }

    @r.post("/api/lan/dhcp-trust")
    def dhcp_trust(body: TrustBody, _=Depends(require_admin)):
        cfg = ctx.settings.get("lan")
        cur = set(cfg["trusted_dhcp"])
        m = body.mac
        cur = cur | {m} if body.trust else cur - {m}
        cfg["trusted_dhcp"] = sorted(cur)
        ctx.settings.set("lan", cfg)
        if body.trust:
            for key in (f"rogue_dhcp:{m}", f"multi_dhcp:{m}"):
                ctx.execute("UPDATE findings SET status='resolved' WHERE key=?", (key,))
                ctx.security.status[key] = "resolved"
        return {"ok": True, "trusted": cfg["trusted_dhcp"]}

    return r
