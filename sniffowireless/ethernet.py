"""Passive Ethernet / LAN capture.

A raw AF_PACKET socket reads every frame on a wired interface. Each frame's Ethernet / IP / TCP / UDP
headers are parsed with plain struct slicing (fast path) to count bytes per device and per conversation.
Only discovery and DNS packets (ARP, DHCP, mDNS, SSDP, LLDP, DNS) are handed to scapy for full decoding.

What the sensor sees depends on where it is plugged in: a normal switch port only delivers broadcast /
multicast frames plus the host's own traffic (enough for device discovery); a mirror/SPAN port, a TAP or
running on the router shows everyone's traffic.
"""
import ipaddress
import logging
import os
import socket
import struct
import threading
import time
from collections import OrderedDict

from scapy.all import Ether, load_contrib
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP

from . import hwinfo, status

load_contrib("lldp")
from scapy.contrib.lldp import (LLDPDUPortDescription, LLDPDUPortID,  # noqa: E402
                                LLDPDUSystemDescription, LLDPDUSystemName)

log = logging.getLogger("sniffowireless.eth")

ETH_P_ALL = 0x0003
SOL_PACKET, PACKET_ADD_MEMBERSHIP, PACKET_MR_PROMISC = 263, 1, 1
DISCOVERY_UDP = {53, 67, 68, 137, 1900, 5353, 5355}
DHCP_MSG = {1: "discover", 2: "offer", 3: "request", 4: "decline", 5: "ack", 6: "nak", 7: "release", 8: "inform"}
REPORT_INTERVAL = 10       # seconds between traffic summaries
DNS_REPEAT = 600           # report the same (device, name) lookup at most this often
MAX_FLOWS = 50_000


def mac_str(b):
    return "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(b)


def is_unicast_mac(b):
    return not (b[0] & 1)


def ip_str(b):
    return socket.inet_ntop(socket.AF_INET if len(b) == 4 else socket.AF_INET6, bytes(b))


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_link_local or a.is_multicast
    except ValueError:
        return False


def _txt(rdata):
    """mDNS TXT rdata -> {key: value}."""
    out = {}
    items = rdata if isinstance(rdata, (list, tuple)) else [rdata]
    for it in items:
        s = it.decode("utf-8", "replace") if isinstance(it, bytes) else str(it)
        if "=" in s:
            k, v = s.split("=", 1)
            if k and v and len(v) < 120:
                out[k.lower()] = v
    return out


def _txt_raw(rdata):
    """mDNS TXT rdata -> {key: raw bytes}, for values that are binary (the Thread extended PAN ID)."""
    out = {}
    for it in rdata if isinstance(rdata, (list, tuple)) else [rdata]:
        b = it if isinstance(it, bytes) else str(it).encode("utf-8", "replace")
        k, sep, v = b.partition(b"=")
        if sep and k:
            out[k.decode("ascii", "replace").lower()] = v
    return out


def meshcop(raw):
    """What a Thread border router announces about its network in `_meshcop._udp` TXT records (Thread spec, MeshCoP service):
    nn network name, xp extended PAN ID (8 bytes), vn vendor name, mn model name, tv Thread version. Empty if there is no valid extended PAN ID."""
    xp = raw.get("xp")
    if not xp or len(xp) != 8:
        return {}

    def text(k, n):
        return "".join(ch for ch in raw.get(k, b"").decode("utf-8", "replace") if ch.isprintable()).strip()[:n] or None
    out = {"xp": ":".join(f"{b:02x}" for b in xp), "nn": text("nn", 16), "vn": text("vn", 32), "mn": text("mn", 32), "tv": text("tv", 12)}
    return {k: v for k, v in out.items() if v}


def _name(v):
    s = v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)
    return s.rstrip(".")


class FrameParser:
    """Turns raw frames into observations. Keeps per-conversation counters between reports."""

    def __init__(self):
        self.flows = {}             # (mac, peer ip, proto, port) -> [bytes_out, bytes_in, pkts]
        self.hosts = {}             # mac -> last seen IP (from IP traffic)
        self.dns_cache = OrderedDict()  # ip -> name, learned from DNS answers
        self.dns_seen = {}          # (mac, name) -> last reported
        self.frames = 0

    # ------------------------------------------------------------ fast path
    def frame(self, buf, n, ts, out):
        self.frames += 1
        if n < 14:
            return
        dst, src = buf[0:6], buf[6:12]
        et = (buf[12] << 8) | buf[13]
        off = 14
        if et == 0x8100 and n >= 18:  # 802.1Q VLAN tag
            et, off = (buf[16] << 8) | buf[17], 18
        if et == 0x0806 or et == 0x88CC:
            self.slow(bytes(buf[:n]), ts, out)
            return
        if et == 0x0800 and n >= off + 20:
            ihl = (buf[off] & 0x0F) * 4
            proto = buf[off + 9]
            sip, dip = bytes(buf[off + 12:off + 16]), bytes(buf[off + 16:off + 20])
            frag = ((buf[off + 6] & 0x1F) << 8) | buf[off + 7]
            l4 = off + ihl if not frag else None
        elif et == 0x86DD and n >= off + 40:
            proto = buf[off + 6]
            sip, dip = bytes(buf[off + 8:off + 24]), bytes(buf[off + 24:off + 40])
            l4 = off + 40
        else:
            return
        sport = dport = 0
        if l4 is not None and proto in (6, 17) and n >= l4 + 4:
            sport, dport = (buf[l4] << 8) | buf[l4 + 1], (buf[l4 + 2] << 8) | buf[l4 + 3]
        port = min(sport, dport) if sport and dport else 0  # the lower port is usually the service
        smac, dmac = mac_str(src), mac_str(dst)
        s_ip, d_ip = ip_str(sip), ip_str(dip)
        if is_unicast_mac(src):
            self._count(smac, d_ip, proto, port, n, 0)
            if len(sip) == 4 and s_ip != "0.0.0.0":
                self.hosts[smac] = s_ip
        if is_unicast_mac(dst):
            self._count(dmac, s_ip, proto, port, 0, n)
        if proto == 17 and (sport in DISCOVERY_UDP or dport in DISCOVERY_UDP):
            self.slow(bytes(buf[:n]), ts, out)

    def _count(self, mac, peer, proto, port, b_out, b_in):
        k = (mac, peer, proto, port)
        f = self.flows.get(k)
        if f is None:
            if len(self.flows) >= MAX_FLOWS:
                return
            f = self.flows[k] = [0, 0, 0]
        f[0] += b_out
        f[1] += b_in
        f[2] += 1

    def report(self, ts):
        """Traffic summary since the last report (one observation)."""
        items = [(m, p, pr, po, b[0], b[1], b[2], self.dns_cache.get(p)) for (m, p, pr, po), b in self.flows.items()]
        hosts = dict(self.hosts)
        self.flows.clear()
        self.hosts.clear()
        if not items and not hosts:
            return None
        return {"t": "lan_traffic", "ts": ts, "mac": "-", "items": items, "hosts": hosts}

    # ------------------------------------------------------------ slow path
    def slow(self, raw, ts, out):
        try:
            pkt = Ether(raw)
        except Exception:
            return
        src = pkt.src.lower()
        if ARP in pkt:
            a = pkt[ARP]
            if a.op in (1, 2) and a.psrc and a.psrc != "0.0.0.0":
                out.append({"t": "lan", "ts": ts, "mac": a.hwsrc.lower(), "ip": a.psrc, "src": "arp",
                            "arp_op": "reply" if a.op == 2 else "request"})
            return
        if pkt.type == 0x88CC:
            self._lldp(pkt, src, ts, out)
            return
        if DHCP in pkt and BOOTP in pkt:
            self._dhcp(pkt, src, ts, out)
            return
        if DNS not in pkt:
            ip = pkt.payload.src if hasattr(pkt.payload, "src") else None
            udp = pkt.getlayer("UDP")
            if udp is not None and 1900 in (udp.sport, udp.dport):
                self._ssdp(bytes(udp.payload), src, ip, ts, out)
            return
        udp = pkt.getlayer("UDP")
        ip = pkt.payload.src
        d = pkt[DNS]
        qd = d.qd[0] if isinstance(d.qd, list) and d.qd else (d.qd if not isinstance(d.qd, list) else None)
        if udp.sport == 5353 or udp.dport == 5353:
            self._mdns(d, src, ip, ts, out)
        elif udp.dport == 53 and not d.qr and qd is not None:
            name = _name(qd.qname).lower()
            key = (src, name)
            if name and ts - self.dns_seen.get(key, 0) > DNS_REPEAT and not name.endswith((".arpa", ".local")):
                self.dns_seen[key] = ts
                if len(self.dns_seen) > 200_000:
                    self.dns_seen.clear()
                out.append({"t": "lan", "ts": ts, "mac": src, "ip": ip, "dns": name, "src": "dns"})
        elif udp.sport == 53 and d.qr:
            for i in range(d.ancount or 0):
                try:
                    rr = d.an[i]
                except (IndexError, TypeError):
                    break
                if rr.type in (1, 28) and qd is not None:
                    self.dns_cache[str(rr.rdata)] = _name(qd.qname).lower()
            while len(self.dns_cache) > 20_000:
                self.dns_cache.popitem(last=False)

    def _dhcp(self, pkt, src, ts, out):
        b = pkt[BOOTP]
        opts = {}
        for o in pkt[DHCP].options:
            if isinstance(o, tuple) and len(o) >= 2:
                opts[o[0]] = o[1] if len(o) == 2 else list(o[1:])
        msg = DHCP_MSG.get(opts.get("message-type"), str(opts.get("message-type")))
        client = mac_str(bytes(b.chaddr[:6]))
        if b.op == 1:  # client -> server
            prl = opts.get("param_req_list")
            vendor = opts.get("vendor_class_id")
            host = opts.get("hostname")
            fp = {"dhcp": {k: v for k, v in {
                "vendor": vendor.decode("utf-8", "replace") if isinstance(vendor, bytes) else vendor,
                "prl": ",".join(str(x) for x in prl) if isinstance(prl, (list, bytes)) else None,
                "msg": msg}.items() if v}}
            out.append({"t": "lan", "ts": ts, "mac": client, "src": "dhcp",
                        "ip": opts.get("requested_addr") or (b.ciaddr if b.ciaddr != "0.0.0.0" else None),
                        "name": host.decode("utf-8", "replace").strip() if isinstance(host, bytes) else host,
                        "fp": {"lan": fp}})
        else:          # server -> client
            server_ip = opts.get("server_id") or (pkt.payload.src if hasattr(pkt.payload, "src") else None)
            out.append({"t": "dhcp_server", "ts": ts, "mac": src, "ip": server_ip, "msg": msg,
                        "client": client, "router": opts.get("router")})
            if msg == "ack" and b.yiaddr and b.yiaddr != "0.0.0.0":
                out.append({"t": "lan", "ts": ts, "mac": client, "ip": b.yiaddr, "src": "dhcp"})

    def _mdns(self, d, src, ip, ts, out):
        if not d.qr:
            return
        services, names, txt, friendly, raw = set(), set(), {}, None, {}
        rrs = []
        for sect, cnt in (("an", d.ancount), ("ar", d.arcount)):
            lst = getattr(d, sect)
            for i in range(cnt or 0):
                try:
                    rrs.append(lst[i])
                except (IndexError, TypeError):
                    break
        for rr in rrs:
            rname = _name(rr.rrname)
            if rr.type == 12:  # PTR
                target = _name(rr.rdata)
                if rname.startswith("_") and "._" in rname and rname != "_services._dns-sd._udp.local":
                    services.add(rname.replace(".local", ""))
                    inst = target.split("._")[0]
                    if inst and not friendly:
                        friendly = inst
            elif rr.type == 33:  # SRV -> host name
                names.add(_name(rr.target).replace(".local", ""))
            elif rr.type in (1, 28):
                names.add(rname.replace(".local", ""))
            elif rr.type == 16:
                txt.update(_txt(rr.rdata))
                if rname.endswith("_meshcop._udp.local"):
                    raw.update(_txt_raw(rr.rdata))
        if not (services or names or txt):
            return
        fp = {"mdns": {"services": sorted(services)[:20], "txt": {k: v for k, v in txt.items()
                                                                 if k in ("model", "md", "ty", "am", "fn", "usb_mfg",
                                                                          "usb_mdl", "manufacturer", "product")}}}
        if raw:
            mc = meshcop(raw)
            if mc:
                fp["mdns"]["meshcop"] = mc
        host = next((n for n in sorted(names) if n and not n[0].isdigit()), None)
        out.append({"t": "lan", "ts": ts, "mac": src, "ip": ip, "src": "mdns",
                    "name": txt.get("fn") or host or friendly, "fp": {"lan": fp}})

    def _ssdp(self, payload, src, ip, ts, out):
        try:
            text = payload.decode("utf-8", "replace")
        except Exception:
            return
        if not text.startswith(("NOTIFY", "HTTP/1.1 200")):
            return
        hdr = {}
        for line in text.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                hdr[k.strip().lower()] = v.strip()
        server = hdr.get("server")
        nt = hdr.get("nt") or hdr.get("st")
        if server or nt:
            out.append({"t": "lan", "ts": ts, "mac": src, "ip": ip, "src": "ssdp",
                        "fp": {"lan": {"ssdp": {"server": server[:160] if server else None,
                                                "nt": [nt[:100]] if nt else []}}}})

    def _lldp(self, pkt, src, ts, out):
        info = {}
        for cls, key in ((LLDPDUSystemName, "sysname"), (LLDPDUSystemDescription, "sysdesc"),
                         (LLDPDUPortID, "port"), (LLDPDUPortDescription, "portdesc")):
            if cls in pkt:
                layer = pkt[cls]
                val = getattr(layer, "system_name", None) or getattr(layer, "description", None) or \
                    getattr(layer, "id", None)
                if val is not None:
                    info[key] = _name(val)[:160]
        if info:
            out.append({"t": "lan", "ts": ts, "mac": src, "src": "lldp", "name": info.get("sysname"),
                        "fp": {"lan": {"lldp": info}}})


class EthernetSensor:
    def __init__(self, iface, cfg, store):
        self.iface, self.cfg, self.store = iface, cfg, store
        self.name = f"eth:{iface}"
        self.parser = FrameParser()
        self.stop = None
        status.register(self.name, type="ethernet", iface=iface, promisc=cfg.eth_promisc, **hwinfo.net(iface))

    def start(self, stop):
        self.stop = stop
        threading.Thread(target=self._loop, daemon=True, name=self.name).start()

    def _open(self):
        if not os.path.exists(f"/sys/class/net/{self.iface}"):
            raise RuntimeError(f"interface {self.iface} not found (network_mode: host?)")
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        s.bind((self.iface, 0))
        if self.cfg.eth_promisc:
            ifindex = socket.if_nametoindex(self.iface)
            s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, struct.pack("iHH8s", ifindex, PACKET_MR_PROMISC, 0, b""))
        s.settimeout(1.0)
        return s

    def _loop(self):
        while not self.stop.is_set():
            sock = None
            try:
                sock = self._open()
                status.update(self.name, state="capturing", error=None)
                self._run(sock)
            except Exception as e:
                log.error("%s: %s", self.name, e)
                status.update(self.name, state="error", error=str(e))
            finally:
                if sock:
                    sock.close()
            self.stop.wait(10)

    def _run(self, sock):
        buf = bytearray(65536)
        mv = memoryview(buf)
        next_report = time.time() + REPORT_INTERVAL
        last_frames, last_t = 0, time.time()
        p = self.parser
        while not self.stop.is_set():
            try:
                n = sock.recv_into(buf)
            except socket.timeout:
                n = 0
            now = time.time()
            if n:
                out = []
                try:
                    p.frame(mv, n, now, out)
                except Exception:
                    log.debug("frame parse failed", exc_info=True)
                for o in out:
                    self.store.put(o)
            if now >= next_report:
                r = p.report(now)
                if r:
                    self.store.put(r)
                next_report = now + REPORT_INTERVAL
                status.update(self.name, packets=p.frames, pps=round((p.frames - last_frames) / (now - last_t), 1))
                last_frames, last_t = p.frames, now
