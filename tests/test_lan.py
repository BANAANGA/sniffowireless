import time

import pytest
from scapy.all import load_contrib
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR, DNSRRSRV
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from sniffowireless.config import Config
from sniffowireless.ethernet import FrameParser
from sniffowireless.main import build

load_contrib("lldp")
from scapy.contrib.lldp import (LLDPDUChassisID, LLDPDUEndOfLLDPDU, LLDPDUPortID,  # noqa: E402
                                LLDPDUSystemDescription, LLDPDUSystemName, LLDPDUTimeToLive)

PC = "d8:bb:c1:00:00:01"
GW = "e0:28:6d:00:00:01"
NAS = "00:11:32:00:00:01"


def run(parser, pkts, ts=1000.0):
    out = []
    for p in pkts:
        raw = bytearray(bytes(p))
        parser.frame(memoryview(raw), len(raw), ts, out)
    return out


@pytest.fixture
def ctx(tmp_path):
    return build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))


def dhcp_request(mac=PC, host=b"DESKTOP-4MJ8T2Q", vendor=b"MSFT 5.0"):
    return (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) / BOOTP(op=1, chaddr=bytes.fromhex(mac.replace(":", "")) + bytes(10)) /
            DHCP(options=[("message-type", "request"), ("requested_addr", "192.168.1.23"), ("hostname", host),
                          ("vendor_class_id", vendor),
                          ("param_req_list", [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]), "end"]))


def dhcp_ack(server=GW, server_ip="192.168.1.1", client=PC):
    return (Ether(src=server, dst=client) / IP(src=server_ip, dst="192.168.1.23") / UDP(sport=67, dport=68) /
            BOOTP(op=2, yiaddr="192.168.1.23", chaddr=bytes.fromhex(client.replace(":", "")) + bytes(10)) /
            DHCP(options=[("message-type", "ack"), ("server_id", server_ip), ("router", "192.168.1.1"), "end"]))


def test_parser_discovery_protocols():
    p = FrameParser()
    arp = Ether(src=GW, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=GW, psrc="192.168.1.1", hwdst=PC, pdst="192.168.1.23")
    mdns = (Ether(src=NAS, dst="01:00:5e:00:00:fb") / IP(src="192.168.1.10", dst="224.0.0.251") / UDP(sport=5353, dport=5353) /
            DNS(qr=1, aa=1, an=DNSRR(rrname="_smb._tcp.local", type="PTR", rdata="DiskStation._smb._tcp.local") /
                DNSRR(rrname="DiskStation._device-info._tcp.local", type="TXT", rdata=[b"model=DS920+"]),
                ar=DNSRRSRV(rrname="DiskStation._smb._tcp.local", target="DiskStation.local", port=445) /
                DNSRR(rrname="DiskStation.local", type="A", rdata="192.168.1.10")))
    ssdp = (Ether(src=NAS, dst="01:00:5e:7f:ff:fa") / IP(src="192.168.1.10", dst="239.255.255.250") /
            UDP(sport=1900, dport=1900) / b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                                          b"SERVER: Synology/DSM/192.168.1.10\r\nNT: upnp:rootdevice\r\n\r\n")
    lldp = (Ether(src="24:a4:3c:00:00:99", dst="01:80:c2:00:00:0e") / LLDPDUChassisID(subtype=4, id="24:a4:3c:00:00:99") /
            LLDPDUPortID(subtype=5, id="Port 3") / LLDPDUTimeToLive(ttl=120) / LLDPDUSystemName(system_name="US-8-60W") /
            LLDPDUSystemDescription(description="UniFi Switch US-8-60W") / LLDPDUEndOfLLDPDU())
    out = run(p, [arp, dhcp_request(), dhcp_ack(), mdns, ssdp, lldp])
    by = {(o["t"], o.get("src")): o for o in out}
    assert by[("lan", "arp")]["ip"] == "192.168.1.1" and by[("lan", "arp")]["mac"] == GW
    req = [o for o in out if o.get("src") == "dhcp" and o.get("fp")][0]
    assert req["name"] == "DESKTOP-4MJ8T2Q" and req["fp"]["lan"]["dhcp"]["vendor"] == "MSFT 5.0"
    assert req["fp"]["lan"]["dhcp"]["prl"].startswith("1,3,6,15,31")
    srv = by[("dhcp_server", None)]
    assert srv["mac"] == GW and srv["ip"] == "192.168.1.1" and srv["router"] == "192.168.1.1"
    m = by[("lan", "mdns")]
    assert "_smb._tcp" in m["fp"]["lan"]["mdns"]["services"] and m["fp"]["lan"]["mdns"]["txt"]["model"] == "DS920+"
    assert m["name"] == "DiskStation"
    assert "Synology" in by[("lan", "ssdp")]["fp"]["lan"]["ssdp"]["server"]
    assert by[("lan", "lldp")]["name"] == "US-8-60W"


def test_parser_traffic_and_dns():
    p = FrameParser()
    q = (Ether(src=PC, dst=GW) / IP(src="192.168.1.23", dst="192.168.1.1") / UDP(sport=50000, dport=53) /
         DNS(rd=1, qd=DNSQR(qname="github.com")))
    a = (Ether(src=GW, dst=PC) / IP(src="192.168.1.1", dst="192.168.1.23") / UDP(sport=53, dport=50000) /
         DNS(qr=1, qd=DNSQR(qname="github.com"), an=DNSRR(rrname="github.com", rdata="140.82.121.4")))
    up = Ether(src=PC, dst=GW) / IP(src="192.168.1.23", dst="140.82.121.4") / TCP(sport=51000, dport=443) / (b"x" * 500)
    down = Ether(src=GW, dst=PC) / IP(src="140.82.121.4", dst="192.168.1.23") / TCP(sport=443, dport=51000) / (b"y" * 1400)
    out = run(p, [q, a, up, down, down])
    assert [o["dns"] for o in out if o.get("dns")] == ["github.com"]
    rep = p.report(1010.0)
    flows = {(m, peer, port): (bo, bi, name) for m, peer, pr, port, bo, bi, pk, name in rep["items"]}
    bo, bi, name = flows[(PC, "140.82.121.4", 443)]
    assert bo == len(up) and bi == 2 * len(down) and name == "github.com"
    assert rep["hosts"][PC] == "192.168.1.23"
    assert p.report(1020.0) is None  # counters reset after each report


def test_lan_store_identification_and_traffic(ctx):
    p = FrameParser()
    s = ctx.store
    t = time.time()
    for o in run(p, [dhcp_request(), dhcp_ack()], ts=t):
        s.process(o)
    up = Ether(src=PC, dst=GW) / IP(src="192.168.1.23", dst="140.82.121.4") / TCP(sport=51000, dport=443) / (b"x" * 500)
    run(p, [up], ts=t)
    s.process(p.report(t + 1))
    s.flush()
    d = ctx.one("SELECT kind, ip, name, os, dev_type FROM devices WHERE mac=?", (PC,))
    assert d == {"kind": "lan", "ip": "192.168.1.23", "name": "DESKTOP-4MJ8T2Q", "os": "Windows", "dev_type": "desktop"}
    # all of the PC's frames count, including its DHCP request
    assert ctx.one("SELECT SUM(bytes_out) b FROM lan_traffic WHERE mac=?", (PC,))["b"] == len(up) + len(dhcp_request())
    assert ctx.one("SELECT bytes_out FROM lan_flows WHERE mac=? AND port=443", (PC,))["bytes_out"] == len(up)
    assert ctx.one("SELECT ip FROM dhcp_servers WHERE mac=?", (GW,))["ip"] == "192.168.1.1"
    # the same MAC later seen over Wi-Fi becomes a Wi-Fi client, keeping its LAN details
    s.process({"t": "wifi_client", "ts": t + 2, "mac": PC, "frame": "probe", "rssi": -50})
    s.flush()
    assert ctx.one("SELECT kind, ip FROM devices WHERE mac=?", (PC,)) == {"kind": "wifi_client", "ip": "192.168.1.23"}


def test_rogue_dhcp_and_arp_spoof(ctx):
    s = ctx.store
    ctx.settings.set("lan", {"trusted_dhcp": [GW]})
    t = time.time()
    p = FrameParser()
    for o in run(p, [dhcp_ack(), dhcp_ack(server="50:c7:bf:00:00:66", server_ip="192.168.1.254")], ts=t):
        s.process(o)
    evil = "0a:00:00:00:00:66"
    for i, mac in enumerate([GW, evil, GW, evil]):
        s.process({"t": "lan", "ts": t + i, "mac": mac, "ip": "192.168.1.1", "src": "arp"})
    s.flush()
    f = {r["type"]: r for r in ctx.rows("SELECT type, mac, severity FROM findings")}
    assert f["rogue_dhcp"]["mac"] == "50:c7:bf:00:00:66" and f["rogue_dhcp"]["severity"] == "high"
    assert f["arp_spoof"]["severity"] == "high"
    assert {"rogue_dhcp", "arp_spoof"} <= {r["type"] for r in ctx.rows("SELECT type FROM events")}
