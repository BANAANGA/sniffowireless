[← Back to the README](../README.md)

# Ethernet monitoring

Set `ETH_INTERFACES` to one or more wired interfaces and sniffowireless listens passively, without sending anything.

| From | It learns |
|---|---|
| **ARP** | which MAC uses which IP, so devices appear as soon as they talk |
| **DHCP** | hostname, OS fingerprint (vendor class + requested-option order, e.g. Windows, Android 14, Apple, Linux/BusyBox) and the DHCP server and gateway |
| **mDNS / Bonjour** | services (AirPlay, Google Cast, printers, HomeKit, Sonos, Hue, Home Assistant…) and model names (`MacBookPro18,3`, `Google Nest Mini`, printer models) |
| **SSDP / UPnP** | server strings (Synology DSM, Sonos, Roku, Samsung/LG TVs, FRITZ!Box, Windows…) |
| **LLDP** | switches and access points: name, model, port |
| **IP traffic** | bytes sent and received per device over time, and every conversation (peer IP, port/service) named via DNS answers |
| **DNS queries** | which domains each device looks up (plain DNS only; DNS-over-HTTPS/TLS is invisible) |

All of this feeds the existing device list, identification, presence history, alerts and statistics. Wired-only devices appear as a new **LAN** device kind. A Wi-Fi client that is also seen on the LAN stays one device and gains an IP address, hostname and traffic. The **LAN** page shows:
- devices online
- throughput over time and top talkers
- internet destinations and traffic by service
- the most looked-up domains and the DHCP servers

Each device page gets a **Network (LAN)** panel with its traffic, peers and DNS lookups.

**Security:** trust your real DHCP server on the LAN page. Any other server answering DHCP then raises a **rogue DHCP** finding and alert; without a trusted server, a second DHCP server is flagged as *medium*. An IP address claimed by changing MACs (especially the gateway's) raises **ARP spoofing**.

## Where to plug it in

| Setup | What sniffowireless sees |
|---|---|
| Ordinary switch port (e.g. the host's own NIC) | Discovery only: ARP, DHCP, mDNS, SSDP, LLDP broadcasts, plus the host's own traffic. Most devices still show up, with names and identification. |
| **Mirror / SPAN port** on a managed switch (UniFi, TP-Link Omada/Easy Smart, Netgear ProSafe, MikroTik, Cisco…) | Everything that crosses the mirrored ports. Mirror the port your router uplink is on to see all internet traffic. |
| **Network TAP** between router and switch (passive, e.g. a cheap 100 Mbit throwing-star or a gigabit TAP) | Everything between the LAN and the router. |
| On the router / firewall itself (Linux-based) | Everything it routes. |

Use a **dedicated** USB Ethernet adapter for the mirror port and give it no IP address, so the host doesn't use it for its own traffic:

```bash
sudo nmcli device set eth1 managed no   # keep NetworkManager away from it
sudo ip addr flush dev eth1
sudo ip link set eth1 up
# .env
ETH_INTERFACES=eth1
```

Packets are decoded in Python. Header parsing is a fast path, but a Raspberry Pi 4 handles roughly a few tens of thousands of packets per second, which is fine for home and small-office links. Watch the sensor's pkt/s and the *dropped* counter on the overview. Remote sensors (`SNIFFOWIRELESS_MODE=sensor`) support `ETH_INTERFACES` too.

**Privacy:** traffic and DNS logging reveal a lot about people's behaviour. Only monitor networks you're responsible for, tell the people using them, and keep `RETENTION_DAYS` short. Payloads are never stored; only byte counts, peers, ports and queried names are.
