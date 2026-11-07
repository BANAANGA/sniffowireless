"""Synthetic data generator so the UI can be explored without radio hardware (DEMO_MODE=1)."""
import hashlib
import logging
import random
import time

from .config import band_of, ch_to_freq, freq_to_channel
from .identify import wifi_fingerprint
from .oui import bt_company

log = logging.getLogger("sniffowireless.demo")

def _wps(**attrs):
    ids = {"manufacturer": 0x1021, "model": 0x1023, "model_number": 0x1024, "device_name": 0x1011}
    out = b""
    for k, v in attrs.items():
        if k == "category":
            val = v[0].to_bytes(2, "big") + bytes.fromhex("0050f204") + v[1].to_bytes(2, "big")
            out += (0x1054).to_bytes(2, "big") + len(val).to_bytes(2, "big") + val
        else:
            out += ids[k].to_bytes(2, "big") + len(v).to_bytes(2, "big") + v.encode()
    return out


def wifi_fp(gen, ss=1, width=20, vendors=(), wfa=(), wps=None, base=(1, 50, 127)):
    """Build raw 802.11 capability elements like a real device sends and run the real parser on them."""
    elts = [(eid, b"\x00" * 8) for eid in base]
    if gen and gen >= 4:
        mcs = bytes([0xFF] * ss + [0] * (16 - ss))
        elts.append((45, (0x0002 if width >= 40 else 0).to_bytes(2, "little") + b"\x17" + mcs + b"\x00" * 7))
    if gen and gen >= 5:
        mcs_map = sum((2 if i < ss else 3) << (2 * i) for i in range(8))
        elts.append((191, ((1 if width >= 160 else 0) << 2).to_bytes(4, "little") + mcs_map.to_bytes(2, "little")
                     + b"\x00" * 6))
    if gen and gen >= 6:
        phy0 = 0x06 | (0x08 if width >= 160 else 0)
        mcs_map = sum((2 if i < ss else 3) << (2 * i) for i in range(8))
        elts.append((255, bytes([35]) + b"\x00" * 6 + bytes([phy0]) + b"\x00" * 10 + mcs_map.to_bytes(2, "little")))
    if gen and gen >= 7:
        elts.append((255, bytes([108]) + b"\x00\x00" + bytes([0x02 if width >= 320 else 0]) + b"\x00" * 8))
    for v in vendors:
        oui, vtype = v.split("/") if "/" in v else (v, "1")
        elts.append((221, bytes.fromhex(oui.replace(":", "")) + bytes([int(vtype)]) + b"\x00\x01"))
    for t in wfa:
        elts.append((221, bytes.fromhex("506f9a") + bytes([t]) + b"\x00"))
    if wps:
        elts.append((221, bytes.fromhex("0050f204") + _wps(**wps)))
    return wifi_fingerprint(elts)


APPLE_PHONE = dict(gen=6, ss=2, width=80, vendors=("00:17:f2/10", "00:10:18/2", "00:50:f2/2"))
ANDROID_PHONE = dict(gen=6, ss=2, width=80, vendors=("8c:fd:f0/1", "00:50:f2/2"), wfa=(0x09, 0x16))
WINDOWS_PC = dict(gen=6, ss=2, width=160, vendors=("00:50:f2/2",), wfa=(0x09,), base=(1, 50, 59, 127))
# per-MAC Wi-Fi fingerprints (clients: probe/assoc capabilities, APs: beacon capabilities)
WIFI_FPS = {
    "a4:83:e7:01:00:01": APPLE_PHONE,
    "a4:83:e7:01:00:02": dict(gen=6, ss=2, width=80, vendors=("00:17:f2/10", "00:10:18/2"), base=(1, 50, 59, 127)),
    "5c:0a:5b:01:00:03": dict(ANDROID_PHONE, vendors=("00:00:f0/1", "8c:fd:f0/1")),
    "a0:a8:cd:01:00:04": dict(WINDOWS_PC, wps=dict(device_name="LAPTOP-8K3J2QH9", category=(1, 5))),
    "b8:27:eb:01:00:05": dict(gen=5, ss=1, width=80, vendors=("00:10:18/2",)),
    "24:0a:c4:01:00:06": dict(gen=4, ss=1, width=20),
    "24:0a:c4:01:00:07": dict(gen=4, ss=1, width=20),
    "fc:65:de:01:00:08": dict(gen=5, ss=2, width=80, vendors=("00:0c:e7/4",)),
    "5c:aa:fd:01:00:09": dict(gen=5, ss=2, width=80, vendors=("00:03:7f/1",)),
    "f4:f5:d8:01:00:0a": dict(gen=5, ss=1, width=80, vendors=("00:10:18/2",)),
    "da:4e:91:01:00:0b": APPLE_PHONE,
    "3e:12:aa:01:00:0c": ANDROID_PHONE,
    "8c:85:90:01:00:0d": dict(gen=5, ss=2, width=80, vendors=("00:17:f2/10", "00:10:18/2")),
    "a0:a8:cd:01:00:0e": dict(gen=5, ss=2, width=80, wfa=(0x09,), wps=dict(device_name="DESKTOP-4MJ8T2Q",
                                                                          category=(1, 6))),
    "5c:0a:5b:01:00:0f": dict(gen=6, ss=2, width=80, vendors=("00:00:f0/1",), wfa=(0x09,),
                              wps=dict(manufacturer="Samsung Electronics", model="QE55Q80T",
                                       device_name="[TV] Samsung Q80 Series (55)", category=(7, 1))),
    # access points
    "24:a4:3c:10:00:01": dict(gen=6, ss=2, width=40),
    "24:a4:3c:10:00:02": dict(gen=6, ss=4, width=160),
    "24:a4:3c:10:00:09": dict(gen=7, ss=2, width=320),
    "50:c7:bf:20:00:03": dict(gen=4, ss=2, width=40, vendors=("00:e0:4c/2",),
                              wps=dict(manufacturer="TP-Link", model="TL-WR841N", category=(6, 1))),
    "a0:40:a0:30:00:04": dict(gen=5, ss=4, width=80, wps=dict(manufacturer="Arcadyan Technology Corporation",
                                                              model="VRV9517", category=(6, 1))),
    "a0:40:a0:30:00:05": dict(gen=6, ss=4, width=160),
    "00:1d:7e:40:00:06": dict(gen=None, wps=dict(manufacturer="Linksys", model="WRT54GL", category=(6, 1))),
    "50:c7:bf:20:00:07": dict(gen=4, ss=1, width=20),
    "f4:f5:d8:50:00:08": dict(gen=5, ss=2, width=80),
    "9c:7b:ef:60:00:0a": dict(gen=4, ss=1, width=20, wfa=(0x09,),
                              wps=dict(manufacturer="HP", model="OfficeJet Pro 9010 series", category=(3, 1))),
}
WIFI_FPS = {k: wifi_fp(**v) for k, v in WIFI_FPS.items()}
# random-MAC passers-by fall into three device families, showing probe-fingerprint grouping
PASSER_FPS = [WIFI_FPS["a4:83:e7:01:00:01"], WIFI_FPS["3e:12:aa:01:00:0c"], wifi_fp(**WINDOWS_PC)]

BLE_FPS = {
    "4c:11:aa:02:00:01": {"company": 0x004C, "apple": [0x07], "apple_model": 0x2014},
    "c9:22:bb:02:00:02": {"company": 0x0075, "ext_adv": True},
    "e1:33:cc:02:00:03": {"company": 0x038F, "uuids": ["fe95"]},
    "d4:44:dd:02:00:05": {"uuids": ["feed"]},
    "f0:55:ee:02:00:06": {"company": 0x01DA, "uuids": ["1812"]},
    "4a:66:ff:02:00:07": {"company": 0x004C, "apple": [0x0C, 0x10]},
    "5b:77:00:02:00:08": {"company": 0x0006, "ms_type": 15},
    "6c:88:11:02:00:09": {"company": 0x004C, "apple": [0x12]},
    "cb:99:22:02:00:0a": {"company": 0x0499, "ext_adv": True},
    "7b:4f:3a:02:00:0b": {"company": 0x004C, "apple": [0x12]},
    "6e:11:aa:02:00:0c": {"company": 0x004C, "apple": [0x0C, 0x10]},  # unknown AirTag following Alex every other day
}

APS = [
    ("24:a4:3c:10:00:01", "HomeNet", 1, "WPA2/PSK", -42, "Ubiquiti"),
    ("24:a4:3c:10:00:02", "HomeNet", 36, "WPA2/PSK", -55, "Ubiquiti"),
    ("50:c7:bf:20:00:03", "HomeNet-IoT", 6, "WPA2/PSK", -48, "TP-Link"),
    ("a0:40:a0:30:00:04", "Vodafone-7F2A", 11, "WPA2/PSK,WPA3/SAE", -71, "Netgear"),
    ("a0:40:a0:30:00:05", "Ziggo5G-Neighbour", 44, "WPA3/SAE", -78, "Netgear"),
    ("00:1d:7e:40:00:06", "Linksys", 11, "OPN", -83, "Cisco-Linksys"),
    ("50:c7:bf:20:00:07", "", 6, "WPA2/PSK", -66, "TP-Link"),
    ("f4:f5:d8:50:00:08", "Bakery Guest", 1, "OPN", -80, "Google"),
    ("24:a4:3c:10:00:09", "HomeNet", ("6", 37), "WPA3/SAE", -58, "Ubiquiti"),
    ("9c:7b:ef:60:00:0a", "DIRECT-4F-HP OfficeJet Pro 9010", 6, "WPA2/PSK", -69, "Hewlett Packard"),
    ("e0:63:da:70:00:0b", "Buren-5G", 100, "WPA2/PSK", -74, "Ubiquiti"),  # on a DFS channel: radar now and then
]
DFS_AP = "e0:63:da:70:00:0b"


def dfs_state(t):
    """Demo radar: in some hours the DFS neighbour hears radar at :10, announces a switch to 36 (or just leaves),
    sits out the 30-minute non-occupancy period and returns to channel 100 at :45. -> (channel, csa or None)"""
    hour, minute = int(t // 3600), int(t % 3600 // 60)
    if _h("radar", hour) % 5 or not 10 <= minute < 45:
        return 100, None
    if minute == 10:
        return 100, ({"mode": 1, "new_channel": 36, "count": 5} if _h("csa", hour) % 3 else None)
    return 36, None


def _freq(ch):
    return ch_to_freq(ch[1], ch[0]) if isinstance(ch, tuple) else ch_to_freq(ch)


def _radio(ch):
    f = _freq(ch)
    return {"freq": f, "channel": freq_to_channel(f), "band": band_of(f)}

# mac, vendor, schedule, preferred AP index(es), base rssi, probes
CLIENTS = [
    ("a4:83:e7:01:00:01", "Apple", "resident", (0, 1, 8), -50, ["HomeNet", "Office-WLAN"]),
    ("a4:83:e7:01:00:02", "Apple", "worker", (0, 1), -58, ["HomeNet", "eduroam"]),
    ("5c:0a:5b:01:00:03", "Samsung", "evening", (0, 1), -61, ["HomeNet"]),
    ("a0:a8:cd:01:00:04", "Intel", "worker", (1, 8), -47, ["HomeNet", "KPN"]),
    ("b8:27:eb:01:00:05", "Raspberry Pi", "always", (0,), -39, []),
    ("24:0a:c4:01:00:06", "Espressif", "always", (2,), -52, []),
    ("24:0a:c4:01:00:07", "Espressif", "always", (2,), -63, []),
    ("fc:65:de:01:00:08", "Amazon", "always", (2,), -57, []),
    ("5c:aa:fd:01:00:09", "Sonos", "always", (1,), -49, []),
    ("f4:f5:d8:01:00:0a", "Google", "always", (2,), -60, []),
    ("da:4e:91:01:00:0b", None, "visitor", (0,), -64, ["HomeNet", "iPhone van Sam"]),
    ("3e:12:aa:01:00:0c", None, "evening", (3,), -74, ["Vodafone-7F2A"]),
    ("8c:85:90:01:00:0d", "Apple", "neighbour", (3,), -76, ["Vodafone-7F2A"]),
    ("a0:a8:cd:01:00:0e", "Intel", "neighbour", (4,), -80, ["Ziggo5G-Neighbour"]),
    ("5c:0a:5b:01:00:0f", "Samsung", "evening", (2,), -62, []),
]

BLE = [
    ("4c:11:aa:02:00:01", "AirPods Pro", 0x004C, "with:a4:83:e7:01:00:01", -60, "random-static", "audio sink"),
    ("c9:22:bb:02:00:02", "Galaxy Watch5", 0x0075, "with:5c:0a:5b:01:00:03", -66, "random-static", "watch"),
    ("e1:33:cc:02:00:03", "Mi Smart Band 7", 0x038F, "with:a0:a8:cd:01:00:04", -71, "random-static", "watch"),
    ("a4:c1:38:02:00:04", "GVH5075_8A1C", 0x04F7, "always", -68, "public", "thermometer"),
    ("d4:44:dd:02:00:05", "Tile", 0x00ED, "always", -82, "random-static", "tag"),
    ("f0:55:ee:02:00:06", "MX Keys", 0x01DA, "worker", -57, "random-static", "HID"),
    ("4a:66:ff:02:00:07", None, 0x004C, "passer", -85, "random-resolvable", None),
    ("5b:77:00:02:00:08", None, 0x0006, "passer", -88, "random-resolvable", None),
    ("6c:88:11:02:00:09", None, 0x004C, "visitor", -73, "random-resolvable", "phone"),
    ("cb:99:22:02:00:0a", "Ruuvi 3F2C", 0x0499, "always", -75, "random-static", "sensor"),
    ("7b:4f:3a:02:00:0b", None, 0x004C, "follow:5c:0a:5b:01:00:03", -74, "random-resolvable", None),
    ("6e:11:aa:02:00:0c", None, 0x004C, "with:a4:83:e7:01:00:01", -58, "random-static", None),   # Sam's iPhone (BLE)
    ("f2:5c:77:02:00:0d", "ES3-4F2A1C", 0x0000, "with:a0:a8:cd:01:00:04", -72, "random-static", "cycling sensor"),
]

CLASSIC = [
    ("00:1b:66:03:00:01", "Sennheiser MOMENTUM 4", "evening", -59, "audio/video", True, "0x240418"),
    ("00:1c:d7:03:00:02", "Car Multimedia", "worker", -80, "audio/video", False, "0x200420"),
    ("ac:bc:32:03:00:03", "MacBook Pro", "with:a4:83:e7:01:00:02", -54, "computer", False, "0x5a010c"),
    ("5c:0a:5b:01:00:04", "Galaxy S23", "with:5c:0a:5b:01:00:03", -63, "phone", False, "0x5a020c"),
]


# pan, address, channel, frames per minute (up to), protocol hint index, frame type bits, rssi
ZIGBEE_RADIOS = [
    (0x1a62, "0x0000", 15, 40, 3, 0b0011, -51), (0x1a62, "0x3f21", 15, 30, 3, 0b0010, -60),
    (0x1a62, "0x8a10", 15, 12, 3, 0b0010, -68), (0x1a62, "00:12:4b:00:25:7c:11:9e", 15, 2, 3, 0b1000, -74),
    (0xc3d4, "04:cd:15:ff:fe:6b:20:7a", 20, 3, 1, 0b0010, -77), (0xc3d4, "0x0001", 20, 6, 1, 0b0010, -70),
    (0x4e20, "0x7c00", 25, 14, 2, 0b0010, -82),
]


def _h(*parts):
    return int(hashlib.md5("|".join(map(str, parts)).encode()).hexdigest()[:8], 16)


def present(sched, mac, t):
    """Deterministic presence model for a schedule at epoch time t (local ~= UTC+1)."""
    lt = t + 3600
    day, hour = int(lt // 86400), (lt % 86400) / 3600
    weekday = (day + 3) % 7
    r = _h(mac, day) % 1000 / 1000.0
    if sched.startswith("with:"):  # worn/carried together with another device
        target = sched[5:]
        return present(next(c[2] for c in CLIENTS if c[0] == target), target, t)
    if sched.startswith("follow:"):  # tag carried by someone else's device, on even days
        target = sched[7:]
        tsched = next(c[2] for c in CLIENTS if c[0] == target)
        return present(tsched, target, t) and day % 2 == 0
    if sched == "always":
        return _h(mac, int(t // 1800)) % 50 != 0  # occasional short drop-out
    if sched == "resident":
        return not (8.5 + r < hour < 17.5 + r) or weekday >= 5
    if sched == "worker":
        return weekday < 5 and 8.0 + r < hour < 17.0 + r * 2
    if sched == "evening":
        return 17.5 + r < hour or hour < 0.5 + r
    if sched == "neighbour":
        return 7 + r * 3 < hour < 23
    if sched == "visitor":
        return r < 0.4 and 13 + r * 10 < hour < 17 + r * 10
    if sched == "passer":
        return _h(mac, int(t // 600)) % 9 == 0
    return False


# ---------------------------------------------------------------- multi-sensor / rooms / security demo
SENSORS = [("local", "This server", "Hallway", 0.50, 0.78), ("living-room", "Living room sensor", "Living room", 0.24, 0.32),
           ("office", "Office sensor", "Office", 0.78, 0.30)]
ROOMS = ["Hallway", "Living room", "Office"]
FIXED_ROOMS = {  # stationary devices
    "24:a4:3c:10:00:01": "Living room", "24:a4:3c:10:00:02": "Office", "24:a4:3c:10:00:09": "Hallway",
    "50:c7:bf:20:00:03": "Hallway", "b8:27:eb:01:00:05": "Office", "24:0a:c4:01:00:06": "Living room",
    "24:0a:c4:01:00:07": "Office", "fc:65:de:01:00:08": "Living room", "5c:aa:fd:01:00:09": "Living room",
    "f4:f5:d8:01:00:0a": "Hallway", "5c:0a:5b:01:00:0f": "Living room", "a4:c1:38:02:00:04": "Office",
    "cb:99:22:02:00:0a": "Living room", "d4:44:dd:02:00:05": "Hallway", "f0:55:ee:02:00:06": "Office",
}
MOBILE = {"a4:83:e7:01:00:01", "4c:11:aa:02:00:01", "00:1b:66:03:00:01", "5c:0a:5b:01:00:03", "c9:22:bb:02:00:02",
          "a0:a8:cd:01:00:04", "a4:83:e7:01:00:02", "e1:33:cc:02:00:03", "ac:bc:32:03:00:03", "da:4e:91:01:00:0b"}
CARRIED_BY = {"4c:11:aa:02:00:01": "a4:83:e7:01:00:01", "00:1b:66:03:00:01": "a4:83:e7:01:00:01",
              "c9:22:bb:02:00:02": "5c:0a:5b:01:00:03", "e1:33:cc:02:00:03": "a0:a8:cd:01:00:04"}
GROUPS = [("Sam", 1, {"a4:83:e7:01:00:01": "Sam's iPhone", "4c:11:aa:02:00:01": "Sam's AirPods",
                      "00:1b:66:03:00:01": "Sam's headphones"}),
          ("Alex", 0, {"5c:0a:5b:01:00:03": "Alex's Galaxy", "c9:22:bb:02:00:02": "Alex's watch"}),
          ("Robin", 0, {"a0:a8:cd:01:00:04": "Robin's work laptop", "a4:83:e7:01:00:02": "Robin's MacBook",
                        "e1:33:cc:02:00:03": "Robin's band", "ac:bc:32:03:00:03": "Robin's MacBook (BT)"})]
LABELS = {"b8:27:eb:01:00:05": "Pi-hole", "24:0a:c4:01:00:06": "Smart plug (kitchen)",
          "24:0a:c4:01:00:07": "Smart plug (desk lamp)", "fc:65:de:01:00:08": "Echo Dot",
          "5c:aa:fd:01:00:09": "Sonos One", "f4:f5:d8:01:00:0a": "Nest Mini", "5c:0a:5b:01:00:0f": "Living room TV",
          "a4:c1:38:02:00:04": "Thermometer office", "cb:99:22:02:00:0a": "Ruuvi living room",
          "f0:55:ee:02:00:06": "Desk keyboard", "d4:44:dd:02:00:05": "Keys (Tile)"}
EVIL_TWIN = "0a:1b:2c:66:00:01"
KARMA = "0a:13:37:00:00:01"
CHANNELS = [(1, "2.4", 0.32), (6, "2.4", 0.55), (11, "2.4", 0.41), (36, "5", 0.16), (44, "5", 0.11),
            (149, "5", 0.04), (37, "6", 0.03)]
FLOORPLAN_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 640" width="1000" height="640">
<rect width="1000" height="640" fill="#111316"/>
<g fill="none" stroke="#3a3f47" stroke-width="6">
<rect x="20" y="20" width="960" height="600" rx="4"/><line x1="520" y1="20" x2="520" y2="400"/>
<line x1="20" y1="400" x2="430" y2="400"/><line x1="610" y1="400" x2="980" y2="400"/>
<line x1="300" y1="400" x2="300" y2="620"/><line x1="700" y1="400" x2="700" y2="620"/></g>
<g fill="#5b6068" font-family="sans-serif" font-size="22"><text x="50" y="60">Living room</text>
<text x="550" y="60">Office</text><text x="330" y="440">Hallway</text><text x="50" y="440">Kitchen</text>
<text x="730" y="440">Bedroom</text></g></svg>"""


# ---------------------------------------------------------------- LAN / Ethernet demo
GW = "e0:28:6d:00:00:01"
APPLE_PRL = "1,121,3,6,15,108,114,119,252,95,44,46"
WIN_PRL = "1,3,6,15,31,33,43,44,46,47,119,121,249,252"
LINUX_PRL = "1,28,2,3,15,6,119,12,44,47,26,121,42"
DESTS = {  # name -> (ip, dns name, port, proto, KB in per active minute, KB out)
    "netflix": ("45.57.90.1", "nflxvideo.net", 443, 6, 28000, 300), "youtube": ("142.250.179.14", "googlevideo.com", 443, 17, 9000, 200),
    "icloud": ("17.248.190.1", "icloud.com", 443, 6, 300, 120), "push": ("17.57.144.20", "courier.push.apple.com", 5223, 6, 4, 3),
    "whatsapp": ("157.240.201.60", "whatsapp.net", 443, 6, 80, 40), "spotify": ("35.186.224.25", "audio-ak.spotifycdn.com", 443, 6, 1200, 30),
    "alexa": ("52.94.233.129", "avs-alexa-eu.amazon.com", 443, 6, 6, 4), "google": ("142.250.179.196", "www.google.com", 443, 17, 200, 40),
    "github": ("140.82.121.4", "github.com", 443, 6, 400, 150), "office": ("52.113.194.132", "teams.microsoft.com", 443, 17, 1500, 1100),
    "windowsupdate": ("13.107.4.50", "download.windowsupdate.com", 80, 6, 2500, 20), "quickconnect": ("52.28.104.1", "quickconnect.to", 443, 6, 15, 10),
    "tuya": ("3.122.66.79", "a1.tuyaeu.com", 8883, 6, 1, 1), "ntp": ("162.159.200.123", "pool.ntp.org", 123, 17, 1, 1),
    "hue": ("52.57.88.10", "diagnostics.meethue.com", 443, 6, 2, 2), "steam": ("155.133.248.34", "cache1-ams1.steamcontent.com", 80, 6, 20000, 300),
    "psn": ("23.32.165.1", "np.playstation.net", 443, 6, 3000, 200), "dns": ("9.9.9.9", "dns.quad9.net", 53, 17, 3, 2),
}
WIRED = [  # mac, ip, hostname, schedule, lan fingerprint, destinations
    (GW, "192.168.1.1", "fritz.box", "always", {"ssdp": {"server": "FRITZ!Box 7590 UPnP/1.0 AVM FRITZ!Box 7590 154.07.57",
                                                          "nt": ["urn:schemas-upnp-org:device:InternetGatewayDevice:2"]}}, ["dns", "ntp"]),
    ("24:a4:3c:00:00:99", "192.168.1.2", None, "always", {"lldp": {"sysname": "US-8-60W", "sysdesc": "UniFi Switch US-8-60W, 6.6.55",
                                                                  "port": "Port 1"}}, []),
    ("00:11:32:00:00:01", "192.168.1.10", "DiskStation", "always", {"mdns": {"services": ["_smb._tcp", "_afpovertcp._tcp", "_http._tcp"],
                                                                             "txt": {"model": "DS920+"}},
                                                                    "ssdp": {"server": "Synology/DSM/192.168.1.10"}}, ["quickconnect", "ntp"]),
    ("d8:bb:c1:00:00:01", "192.168.1.20", "GAMING-PC", "evening", {"dhcp": {"vendor": "MSFT 5.0", "prl": WIN_PRL}},
     ["steam", "windowsupdate", "google"]),
    ("00:17:88:00:00:01", "192.168.1.40", "Philips-hue", "always", {"mdns": {"services": ["_hue._tcp", "_hap._tcp"],
                                                                              "txt": {"md": "BSB002"}}}, ["hue"]),
    ("00:80:77:00:00:01", "192.168.1.41", "BRW008077000001", "always", {"mdns": {"services": ["_ipp._tcp", "_uscan._tcp", "_printer._tcp"],
                                                                                 "txt": {"ty": "Brother HL-L2350DW series", "usb_mfg": "Brother"}}}, []),
    ("dc:a6:32:00:00:01", "192.168.1.42", "homeassistant", "always", {"dhcp": {"prl": LINUX_PRL},
                                                                      "mdns": {"services": ["_home-assistant._tcp", "_ssh._tcp"]}}, ["tuya", "github"]),
    ("bc:33:29:00:00:01", "192.168.1.43", "PS5-417", "evening", {"dhcp": {"vendor": "PS5"}}, ["psn"]),
]
WIFI_LAN = {  # Wi-Fi clients bridged onto the LAN: ip, hostname, fingerprint, destinations
    "a4:83:e7:01:00:01": ("192.168.1.21", "Sams-iPhone", {"dhcp": {"prl": APPLE_PRL}, "mdns": {"services": ["_companion-link._tcp"], "txt": {"model": "iPhone15,2"}}},
                          ["icloud", "push", "whatsapp", "youtube", "spotify"]),
    "a4:83:e7:01:00:02": ("192.168.1.24", "Robins-MacBook-Pro", {"dhcp": {"prl": APPLE_PRL}, "mdns": {"services": ["_companion-link._tcp"], "txt": {"model": "MacBookPro18,3"}}},
                          ["icloud", "github", "push", "google"]),
    "5c:0a:5b:01:00:03": ("192.168.1.22", "Galaxy-S23", {"dhcp": {"vendor": "android-dhcp-14", "prl": "1,3,6,15,26,28,51,58,59,43,114,108"}},
                          ["whatsapp", "youtube", "google"]),
    "a0:a8:cd:01:00:04": ("192.168.1.23", "LAPTOP-8K3J2QH9", {"dhcp": {"vendor": "MSFT 5.0", "prl": WIN_PRL}}, ["office", "github", "windowsupdate"]),
    "fc:65:de:01:00:08": ("192.168.1.30", "amazon-3f2a1c", {"dhcp": {"vendor": "udhcp 1.31.1"}}, ["alexa", "spotify"]),
    "5c:aa:fd:01:00:09": ("192.168.1.31", "SonosZP", {"mdns": {"services": ["_sonos._tcp", "_spotify-connect._tcp"]},
                                                     "ssdp": {"server": "Linux UPnP/1.0 Sonos/79.1-52010 (ZPS27)"}}, ["spotify"]),
    "f4:f5:d8:01:00:0a": ("192.168.1.32", "Google-Nest-Mini", {"mdns": {"services": ["_googlecast._tcp"], "txt": {"md": "Google Nest Mini"}}}, ["google"]),
    "5c:0a:5b:01:00:0f": ("192.168.1.33", "Samsung-TV", {"ssdp": {"server": "SAMSUNG-Linux/4.1, UPnP/1.0, Samsung UPnP SDK/1.0",
                                                                  "nt": ["urn:schemas-upnp-org:device:MediaRenderer:1"]}}, ["netflix", "youtube"]),
    "b8:27:eb:01:00:05": ("192.168.1.5", "pihole", {"dhcp": {"vendor": "dhcpcd-9.4.1", "prl": LINUX_PRL}}, ["dns", "ntp"]),
}
LOCAL_FLOWS = [("d8:bb:c1:00:00:01", "192.168.1.10", 445, 6, 4000, 600), ("5c:0a:5b:01:00:0f", "192.168.1.10", 32400, 6, 6000, 100),
               ("dc:a6:32:00:00:01", "192.168.1.40", 80, 6, 3, 2)]


def room_of(mac, t):
    if mac in CARRIED_BY:
        return room_of(CARRIED_BY[mac], t)
    if mac in FIXED_ROOMS:
        return FIXED_ROOMS[mac]
    return ROOMS[_h(mac, int(t // 1500)) % 3]


def pen(room, sensor_room):
    return 0 if room == sensor_room else -13 - (_h(room, sensor_room) % 6)


class DemoGenerator:
    def __init__(self, cfg, store, ctx=None):
        self.cfg, self.store, self.ctx = cfg, store, ctx
        self.rng = random.Random(42)
        if ctx:
            self.seed()
        self.passers = [f"{0x02 | (i * 4 & 0xfc):02x}:{self.rng.randrange(256):02x}:{self.rng.randrange(256):02x}:"
                        f"9{i % 10}:{self.rng.randrange(256):02x}:{self.rng.randrange(256):02x}" for i in range(40)]

    def _rssi(self, base):
        return int(base + self.rng.gauss(0, 3))

    def observations(self, t):
        rng = self.rng
        out = []
        for mac, ssid, ch, enc, base, vendor in APS:
            csa = None
            if mac == DFS_AP:
                ch, csa = dfs_state(t)
            out.append({"csa": csa, "t": "wifi_ap", "ts": t + rng.random() * 50, "mac": mac, "ssid": ssid or None,
                        **_radio(ch), "enc": enc, "rssi": self._rssi(base), "vendor": vendor,
                        "extra": {"hidden": True} if not ssid else None,
                        "fp": {"wifi": WIFI_FPS[mac], "src": "beacon"} if mac in WIFI_FPS else None})
        for mac, vendor, sched, aps, base, probes in CLIENTS:
            if not present(sched, mac, t):
                continue
            ap_i = aps[(_h(mac, int(t // 5400)) % len(aps))] if len(aps) > 1 else aps[0]
            bssid = APS[ap_i][0]
            fp = WIFI_FPS.get(mac)
            for n in range(rng.randint(2, 6)):
                out.append({"t": "wifi_client", "ts": t + rng.random() * 55, "mac": mac, "bssid": bssid,
                            "frame": "data", "rssi": self._rssi(base), **_radio(APS[ap_i][2]), "vendor": vendor,
                            "fp": {"wifi": fp, "src": "assoc"} if fp and n == 0 else None})
            if probes and rng.random() < 0.05:
                out.append({"t": "wifi_client", "ts": t + rng.random() * 55, "mac": mac, "frame": "probe",
                            "probe": rng.choice(probes), "rssi": self._rssi(base), "vendor": vendor,
                            "fp": {"wifi": fp, "src": "probe"} if fp else None})
        for i, mac in enumerate(self.passers):
            if _h(mac, int(t // 900)) % 25 == 0 and (self.ctx is None or int(t // 60) % 15 == i % 15):
                out.append({"t": "wifi_client", "ts": t + rng.random() * 55, "mac": mac, "frame": "probe",
                            "probe": rng.choice([None, None, "Starbucks", "KPN", "eduroam", "NS WiFi", "HomeNet"]),
                            "rssi": self._rssi(-82), "fp": {"wifi": PASSER_FPS[i % 3], "src": "probe"}})
        for mac, name, cid, sched, base, atype, app in BLE:
            if not present(sched, mac, t):
                continue
            for n in range(rng.randint(3, 10)):
                out.append({"t": "bt", "kind": "ble", "fp": {"ble": BLE_FPS[mac]} if mac in BLE_FPS and n == 0 else None, "ts": t + rng.random() * 55, "mac": mac, "name": name,
                            "rssi": self._rssi(base), "randomized": atype.startswith("random-") and
                            atype != "random-static", "addr_random": atype != "public",
                            "vendor": (bt_company(cid) if cid else None) if atype != "public" else "Govee",
                            "extra": {"addr_type": atype, "company": bt_company(cid) if cid else None, "appearance": app,
                                      "connectable": True}})
        minute = int(t // 60)
        for mac, name, sched, base, cls, connects, cod in CLASSIC:
            if not present(sched, mac, t):
                continue
            out.append({"t": "bt", "kind": "bt_classic", "ts": t + 1, "mac": mac, "name": name,
                        "rssi": self._rssi(base), "randomized": False, "extra": {"class": cls, "cod": cod}})
        if _h("deauth", int(t // 3600)) % 11 == 0 and minute % 60 < 3:
            out.append({"t": "event", "ts": t + 5, "mac": APS[5][0], "type": "deauth_broadcast",
                        "detail": "deauth to ff:ff:ff:ff:ff:ff reason 7"})
        if self.ctx:
            out += self.extras(t, out)
        out.sort(key=lambda o: o["ts"])
        return out

    def _bt_connections(self, t, prev):
        """Simulate the headphones connecting to the sensor's own adapter in the evening."""
        out = []
        for mac, name, sched, base, cls, connects, cod in CLASSIC:
            if not connects:
                continue
            now = present(sched, mac, t) and (_h(mac, int(t // 2700)) % 3 != 0)
            if now != prev.get(mac, False):
                out.append({"t": "bt_conn", "kind": "bt_classic", "ts": t, "mac": mac, "connected": now,
                            "peer": "hci0", "detail": "ACL link" if now else "reason 0x13"})
                prev[mac] = now
        return out

    def seed(self):
        """Pre-configure the admin features (my networks, labels, groups, sensors, floor plan) once."""
        import os
        from contextlib import closing

        from .manage import apply_ignore, apply_meta
        ctx = self.ctx
        if ctx.settings.get("networks")["ssids"]:
            return
        ctx.settings.set("lan", {"trusted_dhcp": [GW]})
        ctx.settings.set("investigate", {"ssids": [
            {"ssid": "Linksys", "note": "Open network next door; check which of our devices join it", "added": time.time()},
            {"ssid": "Starbucks", "note": "Name used by a KARMA-style hotspot nearby", "added": time.time()}]})
        ctx.settings.set("networks", {"ssids": ["HomeNet", "HomeNet-IoT"], "trusted_bssids": [
            "24:a4:3c:10:00:01", "24:a4:3c:10:00:02", "24:a4:3c:10:00:09", "50:c7:bf:20:00:03"]})
        now = time.time()
        with closing(ctx.wdb()) as c:
            for name, watch, members in GROUPS:
                gid = c.execute("INSERT INTO groups(name, kind, watch, created) VALUES(?,?,?,?)",
                                (name, "person", watch, now)).lastrowid
                for mac, label in members.items():
                    c.execute("INSERT OR REPLACE INTO device_meta(mac, label, known, watch, group_id, updated) "
                              "VALUES(?,?,1,?,?,?)", (mac, label, watch, gid, now))
            for mac, label in LABELS.items():
                c.execute("INSERT OR REPLACE INTO device_meta(mac, label, known, updated) VALUES(?,?,1,?)",
                          (mac, label, now))
            for sid, name, room, x, y in SENSORS:
                c.execute("INSERT OR REPLACE INTO sensors(id, name, room, x, y, created, last_seen) VALUES(?,?,?,?,?,?,?)",
                          (sid, name, room, x, y, now, now))
        path = os.path.join(self.cfg.data_dir, "floorplan.svg")
        with open(path, "w") as fh:
            fh.write(FLOORPLAN_SVG)
        ctx.settings.set("floorplan", {"image": "floorplan.svg", "width": 1000, "height": 640})
        ctx.location.reload()
        ctx.security.reload()
        apply_meta(ctx)
        apply_ignore(ctx)

    def extras(self, t, out):
        """Per-sensor copies (room location), channel survey samples and staged security incidents."""
        extra = []
        seen = set()
        for o in out:
            mac = o.get("mac")
            if o.get("rssi") is None or mac in seen or (mac not in FIXED_ROOMS and mac not in MOBILE):
                continue
            seen.add(mac)
            room = room_of(mac, t)
            base = o["rssi"]
            o["rssi"] = base + pen(room, "Hallway")
            for sid, _, sroom, _, _ in SENSORS[1:]:
                extra.append({**o, "sensor": sid, "rssi": base + pen(room, sroom) + self.rng.randint(-2, 2),
                              "fp": None, "ts": o["ts"] + 0.5})
        hour = ((t + 3600) % 86400) / 3600
        busy = 0.5 + 0.5 * max(0.0, 1 - abs(hour - 20) / 8)
        lmin = int(((t + 3600) % 86400) // 60)
        dnum = int((t + 3600) // 86400)
        microwave = lmin in range(12 * 60 + 30, 12 * 60 + 34) or lmin in range(18 * 60 + 45, 18 * 60 + 50)
        sender = dnum % 3 == 0 and 20 * 60 <= lmin < 21 * 60 + 30  # a wireless video sender left on
        for ch, band, u in CHANNELS:
            dwell = 2500
            util = min(0.95, u * busy * (0.85 + self.rng.random() * 0.3))
            frames = int(util * dwell * 1.6)
            noise, retry = (-95 if band == "2.4" else -101), 0.06 + u * 0.18
            if band == "2.4" and microwave and ch >= 6:
                noise, retry = -82 + self.rng.randint(-2, 2), 0.5
            elif band == "2.4" and sender:
                noise, retry = -86 + self.rng.randint(-2, 2), 0.38
            extra.append({"t": "chan", "ts": t + 30, "mac": "-", "freq": ch_to_freq(ch, band), "dwell_ms": dwell,
                          "frames": frames, "bytes": frames * 300, "airtime_us": int(util * dwell * 1000),
                          "retries": int(frames * retry), "noise_sum": noise * 20, "noise_cnt": 20})
        day, minute = int((t + 3600) // 86400), int(((t + 3600) % 86400) // 60)
        if day % 2 == 0 and 21 * 60 <= minute < 21 * 60 + 40:  # evil twin of HomeNet, open network
            extra.append({"t": "wifi_ap", "ts": t + 10, "mac": EVIL_TWIN, "ssid": "HomeNet", "enc": "OPN",
                          "rssi": self._rssi(-61), **_radio(6), "randomized": True})
        if day % 3 == 1 and 14 * 60 <= minute < 14 * 60 + 25:  # KARMA-style AP answering every probe
            for i, ssid in enumerate(("Starbucks", "KPN", "eduroam", "NS WiFi", "Ziggo")):
                extra.append({"t": "wifi_ap", "ts": t + i, "mac": KARMA, "ssid": ssid, "enc": "OPN",
                              "rssi": self._rssi(-70), **_radio(11)})
        if minute == 3 * 60 + 17:  # nightly deauthentication burst against HomeNet
            for i in range(40):
                extra.append({"t": "wifi_client", "ts": t + i * 0.2, "mac": "a4:83:e7:01:00:01",
                              "bssid": "24:a4:3c:10:00:01", "frame": "deauth", "reason": 7, "rssi": None})
        extra += self.lan(t, out)
        extra += self.zigbee(t)
        extra += self.lora(t)
        return extra

    def lora(self, t):
        """A few Meshtastic nodes, a MeshCore repeater and chat clients, a LoRaWAN sensor and a stray unidentified transmitter."""
        import struct
        from .lora_protocols import PROFILES
        rng, res = self.rng, []
        eu, mc, lw = PROFILES["meshtastic-eu868"], PROFILES["meshcore-eu868"], PROFILES["lorawan-eu868"]

        def frame(profile, payload, rssi, sensor=None):
            o = {"t": "lora_frame", "ts": t + rng.random() * 50, "mac": "-", "profile": profile.name, "freq": profile.freq, "bw": profile.bw,
                 "sf": profile.sf, "sync": profile.sync, "rssi": rssi + rng.randint(-4, 4), "snr": round(rng.uniform(-8, 9), 2),
                 "ferr": rng.randint(-900, 900), "hex": payload.hex()}
            if sensor:
                o["sensor"] = sensor
            res.append(o)

        for node, rate, rssi in ((0x1A2B3C4D, 3, -96), (0x5E6F7A8B, 2, -108), (0x0C0FFEE1, 1, -112)):
            for _ in range(rng.randint(0, rate)):
                flags = 0x63 if rng.random() < 0.7 else 0x6B
                frame(eu, struct.pack("<IIIBBBB", 0xFFFFFFFF, node, rng.getrandbits(32), flags, 0x08, 0, node & 0xFF) + bytes(rng.getrandbits(8) for _ in range(rng.randint(12, 60))), rssi)
        if int(t // 60) % 15 == 0:
            advert = bytes(range(0x40, 0x60)) + struct.pack("<I", int(t)) + bytes(64) + bytes([0x92]) + struct.pack("<ii", 0, 0) + b"Hilltop Repeater"
            frame(mc, bytes([0x11, 0x00]) + advert, -101)
        for _ in range(rng.randint(0, 2)):
            frame(mc, bytes([0x09, 0x02, 0x4F, 0xA1, 0xA1, 0x4F]) + bytes(rng.getrandbits(8) for _ in range(rng.randint(20, 70))), -104)
        if int(t // 60) % 5 == 0:
            frame(lw, bytes([0x40]) + struct.pack("<I", 0x26011BDA)[:4] + bytes([0x80]) + struct.pack("<H", int(t // 300) & 0xFFFF) + b"\x01" + bytes(rng.getrandbits(8) for _ in range(8)) + bytes(4), -92)
        return res

    def zigbee(self, t):
        """A home Zigbee network, a Thread network, and an encrypted system of unknown protocol."""
        res = []
        if int(t // 60) % 10 == 0:
            res += [{"t": "zb_network", "ts": t, "mac": "-", "ext_pan": ext, "pan": pan, "channel": ch, "permit_join": False,
                     "stack_profile": 2, "update_id": 3, "lqi": lqi, "rssi": rssi, "routers": []}
                    for ext, pan, ch, lqi, rssi in (("00:12:4b:00:1e:a0:44:01", 0x1a62, 15, 214, -51),
                                                    ("dd:a1:7c:33:90:5e:12:08", 0x4e20, 25, 96, -82))]
            res.append({"t": "zb_energy", "ts": t, "mac": "-",
                        "readings": [[c, -92 + (c % 5) * 3 + self.rng.randint(-2, 2)] for c in range(11, 27)]})
        mask = lambda c: 1 << c  # noqa: E731
        radios, channels = [], {}
        for pan, addr, ch, rate, hint, typ, rssi in ZIGBEE_RADIOS:
            sent = self.rng.randint(0, rate)
            if not sent:
                continue
            channels[str(ch)] = channels.get(str(ch), 0) + sent
            radios.append([pan, addr, mask(ch), sent, 0, sent if hint == 1 else 0, hint, typ,
                           rssi + self.rng.randint(-3, 3), max(20, min(255, (rssi + 100) * 4))])
        if radios:
            res.append({"t": "zb_frames", "ts": t, "mac": "-", "undecoded": 0, "channels": channels, "radios": radios})
        return res

    def lan(self, t, out):
        """Ethernet-side observations: discovery, DHCP, DNS, traffic summaries and staged LAN attacks."""
        rng = self.rng
        res, items, hosts = [], [], {}
        minute = int(t // 60)
        present_wifi = {o["mac"] for o in out if o.get("t") == "wifi_client" and o.get("bssid")}
        hour = ((t + 3600) % 86400) / 3600
        evening = 18 <= hour or hour < 1
        devices = [(m, ip, h, present(sched, m, t) if sched != "always" else True, fp, dests)
                   for m, ip, h, sched, fp, dests in WIRED]
        devices += [(m, ip, h, m in present_wifi, fp, dests) for m, (ip, h, fp, dests) in WIFI_LAN.items()]
        for mac, ip, host, here, fp, dests in devices:
            if not here:
                continue
            hosts[mac] = ip
            if minute % 60 == _h(mac) % 60 or minute % 1440 == 0:  # hourly re-announcement (DHCP / mDNS / SSDP / LLDP)
                res.append({"t": "lan", "ts": t + 2, "mac": mac, "ip": ip, "name": host, "src": "dhcp", "fp": {"lan": fp}})
            for d in dests:
                ip_d, name, port, proto, kin, kout = DESTS[d]
                busy = (0.6 + 0.8 * evening) if kin > 1000 else 1
                if kin > 1000 and rng.random() > 0.35 * busy:
                    continue  # streaming / downloads only some minutes
                f = rng.uniform(0.5, 1.5) * busy
                items.append((mac, ip_d, proto, port, int(kout * 1024 * f), int(kin * 1024 * f), int(kin * f) + 3, name))
                if minute % 10 == _h(mac, d) % 10:
                    res.append({"t": "lan", "ts": t + 5, "mac": mac, "ip": ip, "dns": name, "src": "dns"})
        for mac, peer, port, proto, kin, kout in LOCAL_FLOWS:
            if mac in hosts and rng.random() < 0.3:
                items.append((mac, peer, proto, port, kout * 1024, kin * 1024, kin, None))
        res.append({"t": "lan_traffic", "ts": t + 50, "mac": "-", "items": items, "hosts": hosts})
        if minute % 30 == 0:
            res.append({"t": "dhcp_server", "ts": t + 1, "mac": GW, "ip": "192.168.1.1", "msg": "ack",
                        "client": "a4:83:e7:01:00:01", "router": "192.168.1.1"})
        day, mod = int((t + 3600) // 86400), int(((t + 3600) % 86400) // 60)
        if day % 3 == 2 and 15 * 60 <= mod < 15 * 60 + 20 and mod % 5 == 0:  # a travel router plugged in, handing out leases
            res.append({"t": "dhcp_server", "ts": t + 3, "mac": "50:c7:bf:00:00:66", "ip": "192.168.0.1", "msg": "offer",
                        "client": "5c:0a:5b:01:00:03", "router": "192.168.0.1"})
        if day % 4 == 1 and mod == 2 * 60 + 30:  # ARP spoofing of the gateway
            for i, m in enumerate([GW, "0a:66:00:00:00:66"] * 3):
                res.append({"t": "lan", "ts": t + i, "mac": m, "ip": "192.168.1.1", "src": "arp"})
        return res

    def backfill(self, hours):
        if not hours:
            return
        if self.store.conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]:
            log.info("Demo database already populated; skipping backfill")
            return
        log.info("Generating %d hours of demo history...", hours)
        now = time.time()
        t = int((now - hours * 3600) // 60) * 60
        self._conn_state = {}
        n = 0
        while t < now - 60:
            for o in self.observations(t) + self._bt_connections(t, self._conn_state):
                self.store.process(o)
                n += 1
            self.store.sweep(t + 60)
            if (t // 60) % 5 == 0:  # the interference detector reads recent minutes from the database
                self.store.flush()
            t += 60
        self.store.flush()
        self._sensors_alive()
        log.info("Demo backfill done (%d observations)", n)

    def _sensors_alive(self):
        if self.ctx:  # the demo's remote sensors are simulated: keep them "online"
            self.ctx.execute("UPDATE sensors SET last_seen=?", (time.time(),))

    def run(self, stop):
        state = getattr(self, "_conn_state", {})
        while not stop.wait(30):
            t = time.time()
            for o in self.observations(t - 55):
                o["ts"] = t
                self.store.put(o)
            for o in self._bt_connections(t, state):
                self.store.put(o)
            self._sensors_alive()
