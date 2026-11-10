"""Passive device identification: brand, model, device type, OS, Wi-Fi generation and age.

Every clue becomes a piece of *evidence* (field, value, confidence 0-100, source). For each field
the most confident value wins, and the full evidence list is kept so the UI can show why a
device was identified the way it was. Nothing here transmits anything: all inputs are taken
from frames the device broadcasts itself.
"""
import hashlib
import re

IDENT_VERSION = 8

TYPE_LABELS = {
    "phone": "Phone", "tablet": "Tablet", "laptop": "Laptop", "desktop": "Desktop PC",
    "computer": "Computer", "watch": "Smartwatch", "wearable": "Wearable", "headphones": "Headphones",
    "speaker": "Speaker", "tv": "TV", "streaming": "Streaming device", "console": "Game console",
    "controller": "Game controller", "printer": "Printer", "camera": "Camera", "tag": "Tracker tag",
    "sensor": "Sensor", "iot": "IoT device", "light": "Smart light", "input": "Keyboard / mouse",
    "car": "Car", "router": "Router / access point", "hotspot": "Mobile hotspot", "smart_home": "Smart home",
    "beacon": "Beacon", "sbc": "Single-board computer", "media": "Media device", "network": "Network device",
    "nas": "NAS / storage", "server": "Server", "bike": "Bike / e-bike",
}
WIFI_GEN_YEAR = {4: 2009, 5: 2013, 6: 2019, 7: 2024}
WIFI_6E_YEAR = 2021
CONF_LABEL = ((75, "high"), (50, "medium"), (0, "low"))

# --------------------------------------------------------------------- Wi-Fi
VENDOR_IES = {
    "00:17:f2": "Apple", "00:10:18": "Broadcom", "00:03:7f": "Qualcomm Atheros", "00:e0:4c": "Realtek",
    "00:0c:e7": "MediaTek", "00:0c:43": "Ralink/MediaTek", "00:40:96": "Cisco", "00:00:f0": "Samsung",
    "8c:fd:f0": "Qualcomm", "00:90:4c": "Epigram (Broadcom)", "00:50:f2": "Microsoft/WFA",
    "50:6f:9a": "Wi-Fi Alliance", "00:13:92": "Ruckus", "00:0b:86": "Aruba", "00:1a:11": "Google",
}
WFA_TYPES = {0x09: "Wi-Fi Direct (P2P)", 0x16: "MBO/OCE (agile multiband)", 0x10: "Hotspot 2.0 / Passpoint",
             0x1C: "OWE transition", 0x12: "OSEN"}
WPS_CATEGORY = {
    1: ("computer", {1: "computer", 2: "computer", 3: "media", 5: "laptop", 6: "desktop", 7: "tablet",
                     8: "laptop", 9: "tablet", 10: "laptop"}),
    2: ("input", {}), 3: ("printer", {}), 4: ("camera", {}), 5: ("network", {}),
    6: ("router", {}), 7: ("tv", {2: "media", 3: "media", 4: "computer"}),
    8: ("media", {4: "streaming", 5: "media", 6: "media"}), 9: ("console", {5: "console"}),
    10: ("phone", {}), 11: ("speaker", {1: "media", 2: "speaker", 3: "headphones", 4: "speaker"}),
}


def _ss_from_map(m):
    return sum(1 for i in range(8) if (m >> (2 * i)) & 0x3 != 0x3)


def parse_wps(data):
    out, i = {}, 0
    names = {0x1021: "manufacturer", 0x1023: "model", 0x1024: "model_number", 0x1011: "device_name"}
    while i + 4 <= len(data):
        t, ln = int.from_bytes(data[i:i + 2], "big"), int.from_bytes(data[i + 2:i + 4], "big")
        v = data[i + 4:i + 4 + ln]
        i += 4 + ln
        if t in names:
            s = v.decode("utf-8", "replace").strip("\x00 ").strip()
            if s and s.lower() not in ("", "0", "n/a", "none", "123456", " "):
                out[names[t]] = s[:64]
        elif t == 0x1054 and ln >= 8:
            out["category"] = int.from_bytes(v[0:2], "big")
            out["subcategory"] = int.from_bytes(v[6:8], "big")
    return out


def wifi_fingerprint(elts):
    """Build a capability fingerprint from a list of (element id, bytes) information elements."""
    fp = {"vendors": [], "wfa": []}
    sig = []
    for eid, info in elts:
        if eid == 221 and len(info) >= 3:
            oui = ":".join(f"{b:02x}" for b in info[:3])
            vtype = info[3] if len(info) > 3 else None
            sig.append(f"221:{oui}:{vtype}")
            if oui not in fp["vendors"]:
                fp["vendors"].append(oui)
            if oui == "00:50:f2" and vtype == 4:
                wps = parse_wps(info[4:])
                if wps:
                    fp["wps"] = wps
            elif oui == "50:6f:9a" and vtype in WFA_TYPES and WFA_TYPES[vtype] not in fp["wfa"]:
                fp["wfa"].append(WFA_TYPES[vtype])
            continue
        if eid == 255 and info:
            ext = info[0]
            sig.append(f"255:{ext}")
            if ext == 35 and len(info) >= 8:  # HE capabilities
                fp["he"] = True
                phy0 = info[7]
                if phy0 & 0x18:
                    fp["width"] = max(fp.get("width", 20), 160)
                elif phy0 & 0x06:
                    fp["width"] = max(fp.get("width", 20), 80 if phy0 & 0x04 else 40)
                if len(info) >= 20:
                    fp["ss"] = max(fp.get("ss", 0), _ss_from_map(int.from_bytes(info[18:20], "little")))
            elif ext == 108 and len(info) >= 4:  # EHT capabilities
                fp["eht"] = True
                if info[3] & 0x02:
                    fp["width"] = 320
            continue
        if eid not in (0, 3, 5):  # SSID / DS / TIM vary between frames
            sig.append(str(eid))
        if eid == 45 and len(info) >= 7:  # HT capabilities
            fp["ht"] = True
            if int.from_bytes(info[0:2], "little") & 0x0002:
                fp["width"] = max(fp.get("width", 20), 40)
            fp["ss"] = max(fp.get("ss", 0), sum(1 for b in info[3:7] if b))
        elif eid == 191 and len(info) >= 6:  # VHT capabilities
            fp["vht"] = True
            cw = (int.from_bytes(info[0:4], "little") >> 2) & 0x3
            fp["width"] = max(fp.get("width", 20), 160 if cw else 80)
            fp["ss"] = max(fp.get("ss", 0), _ss_from_map(int.from_bytes(info[4:6], "little")))
        elif eid == 48:
            fp["rsn"] = True
        elif eid == 127:
            fp["extcap_len"] = len(info)
    gen = 7 if fp.get("eht") else 6 if fp.get("he") else 5 if fp.get("vht") else 4 if fp.get("ht") else None
    if gen:
        fp["gen"] = gen
    fp["sig"] = ",".join(sig)
    return {k: v for k, v in fp.items() if v not in ([], None)}


def merge_wifi(old, new):
    m = dict(old or {})
    m["seen"] = True  # capability elements were parsed at least once (even if none were advertised)
    for k, v in new.items():
        if k == "sig":
            continue
        if k in ("vendors", "wfa"):
            m[k] = sorted(set(m.get(k, [])) | set(v))
        elif k in ("gen", "ss", "width", "extcap_len"):
            m[k] = max(m.get(k) or 0, v)
        elif k == "wps":
            m[k] = {**m.get(k, {}), **v}
        else:
            m[k] = v
    return m


def probe_hash(sig):
    return hashlib.sha1(sig.encode()).hexdigest()[:10] if sig else None


# ----------------------------------------------------------------- Bluetooth
APPLE_MODELS = {  # proximity-pairing model id -> (name, type, year)
    0x2002: ("AirPods", "headphones", 2016), 0x200F: ("AirPods (2nd gen)", "headphones", 2019),
    0x2013: ("AirPods (3rd gen)", "headphones", 2021), 0x200E: ("AirPods Pro", "headphones", 2019),
    0x2014: ("AirPods Pro (2nd gen)", "headphones", 2022), 0x2024: ("AirPods Pro (2nd gen, USB-C)", "headphones", 2023),
    0x200A: ("AirPods Max", "headphones", 2020), 0x201F: ("AirPods Max (USB-C)", "headphones", 2024),
    0x2019: ("AirPods 4", "headphones", 2024), 0x201B: ("AirPods 4 (ANC)", "headphones", 2024),
    0x2005: ("BeatsX", "headphones", 2017), 0x2006: ("Beats Solo3", "headphones", 2016),
    0x2003: ("Powerbeats3", "headphones", 2016), 0x200B: ("Powerbeats Pro", "headphones", 2019),
    0x200C: ("Beats Solo Pro", "headphones", 2019), 0x2009: ("Beats Studio3", "headphones", 2017),
    0x2010: ("Beats Flex", "headphones", 2020), 0x2011: ("Beats Studio Buds", "headphones", 2021),
    0x2012: ("Beats Fit Pro", "headphones", 2021), 0x2016: ("Beats Studio Buds+", "headphones", 2023),
    0x2017: ("Beats Studio Pro", "headphones", 2023),
}
APPLE_TYPES = {0x02: "iBeacon", 0x05: "AirDrop", 0x07: "Proximity pairing", 0x09: "AirPlay target",
               0x0A: "AirPlay source", 0x0B: "Magic Switch", 0x0C: "Handoff", 0x0D: "Tethering target",
               0x0E: "Tethering source", 0x0F: "Nearby action", 0x10: "Nearby info", 0x12: "Find My"}
MS_CDP_TYPES = {1: ("Xbox One", "console", "Microsoft", "Windows"), 6: ("iPhone", "phone", "Apple", "iOS"),
                7: ("iPad", "tablet", "Apple", "iPadOS"), 8: ("Android device", "phone", None, "Android"),
                9: ("Windows desktop", "desktop", None, "Windows"), 11: ("Windows phone", "phone", None, "Windows"),
                12: ("Linux device", "computer", None, "Linux"), 13: ("Windows IoT", "iot", None, "Windows"),
                14: ("Surface Hub", "tv", "Microsoft", "Windows"), 15: ("Windows laptop", "laptop", None, "Windows"),
                16: ("Windows tablet", "tablet", None, "Windows")}
BLE_UUIDS = {  # 16-bit service UUID -> (label, type, brand, confidence)
    "fd6f": ("Exposure Notification", "phone", None, 55), "fe2c": ("Google Fast Pair", "headphones", None, 35),
    "feaa": ("Eddystone beacon", "beacon", None, 70), "fd5a": ("Samsung SmartTag", "tag", "Samsung", 85),
    "feed": ("Tile tracker", "tag", "Tile", 85), "feec": ("Tile tracker", "tag", "Tile", 85),
    "180d": ("Heart rate", "wearable", None, 55), "1812": ("HID (keyboard/mouse/remote)", "input", None, 60),
    "1816": ("Cycling speed & cadence", "bike", None, 70), "1818": ("Cycling power", "bike", None, 70),
    "1826": ("Fitness machine", "wearable", None, 40),
    "fe95": ("Xiaomi MiBeacon", "iot", "Xiaomi", 60), "fcd2": ("BTHome sensor", "sensor", None, 75),
    "181a": ("Environmental sensing", "sensor", None, 60), "fe9f": ("Google", None, "Google", 50),
    "fe07": ("Sonos", "speaker", "Sonos", 80), "fe03": ("Amazon", None, "Amazon", 50),
    "fd44": ("Apple Find My network accessory", "tag", None, 70), "fe0f": ("Philips Hue", "light", "Philips Hue", 80),
    "184e": ("Auracast audio broadcast", "speaker", None, 40), "fe59": ("Nordic DFU", "iot", None, 30),
}
APPEARANCE_TYPES = {"phone": "phone", "computer": "computer", "watch": "watch", "clock": "smart_home",
                    "display": "tv", "remote": "input", "tag": "tag", "keyring": "tag", "media player": "media",
                    "thermometer": "sensor", "heart rate": "wearable", "blood pressure": "wearable", "HID": "input",
                    "glucose": "wearable", "running sensor": "wearable",
                    # Bluetooth "Cycling" appearance: bike computers, speed/cadence/power sensors and e-bikes
                    "cycling sensor": "bike",
                    "light": "light", "audio sink": "headphones", "audio source": "media", "sensor": "sensor"}
COD_MINOR = {
    1: {1: "desktop", 2: "computer", 3: "laptop", 4: "tablet", 5: "tablet", 6: "watch", 7: "tablet"},
    2: {1: "phone", 2: "phone", 3: "phone", 4: "phone", 5: "phone"},
    4: {1: "headphones", 2: "headphones", 4: "headphones", 5: "speaker", 6: "headphones", 7: "speaker",
        8: "car", 9: "streaming", 10: "speaker", 12: "camera", 13: "camera", 14: "tv", 15: "tv", 18: "console"},
    7: {1: "watch", 2: "wearable", 3: "wearable", 4: "wearable", 5: "wearable"},
}
# Major class 6 (Imaging) is the exception: its minor field is four independent flag bits (Display/Camera/
# Scanner/Printer, bits 2-5 of the class of device, i.e. bits 0-3 of the extracted 6-bit minor value we
# compute), not an enumerated value — treating it as one blanket "printer" mistypes any Bluetooth camera
# or scanner. Printer wins when several bits are set, since it's the least ambiguous of the four.
COD_IMAGING_FLAGS = (("printer", 0x8), ("camera", 0x4), ("camera", 0x2), ("tv", 0x1))  # scanner -> camera bucket
# No blanket type for major 6 (Imaging, decoded above), 8 (Toy — "console" doesn't fit a toy robot/vehicle
# and nothing else in TYPE_LABELS does either) or 31 (Uncategorized).
COD_MAJOR_TYPE = {1: "computer", 2: "phone", 3: "router", 4: "media", 5: "input", 7: "wearable", 9: "sensor"}


def ble_fingerprint(ad, ext=False):
    """Interesting identification fields from a parsed advertisement (see bluetooth.parse_ad)."""
    fp = {}
    mfg = ad.get("mfg")
    cid = ad.get("company_id")
    if cid is not None:
        fp["company"] = cid
    if mfg and cid == 0x004C:  # Apple Continuity: sequence of [type][len][payload]
        types, i = [], 0
        while i + 2 <= len(mfg):
            t, ln = mfg[i], mfg[i + 1]
            payload = mfg[i + 2:i + 2 + ln]
            types.append(t)
            if t == 0x07 and len(payload) >= 3:
                be, le = int.from_bytes(payload[1:3], "big"), int.from_bytes(payload[1:3], "little")
                model = be if be in APPLE_MODELS else le if le in APPLE_MODELS else None
                if model:
                    fp["apple_model"] = model
            i += 2 + ln
        fp["apple"] = sorted(set(types))
    elif mfg and cid == 0x0006 and len(mfg) >= 2 and mfg[0] == 0x01:  # Microsoft CDP beacon
        fp["ms_type"] = mfg[1] & 0x1F
    if ad.get("uuids"):
        fp["uuids"] = list(ad["uuids"])
    if ext:
        fp["ext_adv"] = True
    return fp


def merge_ble(old, new):
    m = dict(old or {})
    for k, v in new.items():
        if k in ("apple", "uuids"):
            m[k] = sorted(set(m.get(k, [])) | set(v))
        else:
            m[k] = v
    return m


# ---------------------------------------------------------------- LAN (Ethernet) rules
DHCP_VENDOR_RULES = [  # (regex on DHCP option 60, os, type, brand, confidence)
    (r"^MSFT", "Windows", None, None, 85), (r"^android-dhcp-(\d+)", "Android {0}", "phone", None, 90),
    (r"^dhcpcd", "Linux / Android", None, None, 50), (r"^udhcp", "Embedded Linux (BusyBox)", "iot", None, 60),
    (r"^HUAWEI", "Android", "phone", "Huawei", 70), (r"^Cisco", None, "network", "Cisco", 70),
    (r"^PS[45]|^PlayStation", None, "console", "Sony", 85), (r"^Nintendo", None, "console", "Nintendo", 85),
    (r"^Hewlett-Packard|^HP ", None, "printer", "HP", 70), (r"^ESP32|^espressif", None, "iot", "Espressif", 80),
]
DHCP_VENDOR_RULES = [(re.compile(r, re.I), *rest) for r, *rest in DHCP_VENDOR_RULES]
DHCP_PRL_RULES = [  # (option-55 prefix, os, confidence) — order of requested options is characteristic per OS
    ("1,121,3,6,15,108,114,119,252", "iOS / macOS", 75), ("1,121,3,6,15,119,252", "iOS / macOS", 70),
    ("1,3,6,15,31,33,43,44,46,47,119,121,249,252", "Windows", 80), ("1,3,6,15,31,33,43,44,46,47,121,249,252", "Windows", 75),
    ("1,3,6,15,26,28,51,58,59,43", "Android", 65), ("1,3,6,15,26,28,51,58,59", "Android", 60),
    ("1,28,2,3,15,6,119,12,44,47,26,121,42", "Linux", 65), ("1,2,6,12,15,26,28,121,3,33,40,41,42,119,249,252,17", "Linux", 60),
]
MDNS_SERVICES = {  # service -> (label, type, brand, os, confidence)
    "_googlecast._tcp": ("Google Cast", "streaming", None, None, 55), "_airplay._tcp": ("AirPlay receiver", "streaming", None, None, 40),
    "_raop._tcp": ("AirPlay audio", "speaker", None, None, 35), "_ipp._tcp": ("IPP printing", "printer", None, None, 80),
    "_ipps._tcp": ("IPP printing", "printer", None, None, 80), "_printer._tcp": ("LPD printing", "printer", None, None, 80),
    "_pdl-datastream._tcp": ("Raw printing", "printer", None, None, 80), "_uscan._tcp": ("eSCL scanner", "printer", None, None, 70),
    "_hap._tcp": ("HomeKit accessory", "smart_home", None, None, 70), "_sonos._tcp": ("Sonos", "speaker", "Sonos", None, 85),
    "_spotify-connect._tcp": ("Spotify Connect", "speaker", None, None, 40),
    "_companion-link._tcp": ("Apple companion link", "phone", "Apple", "iOS / macOS", 55),
    "_rdlink._tcp": ("Apple remote", None, "Apple", None, 60), "_sleep-proxy._udp": ("Bonjour sleep proxy", "streaming", "Apple", None, 50),
    "_smb._tcp": ("SMB file sharing", "computer", None, None, 35), "_afpovertcp._tcp": ("AFP file sharing", "nas", None, None, 40),
    "_hue._tcp": ("Philips Hue bridge", "smart_home", "Philips Hue", None, 85),
    "_amzn-wplay._tcp": ("Amazon Fire TV", "streaming", "Amazon", "Fire OS", 75),
    "_androidtvremote2._tcp": ("Android TV remote", "tv", None, "Android TV", 75),
    "_matter._tcp": ("Matter", "smart_home", None, None, 60), "_matterc._udp": ("Matter", "smart_home", None, None, 55),
    "_esphomelib._tcp": ("ESPHome", "iot", "Espressif", None, 85), "_home-assistant._tcp": ("Home Assistant", "server", None, "Home Assistant OS", 80),
    "_workstation._tcp": ("Linux workstation (Avahi)", "computer", None, "Linux", 50), "_ssh._tcp": ("SSH", "computer", None, None, 25),
    "_octoprint._tcp": ("OctoPrint", "iot", None, None, 75), "_daap._tcp": ("iTunes sharing", "computer", "Apple", None, 40),
}
APPLE_MODEL_PREFIX = [("MacBook", "laptop", "macOS"), ("iMac", "desktop", "macOS"), ("Macmini", "desktop", "macOS"),
                      ("MacPro", "desktop", "macOS"), ("Mac", "computer", "macOS"), ("iPhone", "phone", "iOS"),
                      ("iPad", "tablet", "iPadOS"), ("AppleTV", "streaming", "tvOS"), ("AudioAccessory", "speaker", None),
                      ("Watch", "watch", "watchOS")]
SSDP_RULES = [  # regex on the SSDP SERVER header -> (os, type, brand, confidence)
    (r"Microsoft-Windows", "Windows", "computer", None, 70), (r"Sonos", None, "speaker", "Sonos", 85),
    (r"Roku", "Roku OS", "streaming", "Roku", 85), (r"Synology|DSM", "DSM", "nas", "Synology", 85),
    (r"QNAP", "QTS", "nas", "QNAP", 85), (r"PlayStation|PS[45]", None, "console", "Sony", 80),
    (r"IpBridge|Philips-hue|hue", None, "smart_home", "Philips Hue", 75), (r"FRITZ!Box|AVM", None, "router", "AVM", 85),
    (r"webOS|LGE|LG Smart", "webOS", "tv", "LG", 80), (r"SAMSUNG|Tizen", "Tizen", "tv", "Samsung", 70),
    (r"Xbox", None, "console", "Microsoft", 80), (r"miniupnpd", None, "router", None, 50),
    (r"Linux", "Linux", None, None, 35),
]
SSDP_RULES = [(re.compile(r, re.I), *rest) for r, *rest in SSDP_RULES]


def merge_lan(old, new):
    m = {k: (dict(v) if isinstance(v, dict) else v) for k, v in (old or {}).items()}
    for sec, val in new.items():
        cur = m.setdefault(sec, {})
        for k, v in val.items():
            if isinstance(v, list):
                cur[k] = sorted(set(cur.get(k, [])) | set(v))[:30]
            elif isinstance(v, dict):
                cur[k] = {**cur.get(k, {}), **v}
            elif v is not None:
                cur[k] = v
    return m


def lan_evidence(ev, lfp, years):
    dhcp, mdns, ssdp, lldp = (lfp.get(k) or {} for k in ("dhcp", "mdns", "ssdp", "lldp"))
    if dhcp.get("vendor"):
        for rx, os_, typ, brand, conf in DHCP_VENDOR_RULES:
            m = rx.search(dhcp["vendor"])
            if m:
                src = f"DHCP vendor class “{dhcp['vendor']}”"
                ev.add("os", os_.format(*m.groups()) if os_ else None, conf, src)
                ev.add("type", typ, conf - 20, src)
                ev.add("brand", brand, conf, src)
                break
    if dhcp.get("prl"):
        for prefix, os_, conf in DHCP_PRL_RULES:
            if dhcp["prl"].startswith(prefix):
                ev.add("os", os_, conf, f"DHCP option-55 fingerprint {dhcp['prl']}")
                break
        ev.add("feature", "DHCP client", 40, "DHCP request")
    for svc in mdns.get("services", []):
        hit = MDNS_SERVICES.get(svc)
        if hit:
            label, typ, brand, os_, conf = hit
            src = f"mDNS service {svc}"
            ev.add("type", typ, conf, src)
            ev.add("brand", brand, conf, src)
            ev.add("os", os_, conf, src)
            ev.add("feature", label, 70, src)
    txt = mdns.get("txt") or {}
    model = txt.get("model") or txt.get("am")
    if model:
        for prefix, typ, os_ in APPLE_MODEL_PREFIX:
            if model.startswith(prefix):
                ev.add("brand", "Apple", 90, f"mDNS model “{model}”")
                ev.add("type", typ, 85, f"mDNS model “{model}”")
                ev.add("os", os_, 80, f"mDNS model “{model}”")
                ev.add("model", model, 80, "mDNS device-info")
                break
        else:
            ev.add("model", model, 70, "mDNS TXT record")
    if txt.get("md"):  # Google Cast model name, e.g. "Chromecast", "Google Nest Mini"
        ev.add("model", txt["md"], 85, "Google Cast TXT record")
        ev.add("brand", "Google" if re.search(r"Google|Chromecast|Nest", txt["md"]) else None, 70, "Google Cast TXT record")
    if txt.get("ty") or txt.get("usb_mdl"):
        ev.add("model", txt.get("ty") or txt.get("usb_mdl"), 85, "Printer TXT record")
        ev.add("type", "printer", 85, "Printer TXT record")
        if txt.get("usb_mfg"):
            ev.add("brand", txt["usb_mfg"], 85, "Printer TXT record")
    if ssdp.get("server"):
        for rx, os_, typ, brand, conf in SSDP_RULES:
            if rx.search(ssdp["server"]):
                src = f"UPnP server “{ssdp['server'][:60]}”"
                ev.add("os", os_, conf, src)
                ev.add("type", typ, conf, src)
                ev.add("brand", brand, conf, src)
                break
    if any("MediaRenderer" in n for n in ssdp.get("nt", [])):
        ev.add("type", "media", 45, "UPnP MediaRenderer")
    if lldp:
        desc = lldp.get("sysdesc", "")
        ev.add("type", "network", 80, f"LLDP from “{lldp.get('sysname') or desc[:40]}”")
        for rx, brand in ((r"UniFi|Ubiquiti|EdgeSwitch", "Ubiquiti"), (r"Cisco", "Cisco"), (r"MikroTik|RouterOS", "MikroTik"),
                          (r"Aruba|ProCurve", "HPE Aruba"), (r"Juniper|JUNOS", "Juniper"), (r"Netgear", "Netgear"),
                          (r"TP-Link|Omada", "TP-Link"), (r"Linux", None)):
            if re.search(rx, desc, re.I):
                ev.add("brand", brand, 80, "LLDP system description")
                break
        if lldp.get("sysname"):
            ev.add("name", lldp["sysname"], 80, "LLDP system name")


# ---------------------------------------------------------------- name rules
# (regex, brand, type, os, use match as model, year)
NAME_RULES = [
    (r"\biPhone\b", "Apple", "phone", "iOS", False, None),
    (r"\biPad\b", "Apple", "tablet", "iPadOS", False, None),
    (r"\bMacBook( Pro| Air)?\b", "Apple", "laptop", "macOS", True, None),
    (r"\b(iMac|Mac mini|Mac Studio|Mac Pro)\b", "Apple", "desktop", "macOS", True, None),
    (r"\bApple Watch\b", "Apple", "watch", "watchOS", True, None),
    (r"\bApple TV\b", "Apple", "streaming", "tvOS", True, None),
    (r"\bHomePod( mini)?\b", "Apple", "speaker", None, True, None),
    (r"\bAirPods( Pro| Max)?\b", "Apple", "headphones", None, True, None),
    (r"\bBeats\b|\bPowerbeats\b", "Beats (Apple)", "headphones", None, True, None),
    (r"\bGalaxy[ _-]?Watch[ _-]?\d*\w*(?:[ _-](?:Classic|Ultra|FE|Pro|Plus))?", "Samsung", "watch", "Wear OS", True, None),
    (r"\bGalaxy[ _-]?Buds[ _-]?\w*(?:[ _-](?:Pro|Plus|Live|FE))?", "Samsung", "headphones", None, True, None),
    (r"\bGalaxy[ _-]?Tab[ _-]?\w*\+?(?:[ _-](?:Ultra|FE|Plus|Lite))*", "Samsung", "tablet", "Android", True, None),
    (r"\bGalaxy[ _-]Z[ _-]?(Flip|Fold)[ _-]?\d*\w*", "Samsung", "phone", "Android", True, None),
    (r"\bGalaxy[ _-]?(S|A|M|Note)[ _-]?\d+\w*\+?(?:[ _-](?:Ultra|FE|Plus|5G))*", "Samsung", "phone", "Android", True, None),
    (r"\[TV\]|\bSamsung .*\bTV\b|\bQ\d{2}\w* Series\b", "Samsung", "tv", "Tizen", False, None),
    (r"\bPixel[ _-]?Watch\b", "Google", "watch", "Wear OS", True, None),
    (r"\bPixel[ _-]?Buds\b", "Google", "headphones", None, True, None),
    (r"\bPixel[ _-]Fold\b", "Google", "phone", "Android", True, None),
    (r"\bPixel[ _-]Tablet\b", "Google", "tablet", "Android", True, None),
    (r"\bPixel[ _-]?\d+\w*(?:[ _-](?:Pro(?:[ _-](?:XL|Fold))?|XL))?\b", "Google", "phone", "Android", True, None),
    (r"\bChromecast\b", "Google", "streaming", None, True, None),
    (r"\b(Google|Nest) (Home|Mini|Hub|Audio)\b", "Google", "speaker", None, True, None),
    (r"\b(Google|Nest) Wifi\b", "Google", "router", None, True, None),  # a mesh router, not a speaker
    (r"\bOnePlus\b", "OnePlus", "phone", "Android", False, None),
    (r"\b(Redmi|POCO)\b", "Xiaomi", "phone", "Android", False, None),
    (r"\b(Mi|Xiaomi) (Smart )?Band ?\d*", "Xiaomi", "wearable", None, True, None),
    (r"\bHUAWEI\b|\bHonor\b", "Huawei", None, None, False, None),
    (r"^DESKTOP-[A-Z0-9]{7}$", None, "desktop", "Windows", False, None),
    (r"^android-[0-9a-f]{16}$", None, "phone", "Android", False, None),
    (r"(^|[-_])(PC|DESKTOP|WORKSTATION)([-_]|$)", None, "desktop", None, False, None),
    (r"\b(DiskStation|RackStation|Synology)\b", "Synology", "nas", "DSM", False, None),
    (r"\b(QNAP|TS-\d{3})\b", "QNAP", "nas", "QTS", False, None),
    (r"\bLGwebOSTV\b|\[LG\]", "LG", "tv", "webOS", False, None),
    (r"\bhomeassistant\b", None, "server", "Home Assistant OS", False, None),
    (r"\bPhilips-hue\b", "Philips Hue", "smart_home", None, False, None),
    (r"^LAPTOP-[A-Z0-9]{7,8}$", None, "laptop", "Windows", False, None),
    (r"\bSurface\b", "Microsoft", "laptop", "Windows", True, None),
    (r"\bXbox\b", "Microsoft", "console", None, True, None),
    (r"\b(DualSense|DUALSHOCK)\b|^Wireless Controller$", "Sony", "controller", None, True, None),
    (r"\bPS[345]\b|\bPlayStation\b", "Sony", "console", None, True, None),
    (r"\bWH-1000XM\d\b|\bWF-\w+\b|\bLinkBuds\b", "Sony", "headphones", None, True, None),
    (r"\bBRAVIA\b", "Sony", "tv", "Android TV", False, None),
    # "Nintendo" alone names the console (a Switch), not a controller — only its actual controller
    # accessories should type as "controller"; a bare brand mention stays untyped rather than guessed.
    (r"\bNintendo Switch\b", "Nintendo", "console", None, True, None),
    (r"\b(Joy-Con|Pro Controller)\b", "Nintendo", "controller", None, True, None),
    (r"\bNintendo\b", "Nintendo", None, None, False, None),
    # Bose and JBL both sell headphones and speakers in similar volume, so the brand name alone doesn't
    # say which — leave the type to the (lower-confidence) MAC-vendor rule below instead of guessing here.
    (r"\bBose\b", "Bose", None, None, False, None),
    (r"\bJBL\b", "JBL", None, None, False, None),
    (r"\bSonos\b", "Sonos", "speaker", None, False, None),
    (r"\bMOMENTUM( True Wireless)?( \d+)?\b", "Sennheiser", "headphones", None, True, None),
    (r"\bSennheiser\b", "Sennheiser", "headphones", None, False, None),
    (r"\bJabra\b", "Jabra", "headphones", None, False, None),
    (r"\b(Echo|Alexa)\b", "Amazon", "speaker", None, False, None),
    (r"\bFire ?TV\b", "Amazon", "streaming", None, True, None),
    (r"\bKindle\b", "Amazon", "tablet", None, False, None),
    (r"\bFitbit\b|\b(Charge|Versa|Sense|Inspire) \d\b", "Fitbit", "wearable", None, True, None),
    (r"\b(Garmin|Forerunner|f[eē]nix|Venu|vivoactive)\b", "Garmin", "watch", None, False, None),
    (r"\bTile\b", "Tile", "tag", None, False, None),
    # e-bikes: VanMoof S3/X3 advertise as ES3-/EX3-<serial>, newer models with the brand name
    (r"^E[SX][345]-[0-9A-Fa-f]{4,}|\bVan ?Moof\b|^VM[SAX]\d", "VanMoof", "bike", None, False, None),
    (r"\bCowboy\b", "Cowboy", "bike", None, False, None),
    (r"\b(Gazelle|Stromer|Specialized|Bosch eBike|Shimano STEPS|Ampler|Rad ?Power|Super73)\b", None, "bike", None, False,
     None),
    (r"\bSmartTag\b", "Samsung", "tag", None, False, None),
    (r"^GV[HM]\d+", "Govee", "sensor", None, False, None),
    (r"\bRuuvi\b", "Ruuvi", "sensor", None, False, None),
    (r"\bMX (Keys|Master|Anywhere|Mechanical)\b", "Logitech", "input", None, True, None),
    (r"\b(Hue|Philips hue)\b", "Philips Hue", "light", None, False, None),
    (r"\b(LaserJet|OfficeJet|DeskJet|ENVY)\b", "HP", "printer", None, True, None),
    (r"\b(EPSON|Brother|Canon (MG|TS|MX))\b", None, "printer", None, False, None),
    (r"\b(Ring|Arlo|Wyze|Blink|Eufy)\b", None, "camera", None, False, None),
    (r"^ESP[_-][0-9A-F]{6}$|\besp32\b|\bESP8266\b", "Espressif", "iot", None, False, None),
    (r"\b(Shelly|tasmota)\b", None, "iot", None, False, None),
    (r"\braspberrypi\b", "Raspberry Pi", "sbc", "Linux", False, None),
    (r"\b(Car Multimedia|CarPlay|Android Auto|Tesla|SYNC|MMI|BMW|VW|Mercedes|Toyota|Volvo)\b", None, "car", None,
     False, None),
    (r"\bWeMo\b", "Belkin Wemo", "smart_home", None, False, None),
    (r"\bSmartThings\b", "Samsung", "smart_home", None, False, None),
    (r"\b(Kasa|Tapo)\b", "TP-Link", "smart_home", None, False, None),
    (r"\bLIFX\b", "LIFX", "light", None, False, None),
    (r"\bMeross\b", "Meross", "smart_home", None, False, None),
    (r"\becobee\b", "ecobee", "smart_home", None, False, None),
    (r"\b(Roomba|iRobot|Braava)\b", "iRobot", "iot", None, False, None),
    (r"\beero\b", "eero", "router", None, False, None),
    (r"\bOrbi\b", "Netgear", "router", None, False, None),
    (r"\bVelop\b", "Linksys", "router", None, False, None),
    (r"\bNVIDIA SHIELD\b|\bSHIELD TV\b", "NVIDIA", "streaming", None, True, None),  # not bare "shield": too common a word
]
NAME_RULES = [(re.compile(r, re.I), *rest) for r, *rest in NAME_RULES]

SSID_RULES = [
    (re.compile(r"^DIRECT-\w{2}-?(HP|.*LaserJet|.*OfficeJet)", re.I), "HP", "printer", None),
    (re.compile(r"^DIRECT-\w{2}-?.*(EPSON|Brother|Canon)", re.I), None, "printer", None),
    (re.compile(r"^DIRECT-\w{2}-?.*\[TV\]", re.I), "Samsung", "tv", None),
    (re.compile(r"^DIRECT-", re.I), None, "media", None),
    (re.compile(r"iPhone|iPad", re.I), "Apple", "hotspot", "iOS"),
    (re.compile(r"AndroidAP|Galaxy|Pixel|Redmi|OnePlus|HUAWEI", re.I), None, "hotspot", "Android"),
    (re.compile(r"Tesla|^VW[ _]|Audi|BMW|Mercedes|Ford|Toyota|Volvo|Polestar", re.I), None, "car", None),
    (re.compile(r"Chromecast|Google-Home", re.I), "Google", "streaming", None),
    (re.compile(r"^ESP_|^ESP-|^Tasmota|^shelly", re.I), None, "iot", None),
    (re.compile(r"Ring Setup|Wyze|Arlo", re.I), None, "camera", None),
]

# MAC vendor (OUI) hints: regex on the vendor name -> (brand, type, type confidence)
VENDOR_RULES = [
    (r"\bApple\b", "Apple", None, 0), (r"\bSamsung\b", "Samsung", None, 0), (r"\bGoogle\b", "Google", None, 0),
    (r"\bNest\b", "Google Nest", "smart_home", 50), (r"\bEspressif\b", "Espressif", "iot", 60),
    (r"\bRaspberry\b", "Raspberry Pi", "sbc", 70), (r"\bSonos\b", "Sonos", "speaker", 75),
    (r"\bAmazon\b", "Amazon", "speaker", 30), (r"\bRoku\b", "Roku", "streaming", 70),
    (r"\bRing\b", "Ring", "camera", 60), (r"\bNintendo\b", "Nintendo", "console", 60),
    (r"Sony Interactive", "Sony", "console", 70), (r"\bSony\b", "Sony", None, 0),
    (r"\bMicrosoft\b", "Microsoft", None, 0), (r"\bLG Electronics\b", "LG", None, 0),
    (r"\b(Hikvision|Dahua|Reolink)\b", None, "camera", 70), (r"\bTuya\b", "Tuya", "iot", 60),
    (r"\b(Signify|Philips Lighting)\b", "Philips Hue", "light", 70), (r"\bXiaomi\b", "Xiaomi", None, 0),
    (r"\bHuawei\b", "Huawei", None, 0), (r"\bOnePlus\b", "OnePlus", "phone", 60), (r"\bGarmin\b", "Garmin", "watch", 50),
    (r"\bFitbit\b", "Fitbit", "wearable", 70), (r"\bTesla\b", "Tesla", "car", 70),
    (r"\bSynology\b", "Synology", "nas", 80), (r"\bQNAP\b", "QNAP", "nas", 80),
    (r"\biRobot\b", "iRobot", "iot", 75), (r"\becobee\b", "ecobee", "smart_home", 75),
    (r"\b(Seiko Epson|Brother|Canon)\b", None, "printer", 55), (r"\bHewlett|\bHP Inc", "HP", None, 0),
    (r"\b(Ubiquiti|TP-LINK|TP-Link|Netgear|Cisco|Linksys|AVM|ASUSTek|Zyxel|MikroTik|Aruba|Ruckus|D-Link|"
     r"Arcadyan|Sagemcom|Technicolor|Compal Broadband|Eero|Juniper)\b", None, "network", 0),
    (r"Automotive|\bAlpine Electronics\b|\bVisteon\b|\bBosch Car\b", None, "car", 65),
    (r"\b(Bose|Sennheiser|Jabra|GN Netcom|Harman|Bang & Olufsen)\b", None, "headphones", 45),
    (r"\b(Intel|Realtek|MediaTek|Qualcomm|Liteon|LITE-ON|AzureWave|Hon Hai|Murata|Universal Global|Broadcom|"
     r"Ralink|Atheros|Chicony|Rivet)\b", None, "computer", 25),
]
VENDOR_RULES = [(re.compile(r, re.I), *rest) for r, *rest in VENDOR_RULES]
SUFFIXES = re.compile(r"[,.]?\s+(Inc|Co|Ltd|Corp(oration)?|LLC|GmbH|AG|S\.?A|Limited|Technologies|Technology|"
                      r"Electronics|Communications|International|Trading|Group|Holding|Systems|Automotive)\b.*$", re.I)


def short_vendor(v):
    if not v:
        return None
    for rx, brand, *_ in VENDOR_RULES:
        if brand and rx.search(v):
            return brand
    return SUFFIXES.sub("", v).strip(" ,.") or v


def tidy_model(text):
    """A model name found in a name or hostname: separators become spaces ("Galaxy-S23-Ultra" -> "Galaxy S23 Ultra") and an all
    lowercase one (routers often lowercase hostnames) gets its capitals back."""
    t = re.sub(r"[ _-]+", " ", text).strip()
    if t == t.lower():
        t = " ".join({"fe": "FE", "xl": "XL", "5g": "5G"}.get(w) or (w.capitalize() if w[:1].isalpha() else w) for w in t.split())
    return t


# Samsung model numbers: SM-<line letter><3 digits><region letters>, e.g. SM-S918B. The line letter says what kind of device it is (Samsung
# publishes no table, so these are the commonly documented lines). Marketing names only for models confirmed from published model lists.
SM_RX = re.compile(r"\bSM-([A-Z])(\d{3})([A-Z0-9]{0,3})\b", re.I)
SM_TYPES = {"A": "phone", "S": "phone", "G": "phone", "N": "phone", "F": "phone", "M": "phone", "J": "phone",
            "T": "tablet", "X": "tablet", "P": "tablet"}
SM_NAMES = {  # letter + digits -> (marketing name, year)
    "S921": ("Galaxy S24", 2024), "S926": ("Galaxy S24+", 2024), "S928": ("Galaxy S24 Ultra", 2024),
    "S911": ("Galaxy S23", 2023), "S916": ("Galaxy S23+", 2023), "S918": ("Galaxy S23 Ultra", 2023),
    "S901": ("Galaxy S22", 2022), "S906": ("Galaxy S22+", 2022), "S908": ("Galaxy S22 Ultra", 2022),
    "G991": ("Galaxy S21", 2021), "G996": ("Galaxy S21+", 2021), "G998": ("Galaxy S21 Ultra", 2021),
    "F741": ("Galaxy Z Flip6", 2024), "F946": ("Galaxy Z Fold5", 2023),
}


def samsung_model_evidence(ev, years, text, source):
    """Evidence from a Samsung model number in `text` (a WPS model, a device or Bluetooth name). True when there was one."""
    m = SM_RX.search(text or "")
    if not m:
        return False
    letter, digits = m.group(1).upper(), m.group(2)
    number = f"SM-{letter}{digits}{m.group(3).upper()}"
    src = f"{source}: Samsung model number {number}"
    ev.add("brand", "Samsung", 88, src)
    if letter in SM_TYPES:
        ev.add("type", SM_TYPES[letter], 78, src)
        ev.add("os", "Android", 70, src)
    known = SM_NAMES.get(letter + digits)
    ev.add("model", known[0] if known else number, 90 if known else 80, src)
    if known:
        years.append((known[1], f"{known[0]} released {known[1]}"))
    return True


class Evidence:
    def __init__(self):
        self.items = []

    def add(self, field, value, conf, source):
        if value is not None and value != "":
            self.items.append({"field": field, "value": value, "conf": conf, "source": source})

    def best(self, field):
        cands = [e for e in self.items if e["field"] == field]
        return max(cands, key=lambda e: e["conf"]) if cands else None


def identify(dev):
    """Return identification columns + a detailed 'ident' dict for a device record."""
    ev = Evidence()
    kind = dev.get("kind")
    extra = dev.get("extra") or {}
    fp = extra.get("fp") or {}
    name, vendor, ssid = dev.get("name"), dev.get("vendor"), dev.get("ssid")
    wfp, bfp, lfp = fp.get("wifi") or {}, fp.get("ble") or {}, fp.get("lan") or {}
    years = []
    if lfp:
        lan_evidence(ev, lfp, years)

    # --- MAC vendor
    if vendor and not dev.get("randomized"):
        for rx, brand, typ, tconf in VENDOR_RULES:
            if rx.search(vendor):
                if brand:
                    ev.add("brand", brand, 50, f"MAC vendor {vendor}")
                elif typ == "network" or (tconf and tconf > 25):
                    # Network gear / product makers: the vendor is the brand (unlike Wi-Fi module makers).
                    ev.add("brand", short_vendor(vendor), 50, f"MAC vendor {vendor}")
                if typ and tconf and not (typ == "network" and kind not in ("ap", "lan")):
                    label = "Wi-Fi module maker (common in laptops/PCs)" if tconf == 25 else f"MAC vendor {vendor}"
                    ev.add("type", typ, tconf, label)
                break
        else:
            ev.add("brand", short_vendor(vendor), 40, f"MAC vendor {vendor}")
    elif vendor and kind == "ble":
        ev.add("brand", vendor, 45, "Bluetooth manufacturer data")

    # --- kind defaults
    if kind == "ap":
        ev.add("type", "router", 40, "Transmits beacons (access point)")
    if dev.get("randomized") and kind == "wifi_client":
        ev.add("type", "phone", 25, "Randomized MAC (default on phones)")

    # --- names / SSIDs
    for text, what in ((name, "Device name"), (ssid if kind == "ap" else None, "Network name")):
        if not text:
            continue
        samsung_model_evidence(ev, years, text, f"{what} “{text}”")
        for rx, brand, typ, os_, as_model, year in NAME_RULES:
            m = rx.search(text)
            if m:
                ev.add("brand", brand, 70, f"{what} “{text}”")
                ev.add("type", typ, 70 if what == "Device name" else 45, f"{what} “{text}”")
                ev.add("os", os_, 65, f"{what} “{text}”")
                if as_model:
                    ev.add("model", tidy_model(m.group(0)), 60, f"{what} “{text}”")
                break
    if kind == "ap" and ssid:
        for rx, brand, typ, os_ in SSID_RULES:
            if rx.search(ssid):
                ev.add("brand", brand, 60, f"Network name “{ssid}”")
                ev.add("type", typ, 72, f"Network name “{ssid}”")
                ev.add("os", os_, 55, f"Network name “{ssid}”")
                break

    # --- Wi-Fi capabilities
    if wfp:
        gen = wfp.get("gen")
        six = dev.get("band") == "6"
        if gen:
            label = "Wi-Fi 6E" if gen == 6 and six else f"Wi-Fi {gen}"
            parts = [p for p in (f"{wfp['ss']}×{wfp['ss']} MIMO" if wfp.get("ss") else None,
                                 f"up to {wfp['width']} MHz" if wfp.get("width") else None) if p]
            ev.add("wifi", label, 90, "Capabilities in " + ("beacons" if kind == "ap" else "probe/association requests")
                   + (f" ({', '.join(parts)})" if parts else ""))
            years.append((WIFI_6E_YEAR if gen == 6 and six else WIFI_GEN_YEAR[gen], f"supports {label}"))
        else:
            ev.add("wifi", "Wi-Fi 3 or older (802.11a/b/g)", 70, "No HT/VHT/HE capabilities advertised")
            years.append((2003, "802.11g era"))
        for oui in wfp.get("vendors", []):
            vname = VENDOR_IES.get(oui)
            if oui == "00:17:f2":
                ev.add("brand", "Apple", 80, "Apple vendor element in Wi-Fi frames")
                if kind == "wifi_client":
                    ev.add("os", "iOS / macOS", 55, "Apple vendor element in Wi-Fi frames")
                    if dev.get("randomized"):
                        ev.add("type", "phone", 50, "Apple device probing with private address (iPhone/iPad)")
            elif oui == "00:00:f0":
                ev.add("brand", "Samsung", 70, "Samsung vendor element in Wi-Fi frames")
            elif vname and oui not in ("00:50:f2", "50:6f:9a"):
                ev.add("chipset", vname, 50, f"Vendor element {oui}")
        for f in wfp.get("wfa", []):
            ev.add("feature", f, 80, "Wi-Fi Alliance vendor element")
            if f.startswith("MBO") and kind == "wifi_client":
                years.append((2018, "advertises MBO (2018+)"))
        wps = wfp.get("wps") or {}
        if wps:
            src = "WPS information"
            if wps.get("manufacturer"):
                ev.add("brand", short_vendor(wps["manufacturer"]), 88, f"{src}: manufacturer “{wps['manufacturer']}”")
            model = " ".join(x for x in (wps.get("model"), wps.get("model_number")) if x and x != wps.get("manufacturer"))
            if model:
                ev.add("model", model, 85, f"{src}: model")
                samsung_model_evidence(ev, years, model, src)
            if wps.get("device_name"):
                ev.add("name", wps["device_name"], 80, f"{src}: device name")
                samsung_model_evidence(ev, years, wps["device_name"], f"{src}: device name")
                for rx, brand, typ, os_, _m, _y in NAME_RULES:
                    if rx.search(wps["device_name"]):
                        ev.add("brand", brand, 72, f"{src}: device name “{wps['device_name']}”")
                        ev.add("type", typ, 72, f"{src}: device name “{wps['device_name']}”")
                        ev.add("os", os_, 70, f"{src}: device name “{wps['device_name']}”")
                        break
            cat = wps.get("category")
            if cat in WPS_CATEGORY:
                base, subs = WPS_CATEGORY[cat]
                ev.add("type", subs.get(wps.get("subcategory"), base), 88, f"{src}: device category {cat}")

    # --- Bluetooth Low Energy
    if bfp:
        model = APPLE_MODELS.get(bfp.get("apple_model"))
        if model:
            ev.add("brand", "Beats (Apple)" if model[0].startswith(("Beats", "Powerbeats")) else "Apple", 95,
                   "Apple proximity-pairing message")
            ev.add("model", model[0], 92, "Apple proximity-pairing model ID")
            ev.add("type", model[1], 92, "Apple proximity-pairing model ID")
            years.append((model[2], f"{model[0]} released {model[2]}"))
        apple = set(bfp.get("apple", []))
        if apple:
            ev.add("brand", "Apple", 85, "Apple Continuity advertisement")
            msgs = ", ".join(APPLE_TYPES.get(t, f"0x{t:02x}") for t in sorted(apple))
            if apple & {0x0C, 0x10, 0x0F, 0x05}:
                ev.add("type", "phone", 45, f"Continuity messages: {msgs} (iPhone, iPad or Mac)")
                ev.add("os", "iOS / macOS", 70, f"Continuity messages: {msgs}")
            if 0x09 in apple:
                ev.add("type", "streaming", 55, "AirPlay target (Apple TV / HomePod / Mac)")
            if apple == {0x12}:
                ev.add("type", "tag", 60, "Only Find My messages (AirTag or offline Apple device)")
            if 0x02 in apple:
                ev.add("type", "beacon", 65, "iBeacon")
        cdp = MS_CDP_TYPES.get(bfp.get("ms_type"))
        if cdp:
            label, typ, brand, os_ = cdp
            ev.add("type", typ, 85, f"Microsoft CDP beacon: {label}")
            ev.add("os", os_, 85, f"Microsoft CDP beacon: {label}")
            ev.add("brand", brand, 80, f"Microsoft CDP beacon: {label}")
        for u in bfp.get("uuids", []):
            if u in BLE_UUIDS:
                label, typ, brand, conf = BLE_UUIDS[u]
                ev.add("type", typ, conf, f"Service {label} (0x{u})")
                ev.add("brand", brand, conf, f"Service {label} (0x{u})")
                ev.add("feature", label, 70, f"Service UUID 0x{u}")
        if bfp.get("ext_adv"):
            ev.add("feature", "Bluetooth 5 extended advertising", 90, "Extended advertising reports")
            years.append((2017, "Bluetooth 5 extended advertising (2017+)"))
    app = extra.get("appearance")
    if app in APPEARANCE_TYPES:
        ev.add("type", APPEARANCE_TYPES[app], 75, f"BLE appearance “{app}”")
    if extra.get("company") and kind == "ble" and not extra["company"].startswith(("Company 0x", "Unregistered 0x")):
        ev.add("brand", extra["company"], 55, "BLE manufacturer data")

    # --- Bluetooth Classic class of device
    cod = extra.get("cod")
    if cod:
        try:
            c = int(cod, 16) if isinstance(cod, str) else int(cod)
        except ValueError:
            c = None
        if c:
            major, minor = (c >> 8) & 0x1F, (c >> 2) & 0x3F
            if major == 6:
                typ = next((t for t, bit in COD_IMAGING_FLAGS if minor & bit), None)
            else:
                typ = COD_MINOR.get(major, {}).get(minor) or COD_MAJOR_TYPE.get(major)
            ev.add("type", typ, 80, f"Bluetooth class of device {cod}")
    elif extra.get("class") and kind == "bt_classic":
        ev.add("type", {"audio/video": "media", "computer": "computer", "phone": "phone",
                        "wearable": "wearable"}.get(extra["class"]), 55, f"Bluetooth device class “{extra['class']}”")

    # --- resolve
    out = {}
    for f in ("brand", "model", "type", "os", "wifi", "chipset"):
        b = ev.best(f)
        out[f] = b["value"] if b else None
        out[f + "_conf"] = b["conf"] if b else 0
    era = max(years) if years else None
    gen = wfp.get("gen") if wfp else None
    six = dev.get("band") == "6"
    hint = None
    model_year = next((y for y in years if "released" in y[1]), None)
    if model_year:
        hint = model_year[1]
    elif era:
        # For phones, computers, TVs etc. the newest Wi-Fi standard supported bounds the age from both sides:
        # it can't predate the standard, and models made once the next standard was common usually support
        # it. Printers, IoT and accessories still ship with old Wi-Fi, so only the lower bound applies there.
        bounded = out["type"] in ("phone", "tablet", "laptop", "desktop", "computer", "hotspot", "tv",
                                  "streaming", "console", "router", "watch")
        ranges = {2003: "≈2003–2010", 2009: "typically 2009–2016", 2013: "typically 2013–2020"}
        when = ranges.get(era[0]) if bounded or era[0] == 2003 else None
        hint = f"{when or f'{era[0]} or newer'} · {era[1]}"
    ident = {
        "version": IDENT_VERSION,
        "label": label_for(out),
        "fields": {f: {"value": out[f], "conf": out[f + "_conf"],
                       "level": next(l for t, l in CONF_LABEL if out[f + "_conf"] >= t)}
                   for f in ("brand", "model", "type", "os", "wifi", "chipset") if out[f]},
        "features": sorted({e["value"] for e in ev.items if e["field"] == "feature"}),
        "era": era[0] if era else None, "age_hint": hint,
        "wifi_caps": {k: wfp[k] for k in ("gen", "ss", "width", "vendors", "wfa") if wfp.get(k)} if wfp else None,
        "wps": wfp.get("wps") if wfp else None,
        "evidence": sorted(ev.items, key=lambda e: -e["conf"]),
    }
    return {
        "brand": out["brand"], "model": out["model"], "dev_type": out["type"], "os": out["os"],
        # 66 = Wi-Fi 6E, 3 = legacy 802.11a/b/g only
        "wifi_gen": (66 if gen == 6 and six else gen) if gen else (3 if wfp else None),
        "era": era[0] if era else None, "ident": ident,
    }


def label_for(o):
    brand, model = o["brand"], o["model"]
    if brand and model and brand.split(" (")[0].lower() in model.lower():
        brand = None  # model already names the brand ("HP OfficeJet")
    head = " ".join(p for p in (brand, model) if p)
    t = TYPE_LABELS.get(o["type"]) if o["type"] else None
    return " · ".join(p for p in (head, t) if p) or None
