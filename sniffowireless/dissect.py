"""Decoding recorded frames for the frame inspector (Settings -> Frame recording -> Open).

Every frame of a recording (capture.py) is turned into a one-line summary for the frame list (source, destination, protocol, info) and,
when it is opened, into a tree of fields like Wireshark's: each node has a name, a value and the bytes it was read from, so the page can
highlight them in the hex view. Wi-Fi frames are decoded from their radiotap and 802.11 headers and tagged elements, Bluetooth from
the HCI event (advertising reports, inquiry results and their AD structures), Zigbee / Thread from the 802.15.4 MAC header, the
Zigbee network header and the beacon payloads, LoRa from the sniffer line and the Meshtastic, LoRaWAN, MeshCore and APRS layouts.

The layouts are those of the published specifications (radiotap.org, IEEE 802.11-2020, Bluetooth Core 5.4 Vol 4 Part E and the
Assigned Numbers, IEEE 802.15.4-2015, Zigbee 3.0 / Zigbee PRO, the Thread beacon of OpenThread, LoRaWAN 1.0.4, the Meshtastic and
MeshCore packet formats). Nothing is trusted: a frame that ends early gets a "malformed" node where it ran out, like Wireshark does.
"""
import functools
import struct
import threading
import time
import zlib

from .lora_protocols import classify
from .oui import bt_company
from .zigbee_radio import _pans_present

MALFORMED = "[Malformed: the frame ends early]"


class Truncated(Exception):
    pass


def node(name, value=None, off=None, length=None, children=None):
    n = {"n": name}
    if value is not None:
        n["v"] = str(value)
    if off is not None:
        n["o"], n["l"] = off, length
    if children:
        n["c"] = children
    return n


class Reader:
    """Reads little-endian values from `data[start:end]` and remembers where each came from."""

    def __init__(self, data, at=0, end=None):
        self.d, self.at, self.end = data, at, len(data) if end is None else end

    def need(self, n):
        if self.at + n > self.end:
            raise Truncated

    def take(self, n):
        self.need(n)
        v = self.d[self.at:self.at + n]
        self.at += n
        return v

    def u8(self):
        self.need(1)
        self.at += 1
        return self.d[self.at - 1]

    def u16(self, big=False):
        return int.from_bytes(self.take(2), "big" if big else "little")

    def u24(self):
        return int.from_bytes(self.take(3), "little")

    def u32(self, big=False):
        return int.from_bytes(self.take(4), "big" if big else "little")

    def u64(self):
        return int.from_bytes(self.take(8), "little")

    def left(self):
        return max(0, self.end - self.at)


@functools.lru_cache(maxsize=16384)   # the same flags with the same values come back frame after frame
def bits(value, width, mask, label, text=None):
    """One flag or bit range shown the Wireshark way: `.... ..1. = Retry: set`."""
    shift = (mask & -mask).bit_length() - 1
    field = (value & mask) >> shift
    pattern = "".join(("1" if value >> i & 1 else "0") if mask >> i & 1 else "." for i in range(width - 1, -1, -1))
    pattern = " ".join(pattern[i:i + 4] for i in range(0, width, 4))
    if text is None:
        text = ("set" if field else "not set") if mask & (mask - 1) == 0 else str(field)
    return f"{pattern} = {label}: {text}"


LIGHT = threading.local()   # .on while only summaries are wanted (reading a whole recording): bit-by-bit fields are skipped


def flag_nodes(value, width, table, off, length):
    if getattr(LIGHT, "on", False):
        return []
    return [node(bits(value, width, mask, label, text(value & mask) if callable(text) else None), off=off, length=length)
            for mask, label, text in table]


def mac(b):
    return ":".join(f"{x:02x}" for x in b)


def rev_mac(b):
    return ":".join(f"{x:02x}" for x in reversed(b))


def hexs(b, limit=64):
    h = bytes(b).hex()
    return h if len(h) <= limit * 2 else h[:limit * 2] + "…"


def text(b):
    s = bytes(b).decode("utf-8", "replace")
    return "".join(ch if ch.isprintable() else "·" for ch in s)


# ================================================================================================================ Wi-Fi
def freq_channel(f):
    if 2412 <= f <= 2472:
        return (f - 2407) // 5
    if f == 2484:
        return 14
    if 5955 <= f <= 7115:
        return (f - 5950) // 5
    if 5000 <= f <= 5925:
        return (f - 5000) // 5
    return None


def band_of(f):
    return "2.4 GHz" if f < 3000 else "6 GHz" if f >= 5955 else "5 GHz"


RT_FLAGS = ((0x01, "CFP", None), (0x02, "Short preamble", None), (0x04, "WEP", None), (0x08, "Fragmentation", None),
            (0x10, "FCS at end", None), (0x20, "Data pad", None), (0x40, "Bad FCS", None), (0x80, "Short GI", None))
RT_CHANNEL_FLAGS = ((0x0010, "Turbo", None), (0x0020, "CCK", None), (0x0040, "OFDM", None), (0x0080, "2 GHz spectrum", None),
                    (0x0100, "5 GHz spectrum", None), (0x0200, "Passive", None), (0x0400, "Dynamic CCK-OFDM", None), (0x0800, "GFSK", None))
# bit: (name, alignment, size)
RT_FIELDS = {0: ("TSFT", 8, 8), 1: ("Flags", 1, 1), 2: ("Data rate", 1, 1), 3: ("Channel", 2, 4), 4: ("FHSS", 1, 2),
             5: ("Antenna signal", 1, 1), 6: ("Antenna noise", 1, 1), 7: ("Lock quality", 2, 2), 8: ("TX attenuation", 2, 2),
             9: ("dB TX attenuation", 2, 2), 10: ("dBm TX power", 1, 1), 11: ("Antenna", 1, 1), 12: ("dB antenna signal", 1, 1),
             13: ("dB antenna noise", 1, 1), 14: ("RX flags", 2, 2), 15: ("TX flags", 2, 2), 16: ("RTS retries", 1, 1),
             17: ("Data retries", 1, 1), 18: ("XChannel", 4, 8), 19: ("MCS information", 1, 3), 20: ("A-MPDU status", 4, 8),
             21: ("VHT information", 2, 12), 22: ("Timestamp", 8, 12), 23: ("HE information", 2, 12), 24: ("HE-MU information", 2, 12),
             25: ("HE-MU other user", 2, 6), 26: ("0-length PSDU", 1, 1), 27: ("L-SIG", 2, 4)}


def radiotap(d, info):
    """The radiotap header: returns (node, length). Fills info with signal, channel, rate and whether an FCS ends the frame."""
    r = Reader(d)
    kids = [node("Header revision", r.u8(), 0, 1), node("Header pad", r.u8(), 1, 1)]
    length = r.u16()
    kids.append(node("Header length", length, 2, 2))
    if length < 8 or length > len(d):
        raise Truncated
    words, at = [], 4
    while True:
        if at + 4 > length:
            raise Truncated
        w = int.from_bytes(d[at:at + 4], "little")
        words.append((at, w))
        at += 4
        if not w & 0x80000000:
            break
    present = []
    for i, (o, w) in enumerate(words):
        names = [RT_FIELDS[b][0] for b in range(29) if w >> b & 1 and b in RT_FIELDS]
        extra = [n for b, n in ((29, "Radiotap namespace next"), (30, "Vendor namespace next"), (31, "Ext")) if w >> b & 1]
        present.append(node(f"Present flags word {i}", f"0x{w:08x}", o, 4, [node(n) for n in names + extra] or None))
    kids.append(node("Present flags", None, 4, at - 4, present))
    p = at
    vendor = False
    for i, (_, w) in enumerate(words):
        if vendor:
            break
        for b in range(29):
            if not w >> b & 1:
                continue
            if b not in RT_FIELDS:
                kids.append(node("Fields with no known layout follow", None, p, length - p))
                p = length
                vendor = True
                break
            name, align, size = RT_FIELDS[b]
            p = (p + align - 1) // align * align
            if p + size > length:
                raise Truncated
            v = d[p:p + size]
            kids.append(radiotap_field(b, name, v, p, size, info, antenna=i))
            p += size
        if w >> 30 & 1:  # a vendor namespace: OUI, sub-namespace, skip length; its fields are not decoded
            vendor = True
            p = (p + 1) // 2 * 2
            if p + 6 <= length:
                skip = int.from_bytes(d[p + 4:p + 6], "little")
                kids.append(node("Vendor namespace", f"{mac(d[p:p + 3])}, sub-namespace {d[p + 3]}", p, min(6 + skip, length - p)))
    return node("Radiotap Header v0", f"Length {length}", 0, length, kids), length


def radiotap_field(b, name, v, off, size, info, antenna=0):
    if b == 0:
        return node("MAC timestamp", f"{int.from_bytes(v, 'little')} µs", off, size)
    if b == 1:
        info["fcs"] = bool(v[0] & 0x10)
        return node("Flags", f"0x{v[0]:02x}", off, size, flag_nodes(v[0], 8, RT_FLAGS, off, 1))
    if b == 2:
        info.setdefault("rate", v[0] / 2)
        return node("Data rate", f"{v[0] / 2:g} Mb/s", off, size)
    if b == 3:
        f, fl = int.from_bytes(v[:2], "little"), int.from_bytes(v[2:], "little")
        ch = freq_channel(f)
        info.setdefault("freq", f)
        info.setdefault("channel", ch)
        return node("Channel", f"{f} MHz" + (f" (channel {ch}, {band_of(f)})" if ch else ""), off, size,
                    [node("Frequency", f"{f} MHz", off, 2), node("Channel flags", f"0x{fl:04x}", off + 2, 2, flag_nodes(fl, 16, RT_CHANNEL_FLAGS, off + 2, 2))])
    if b in (5, 6, 10):
        dbm = struct.unpack("b", v)[0]
        if b == 5:
            info.setdefault("rssi", dbm)  # the first one is the combined signal; antennas follow in later namespaces
        label = {5: "Antenna signal", 6: "Antenna noise", 10: "TX power"}[b]
        return node(label + (f" (namespace {antenna})" if antenna else ""), f"{dbm} dBm", off, size)
    if b == 11:
        return node("Antenna", v[0], off, size)
    if b == 19:
        known, flags, idx = v[0], v[1], v[2]
        bw = ("20", "40", "20L", "20U")[flags & 3] if known & 1 else "?"
        gi = ("long", "short")[flags >> 2 & 1] if known & 4 else "?"
        info.setdefault("mcs", idx)
        return node("MCS information", f"MCS {idx}, {bw} MHz, {gi} GI", off, size)
    if b == 21:
        bw = {0: "20", 1: "40", 4: "80", 11: "160"}.get(v[3] & 0x1F, str(v[3] & 0x1F))
        mcs = v[4] >> 4
        nss = v[4] & 0x0F
        return node("VHT information", f"MCS {mcs}, {nss} spatial stream(s), {bw} MHz" if nss else f"{bw} MHz", off, size)
    if b == 18:
        f = int.from_bytes(v[4:6], "little")
        info.setdefault("freq", f)
        info.setdefault("channel", v[6] or freq_channel(f))
        return node("XChannel", f"{f} MHz, channel {v[6]}", off, size)
    return node(name, bytes(v).hex(), off, size)


MGMT = {0: "Association Request", 1: "Association Response", 2: "Reassociation Request", 3: "Reassociation Response", 4: "Probe Request",
        5: "Probe Response", 6: "Timing Advertisement", 8: "Beacon frame", 9: "ATIM", 10: "Disassociation", 11: "Authentication",
        12: "Deauthentication", 13: "Action", 14: "Action No Ack"}
CTRL = {2: "Trigger", 3: "TACK", 4: "Beamforming Report Poll", 5: "NDP Announcement", 6: "Control Frame Extension", 7: "Control Wrapper",
        8: "Block Ack Request", 9: "Block Ack", 10: "PS-Poll", 11: "Request-to-send", 12: "Clear-to-send", 13: "Acknowledgement",
        14: "CF-End", 15: "CF-End + CF-Ack"}
DATA = {0: "Data", 1: "Data + CF-Ack", 2: "Data + CF-Poll", 3: "Data + CF-Ack + CF-Poll", 4: "Null function (No data)", 5: "CF-Ack (No data)",
        6: "CF-Poll (No data)", 7: "CF-Ack + CF-Poll (No data)", 8: "QoS Data", 9: "QoS Data + CF-Ack", 10: "QoS Data + CF-Poll",
        11: "QoS Data + CF-Ack + CF-Poll", 12: "QoS Null function (No data)", 14: "QoS CF-Poll (No data)", 15: "QoS CF-Ack + CF-Poll (No data)"}
FC_FLAGS = ((0x01, "To DS", None), (0x02, "From DS", None), (0x04, "More fragments", None), (0x08, "Retry", None),
            (0x10, "Power management", None), (0x20, "More data", None), (0x40, "Protected", None), (0x80, "+HTC/Order", None))
REASONS = {1: "Unspecified", 2: "Previous authentication no longer valid", 3: "Deauthenticated because sending STA is leaving (or has left) the BSS",
           4: "Disassociated due to inactivity", 5: "Disassociated because AP is unable to handle all currently associated STAs",
           6: "Class 2 frame received from nonauthenticated STA", 7: "Class 3 frame received from nonassociated STA",
           8: "Disassociated because sending STA is leaving (or has left) the BSS", 9: "STA requesting (re)association is not authenticated",
           10: "Power capability element is unacceptable", 11: "Supported channels element is unacceptable", 13: "Invalid element",
           14: "Message integrity code (MIC) failure", 15: "4-way handshake timeout", 16: "Group key handshake timeout",
           17: "Element in 4-way handshake differs from (re)association request", 18: "Invalid group cipher", 19: "Invalid pairwise cipher",
           20: "Invalid AKMP", 21: "Unsupported RSNE version", 22: "Invalid RSNE capabilities", 23: "IEEE 802.1X authentication failed",
           24: "Cipher suite rejected because of the security policy", 34: "Disassociated because of excessive frame losses (poor channel)",
           36: "Requesting STA is leaving the BSS (or resetting)", 39: "Peer STA does not support the requested cipher suite",
           45: "Peer STA does not support the requested cipher suite", 46: "Disassociated: the AP is being disbanded"}
STATUSES = {0: "Successful", 1: "Unspecified failure", 10: "Cannot support all requested capabilities", 12: "Association denied (reason outside 802.11)",
            13: "Authentication algorithm not supported", 14: "Authentication transaction sequence number out of expected sequence",
            15: "Challenge failure", 16: "Authentication timeout", 17: "AP is unable to handle additional associated STAs",
            30: "Association request rejected temporarily; try again later", 31: "Robust management frame policy violation",
            37: "The request has been declined", 40: "Invalid element", 41: "Invalid group cipher", 42: "Invalid pairwise cipher",
            43: "Invalid AKMP", 72: "Anti-clogging token required", 76: "Finite cyclic group not supported", 77: "Unknown password identifier",
            126: "SAE hash-to-element", 123: "SAE public key"}
AUTH_ALGOS = {0: "Open System", 1: "Shared Key", 2: "Fast BSS Transition", 3: "SAE", 4: "FILS shared key", 5: "FILS PFS", 6: "FILS public key",
              8: "PASN"}
ACTION_CATEGORIES = {0: "Spectrum Management", 1: "QoS", 3: "Block Ack", 4: "Public", 5: "Radio Measurement", 6: "Fast BSS Transition",
                     7: "HT", 8: "SA Query", 9: "Protected Dual of Public Action", 10: "WNM", 11: "Unprotected WNM", 12: "TDLS", 13: "Mesh",
                     14: "Multihop", 15: "Self-protected", 17: "WMM", 21: "VHT", 30: "HE", 31: "Protected HE", 126: "Vendor-specific Protected",
                     127: "Vendor-specific"}
CAPABILITIES = ((0x0001, "ESS capabilities", None), (0x0002, "IBSS status", None), (0x0010, "Privacy", None), (0x0020, "Short preamble", None),
                (0x0100, "Spectrum management", None), (0x0200, "QoS", None), (0x0400, "Short slot time", None), (0x1000, "Radio measurement", None),
                (0x8000, "Immediate Block Ack", None))
ELEMENTS = {0: "SSID", 1: "Supported Rates", 3: "DS Parameter set", 4: "CF Parameter set", 5: "Traffic Indication Map (TIM)", 6: "IBSS Parameter set",
            7: "Country Information", 10: "Request", 11: "QBSS Load Element", 12: "EDCA Parameter Set", 32: "Power Constraint",
            33: "Power Capability", 35: "TPC Report", 36: "Supported Channels", 37: "Channel Switch Announcement", 42: "ERP Information",
            45: "HT Capabilities", 46: "QoS Capability", 48: "RSN Information", 50: "Extended Supported Rates", 51: "AP Channel Report",
            54: "Mobility Domain", 55: "Fast BSS Transition", 59: "Supported Operating Classes", 61: "HT Information", 62: "Secondary Channel Offset",
            70: "RM Enabled Capabilities", 72: "20/40 BSS Coexistence", 74: "Overlapping BSS Scan Parameters", 107: "Interworking",
            108: "Advertisement Protocol", 111: "Roaming Consortium", 113: "Mesh Configuration", 114: "Mesh ID", 127: "Extended Capabilities",
            191: "VHT Capabilities", 192: "VHT Operation", 195: "VHT Tx Power Envelope", 199: "Operating Mode Notification",
            201: "Reduced Neighbor Report", 221: "Vendor Specific", 244: "RSN eXtension", 255: "Element ID Extension"}
EXT_ELEMENTS = {35: "HE Capabilities", 36: "HE Operation", 37: "UORA Parameter Set", 38: "MU EDCA Parameter Set", 39: "Spatial Reuse Parameter Set",
                59: "HE 6 GHz Band Capabilities", 106: "EHT Operation", 107: "Multi-Link", 108: "EHT Capabilities"}
SUITES = {1: "WEP-40", 2: "TKIP", 4: "CCMP-128 (AES)", 5: "WEP-104", 6: "BIP-CMAC-128", 7: "Group addressed traffic not allowed", 8: "GCMP-128",
          9: "GCMP-256", 10: "CCMP-256", 11: "BIP-GMAC-128", 12: "BIP-GMAC-256", 13: "BIP-CMAC-256"}
AKMS = {1: "802.1X (WPA-Enterprise)", 2: "PSK", 3: "FT over 802.1X", 4: "FT using PSK", 5: "802.1X (SHA256)", 6: "PSK (SHA256)", 8: "SAE (WPA3-Personal)",
        9: "FT using SAE", 11: "802.1X Suite B", 12: "802.1X Suite B-192", 13: "FT over 802.1X (SHA384)", 18: "OWE (Enhanced Open)",
        24: "SAE using group-dependent hash", 25: "FT using SAE group-dependent hash"}
VENDOR_OUIS = {"00:50:f2": "Microsoft", "50:6f:9a": "Wi-Fi Alliance", "00:10:18": "Broadcom", "00:17:f2": "Apple", "00:0c:43": "Ralink / MediaTek",
               "00:03:7f": "Qualcomm Atheros", "00:0c:e7": "MediaTek", "8c:fd:f0": "Qualcomm", "00:13:92": "Ruckus", "00:40:96": "Cisco",
               "00:0b:86": "Aruba", "00:e0:4c": "Realtek", "f4:f5:e8": "Google", "00:90:4c": "Epigram (Broadcom)"}
WPS_ATTRS = {0x1008: "Config Methods", 0x1011: "Device Name", 0x1012: "Device Password ID", 0x1021: "Manufacturer", 0x1023: "Model Name",
             0x1024: "Model Number", 0x103b: "Response Type", 0x103c: "RF Bands", 0x1041: "Selected Registrar", 0x1042: "Serial Number",
             0x1044: "Wi-Fi Protected Setup State", 0x1047: "UUID-E", 0x1048: "UUID-R", 0x1049: "Vendor Extension", 0x104a: "Version",
             0x1053: "Selected Registrar Config Methods", 0x1054: "Primary Device Type", 0x1057: "AP Setup Locked"}
WPS_TEXT = {0x1011, 0x1021, 0x1023, 0x1024, 0x1042}
MEMBERSHIP = {127: "HT PHY", 126: "VHT PHY", 123: "SAE hash-to-element only", 122: "HE PHY", 121: "EHT PHY"}


def suite(b):
    oui, t = mac(b[:3]), b[3]
    if oui == "00:0f:ac":
        return SUITES.get(t, f"type {t}")
    return f"{oui} type {t}"


def akm(b):
    oui, t = mac(b[:3]), b[3]
    return AKMS.get(t, f"type {t}") if oui in ("00:0f:ac", "00:50:f2") else f"{oui} type {t}"


def rsn_body(v, off, wpa=False):
    """RSN (and the older WPA vendor element, same layout with Microsoft's OUI): version, ciphers, key management, capabilities."""
    r = Reader(v)
    out = [node("Version", r.u16(), off, 2)]
    summary = {}
    try:
        g = r.take(4)
        out.append(node("Group cipher suite", suite(g) if not wpa else SUITES.get(g[3], f"type {g[3]}"), off + 2, 4))
        for label, key, fn in (("Pairwise cipher suite", "pairwise", (lambda b: SUITES.get(b[3], f"type {b[3]}")) if wpa else suite),
                               ("Auth Key Management (AKM) suite", "akm", akm)):
            start = r.at
            n = r.u16()
            items = []
            for _ in range(n):
                o = r.at
                b = r.take(4)
                items.append(node(label, fn(b), off + o, 4))
            summary[key] = [x["v"] for x in items]
            out.append(node(f"{label} list", f"{n}: " + ", ".join(summary[key]), off + start, r.at - start, items))
        if r.left() >= 2:
            o = r.at
            caps = r.u16()
            out.append(node("RSN Capabilities", f"0x{caps:04x}", off + o, 2, flag_nodes(caps, 16, (
                (0x0001, "Pre-authentication", None), (0x0002, "No pairwise", None), (0x0040, "Management frame protection required", None),
                (0x0080, "Management frame protection capable", None)), off + o, 2)))
            summary["mfp"] = "required" if caps & 0x40 else "capable" if caps & 0x80 else "off"
        if r.left() >= 2:
            o = r.at
            n = r.u16()
            r.take(16 * n)
            out.append(node("PMKID list", n, off + o, 2 + 16 * n))
        if r.left() >= 4:
            o = r.at
            out.append(node("Group management cipher suite", suite(r.take(4)), off + o, 4))
    except Truncated:
        out.append(node(MALFORMED))
    return out, summary


def element(eid, v, off, info, vendor_name):
    """The decoded fields of one tagged element (off is where its value starts)."""
    kids, val = [], None
    if eid == 0:
        ssid = bytes(v)
        val = '"' + text(ssid) + '"' if ssid.strip(b"\x00") else "Wildcard (hidden or any)"
        info.setdefault("ssid", text(ssid) if ssid.strip(b"\x00") else "")
    elif eid in (1, 50):
        rates = []
        for i, b in enumerate(v):
            r = MEMBERSHIP.get(b & 0x7F) if b & 0x80 and (b & 0x7F) in MEMBERSHIP else None
            label = f"BSS membership: {r}" if r else f"{(b & 0x7F) / 2:g}{'(B)' if b & 0x80 else ''} Mb/s"
            rates.append(label)
            kids.append(node("Rate", label, off + i, 1))
        val = " ".join(rates)
    elif eid == 3 and v:
        val = f"Current channel: {v[0]}"
        info.setdefault("ie_channel", v[0])
    elif eid == 5 and len(v) >= 3:
        val = f"DTIM {v[0]} of {v[1]}, bitmap control 0x{v[2]:02x}"
        kids = [node("DTIM count", v[0], off, 1), node("DTIM period", v[1], off + 1, 1), node("Bitmap control", f"0x{v[2]:02x}", off + 2, 1),
                node("Partial virtual bitmap", hexs(v[3:]), off + 3, len(v) - 3)]
    elif eid == 7 and len(v) >= 3:
        val = f"{text(v[:2])}, environment {'any' if v[2] == 0x20 else 'indoor' if v[2] == 0x49 else 'outdoor' if v[2] == 0x4F else f'0x{v[2]:02x}'}"
        kids = [node("Code", text(v[:2]), off, 2), node("Environment", f"0x{v[2]:02x}", off + 2, 1)]
        for i in range(3, len(v) - 2, 3):
            if v[i] < 200:
                kids.append(node("Channels", f"first {v[i]}, {v[i + 1]} channel(s), max {v[i + 2]} dBm", off + i, 3))
    elif eid == 11 and len(v) >= 5:
        val = f"{int.from_bytes(v[:2], 'little')} stations, channel utilization {v[2] * 100 // 255}%"
        kids = [node("Station count", int.from_bytes(v[:2], "little"), off, 2), node("Channel utilization", f"{v[2]} ({v[2] * 100 // 255}%)", off + 2, 1),
                node("Available admission capacity", int.from_bytes(v[3:5], "little"), off + 3, 2)]
    elif eid == 32 and v:
        val = f"{v[0]} dB"
    elif eid == 37 and len(v) >= 3:
        val = f"mode {v[0]}, new channel {v[1]}, count {v[2]}"
    elif eid == 42 and v:
        val = f"0x{v[0]:02x}"
        kids = flag_nodes(v[0], 8, ((0x01, "Non-ERP present", None), (0x02, "Use protection", None), (0x04, "Barker preamble mode", None)), off, 1)
    elif eid == 45 and len(v) >= 26:
        cap = int.from_bytes(v[:2], "little")
        streams = sum(1 for i in range(4) if v[3 + i])
        val = f"{'20/40' if cap & 2 else '20'} MHz, {streams} spatial stream(s)"
        kids = [node("HT Capabilities Info", f"0x{cap:04x}", off, 2, flag_nodes(cap, 16, (
            (0x0001, "LDPC coding", None), (0x0002, "Supported channel width", lambda x: "20 and 40 MHz" if x else "20 MHz only"),
            (0x0010, "Green field", None), (0x0020, "Short GI for 20 MHz", None), (0x0040, "Short GI for 40 MHz", None),
            (0x0080, "Tx STBC", None), (0x4000, "40 MHz intolerant", None)), off, 2)),
            node("A-MPDU parameters", f"0x{v[2]:02x}", off + 2, 1), node("Rx supported MCS set", hexs(v[3:19]), off + 3, 16)]
        info.setdefault("ht", True)
    elif eid == 48:
        kids, s = rsn_body(v, off)
        val = ", ".join(s.get("akm", [])) or None
        info.setdefault("security", s)
    elif eid == 54 and len(v) >= 3:
        val = f"MDID 0x{int.from_bytes(v[:2], 'little'):04x}"
    elif eid == 61 and len(v) >= 2:
        sec = {0: "none", 1: "above", 3: "below"}.get(v[1] & 3, "?")
        val = f"Primary channel {v[0]}, secondary {sec}"
        kids = [node("Primary channel", v[0], off, 1), node(bits(v[1], 8, 0x03, "Secondary channel offset", sec), off=off + 1, length=1),
                node(bits(v[1], 8, 0x04, "Supported channel width", "any" if v[1] & 4 else "20 MHz"), off=off + 1, length=1)]
    elif eid == 127:
        named = {2: "Extended channel switching", 19: "BSS transition (802.11v)", 22: "Multiple BSSID", 31: "Interworking (Hotspot 2.0)",
                 46: "WNM notification", 62: "Opmode notification", 70: "FTM responder", 71: "FTM initiator"}
        on = [i for i in range(len(v) * 8) if v[i // 8] >> (i % 8) & 1]
        kids = [node(f"Bit {i}", named.get(i, "set"), off + i // 8, 1) for i in on]
        val = ", ".join(named[i] for i in on if i in named) or hexs(v)
    elif eid == 191 and len(v) >= 12:
        c = int.from_bytes(v[:4], "little")
        width = ("80", "160", "80+80 and 160", "?")[c >> 2 & 3]
        val = f"up to {width} MHz"
        kids = [node("VHT Capabilities Info", f"0x{c:08x}", off, 4, flag_nodes(c, 32, (
            (0x0000000C, "Supported channel width set", lambda x: width + " MHz"), (0x00000020, "Short GI for 80 MHz", None),
            (0x00000040, "Short GI for 160 MHz", None), (0x00000800, "SU beamformer", None), (0x00001000, "SU beamformee", None),
            (0x00080000, "MU beamformer", None), (0x00100000, "MU beamformee", None)), off, 4)),
            node("Supported MCS set", hexs(v[4:12]), off + 4, 8)]
        info.setdefault("vht", True)
    elif eid == 192 and len(v) >= 3:
        val = f"{'80/160' if v[0] else '20/40'} MHz, center {v[1]}" + (f"/{v[2]}" if v[2] else "")
    elif eid == 221 and len(v) >= 3:
        oui = mac(v[:3])
        name = VENDOR_OUIS.get(oui) or vendor_name(oui + ":00:00:00") or oui
        t = v[3] if len(v) > 3 else None
        kids = [node("OUI", f"{oui} ({name})", off, 3)]
        if t is not None:
            kids.append(node("Vendor specific OUI type", t, off + 3, 1))
        if oui == "00:50:f2" and t == 1:
            sub, s = rsn_body(v[4:], off + 4, wpa=True)
            kids += sub
            val = "Microsoft: WPA Information Element"
            info.setdefault("wpa", s)
        elif oui == "00:50:f2" and t == 2:
            val = "Microsoft: WMM/WME"
        elif oui == "00:50:f2" and t == 4:
            val = "Microsoft: Wi-Fi Protected Setup"
            kids += wps(v[4:], off + 4, info)
        elif oui == "50:6f:9a":
            val = f"Wi-Fi Alliance: {({9: 'P2P', 0x10: 'Hotspot 2.0 Indication', 0x12: 'OSEN', 0x1c: 'OWE Transition Mode', 0x1a: 'MBO-OCE', 0x16: 'Neighbor Awareness Networking'}).get(t, f'type {t}')}"
        else:
            val = name
    elif eid == 255 and v:
        name = EXT_ELEMENTS.get(v[0], f"extension {v[0]}")
        kids = [node("Element ID extension", f"{name} ({v[0]})", off, 1)]
        if v[0] == 36 and len(v) >= 7:
            color = v[4]
            kids.append(node("BSS color", f"{color & 0x3F}{' (disabled)' if color & 0x80 else ''}", off + 4, 1))
            info.setdefault("he", True)
        elif v[0] == 35:
            info.setdefault("he", True)
        elif v[0] in (106, 108):
            info.setdefault("eht", True)
        if len(v) > 1:
            kids.append(node("Data", hexs(v[1:]), off + 1, len(v) - 1))
    elif v:
        val = hexs(v, 32)
    return val, kids


def wps(v, off, info):
    out, r = [], Reader(v)
    try:
        while r.left() >= 4:
            o = r.at
            t, n = r.u16(big=True), r.u16(big=True)
            data = r.take(n)
            name = WPS_ATTRS.get(t, f"Attribute 0x{t:04x}")
            value = text(data) if t in WPS_TEXT else (str(data[0]) if n == 1 else hexs(data, 24))
            if t in WPS_TEXT:
                info.setdefault("wps", {})[name] = value
            out.append(node(name, value, off + o, 4 + n))
    except Truncated:
        out.append(node(MALFORMED))
    return out


def elements(d, at, end, info, vendor_name):
    if getattr(LIGHT, "on", False):  # for the frame list only the network name and channel are needed
        while at + 2 <= end and at + 2 + d[at + 1] <= end:
            eid, n = d[at], d[at + 1]
            if eid == 0:
                info.setdefault("ssid", text(d[at + 2:at + 2 + n]) if bytes(d[at + 2:at + 2 + n]).strip(b"\x00") else "")
            elif eid == 3 and n:
                info.setdefault("ie_channel", d[at + 2])
            at += 2 + n
        return []
    out = []
    while at < end:
        if at + 2 > end:
            out.append(node(MALFORMED, None, at, end - at))
            break
        eid, n = d[at], d[at + 1]
        if at + 2 + n > end:
            out.append(node(f"Tag: {ELEMENTS.get(eid, f'Unknown ({eid})')}", MALFORMED, at, end - at))
            break
        v = d[at + 2:at + 2 + n]
        val, kids = element(eid, v, at + 2, info, vendor_name)
        name = ELEMENTS.get(eid, f"Reserved ({eid})")
        if eid == 255 and v:
            name = EXT_ELEMENTS.get(v[0], f"Element ID extension {v[0]}")
        out.append(node(f"Tag: {name}", val, at, 2 + n, [node("Tag number", eid, at, 1), node("Tag length", n, at + 1, 1)] + kids))
        at += 2 + n
    return out


def addr_label(b, vendor_name):
    a = mac(b)
    if a == "ff:ff:ff:ff:ff:ff":
        return a, "Broadcast"
    v = vendor_name(a)
    return a, (f"{v}_{a[9:]}" if v else a)


def wifi(raw, meta, vendor_name):
    info = {}
    tree = []
    s = {"proto": "802.11"}
    try:
        rt, at = radiotap(raw, info)
        tree.append(rt)
    except Truncated:
        tree.append(node("Radiotap Header", MALFORMED, 0, len(raw)))
        s.update(info="Malformed radiotap header", color="bad")
        return s, tree
    end = len(raw) - (4 if info.get("fcs") and len(raw) - at >= 14 else 0)
    if at + 2 > end:
        tree.append(node("IEEE 802.11", MALFORMED, at, len(raw) - at))
        s.update(info="Malformed 802.11 frame", color="bad")
        return s, tree
    fc0, fc1 = raw[at], raw[at + 1]
    ftype, sub = fc0 >> 2 & 3, fc0 >> 4
    name = (MGMT if ftype == 0 else CTRL if ftype == 1 else DATA if ftype == 2 else {}).get(sub) or \
        ("Extension" if ftype == 3 else f"Reserved ({ftype}/{sub})")
    hdr = []
    hdr.append(node("Frame Control Field", f"0x{fc0:02x}{fc1:02x}", at, 2, [
        node(bits(fc0, 8, 0x03, "Version", str(fc0 & 3)), off=at, length=1),
        node(bits(fc0, 8, 0x0C, "Type", ("Management", "Control", "Data", "Extension")[ftype] + f" frame ({ftype})"), off=at, length=1),
        node(bits(fc0, 8, 0xF0, "Subtype", str(sub)), off=at, length=1),
        node("Flags", f"0x{fc1:02x}", at + 1, 1, flag_nodes(fc1, 8, FC_FLAGS, at + 1, 1))]))
    r = Reader(raw, at + 2, end)
    to_ds, from_ds, protected = fc1 & 1, fc1 >> 1 & 1, fc1 & 0x40
    src = dst = bssid = None
    seq = None
    try:
        dur = r.u16()
        hdr.append(node("Duration" if not (ftype == 1 and sub == 10) else "Association ID", dur & 0x3FFF if ftype == 1 and sub == 10 else f"{dur} µs",
                        r.at - 2, 2))
        a1 = r.take(6)
        o1 = r.at - 6

        def add(label, b, o):
            a, shown = addr_label(b, vendor_name)
            hdr.append(node(label, f"{shown} ({a})" if shown != a else a, o, 6))
            return a
        if ftype == 1:
            ra = add("Receiver address", a1, o1)
            dst = ra
            if sub in (8, 9, 10, 11, 14, 15, 4, 5, 2) and r.left() >= 6:
                o = r.at
                ta = add("Transmitter address" if sub != 10 else "BSSID", r.take(6), o)
                src = ta
            if sub in (8, 9) and r.left():
                o = r.at
                rest = r.take(r.left())
                hdr.append(node("Block Ack control and information", hexs(rest), o, len(rest)))
        else:
            o2 = r.at
            a2 = r.take(6)
            o3 = r.at
            a3 = r.take(6)
            if ftype == 0:
                dst, src, bssid = add("Destination address", a1, o1), add("Source address", a2, o2), add("BSS Id", a3, o3)
            elif not to_ds and not from_ds:
                dst, src, bssid = add("Receiver/Destination address", a1, o1), add("Transmitter/Source address", a2, o2), add("BSS Id", a3, o3)
            elif to_ds and not from_ds:
                bssid, src, dst = add("Receiver address (BSS Id)", a1, o1), add("Transmitter/Source address", a2, o2), add("Destination address", a3, o3)
            elif from_ds and not to_ds:
                dst, bssid, src = add("Receiver/Destination address", a1, o1), add("Transmitter address (BSS Id)", a2, o2), add("Source address", a3, o3)
            else:
                add("Receiver address", a1, o1)
                add("Transmitter address", a2, o2)
                dst = add("Destination address", a3, o3)
            o = r.at
            sc = r.u16()
            seq = sc >> 4
            hdr.append(node("Sequence control", f"SN={seq}, FN={sc & 15}", o, 2, [node(bits(sc, 16, 0x000F, "Fragment number"), off=o, length=2),
                                                                                  node(bits(sc, 16, 0xFFF0, "Sequence number"), off=o, length=2)]))
            if ftype == 2 and to_ds and from_ds:
                o = r.at
                src = add("Source address", r.take(6), o)
            if ftype == 2 and sub & 8:
                o = r.at
                q = r.u16()
                hdr.append(node("QoS Control", f"TID {q & 15}", o, 2, [node(bits(q, 16, 0x000F, "TID"), off=o, length=2),
                                                                       node(bits(q, 16, 0x0060, "Ack policy", ("Normal Ack", "No Ack", "No explicit Ack", "Block Ack")[q >> 5 & 3]), off=o, length=2),
                                                                       node(bits(q, 16, 0x0080, "A-MSDU present"), off=o, length=2)]))
            if fc1 & 0x80 and (ftype == 0 or sub & 8) and r.left() >= 4:
                o = r.at
                hdr.append(node("HT Control", f"0x{r.u32():08x}", o, 4))
    except Truncated:
        hdr.append(node(MALFORMED))
    tree.append(node(f"IEEE 802.11 {name}", f"Flags: {''.join(c if fc1 >> i & 1 else '.' for i, c in reversed(list(enumerate('TFmRPMpO'))))}",
                     at, r.at - at, hdr))
    body = []
    extra = ""
    body_start = r.at
    if ftype == 0 and r.at < end:
        if protected and sub in (10, 12, 13):
            body.append(node("Encrypted (protected) management frame body", f"{end - r.at} bytes", r.at, end - r.at))
        else:
            fixed, extra = mgmt_fixed(raw, r, sub, info)
            body = [node("Fixed parameters", None, body_start, r.at - body_start, fixed)] if fixed else []
            if not any(x.get("n") == MALFORMED for x in fixed):
                tags = elements(raw, r.at, end, info, vendor_name)
                if tags:
                    body.append(node("Tagged parameters", f"{end - r.at} bytes", r.at, end - r.at, tags))
        tree.append(node("IEEE 802.11 Wireless Management", None, body_start, end - body_start, body))
    elif ftype == 2:
        rest = end - r.at
        if rest > 0:
            tree.append(node("Data", f"{rest} bytes", r.at, rest))
        else:
            tree.append(node("Data", "not recorded: of data frames only the headers are kept"))
    elif r.at < end:
        tree.append(node("Frame body", hexs(raw[r.at:end]), r.at, end - r.at))
    if info.get("fcs") and len(raw) - at >= 14:
        got = int.from_bytes(raw[-4:], "little")
        ok = zlib.crc32(raw[at:-4]) & 0xFFFFFFFF == got
        tree.append(node("Frame check sequence", f"0x{got:08x} [{'correct' if ok else 'incorrect'}]", len(raw) - 4, 4))
        if not ok:
            s["color"] = "bad"
    parts = [name]
    if seq is not None:
        parts.append(f"SN={seq}")
    if ftype == 0 and sub in (8, 5) and "interval" in info:
        parts.append(f"BI={info['interval']}")
    if "ssid" in info:
        parts.append(f"SSID={info['ssid'] or 'Wildcard (Broadcast)'}" if sub == 4 else f'SSID="{info["ssid"]}"' if info["ssid"] else "SSID=<hidden>")
    if protected and ftype == 2:
        parts.append("protected")
    if extra:
        parts.append(extra)
    s.update(src=src or "", dst=("Broadcast" if dst == "ff:ff:ff:ff:ff:ff" else dst) or "", info=", ".join(parts), type=name,
             ssid=info.get("ssid"), rssi=info.get("rssi"), channel=info.get("channel") or info.get("ie_channel"), bssid=bssid)
    s.setdefault("color", "deauth" if ftype == 0 and sub in (10, 12) else "beacon" if ftype == 0 and sub == 8 else
                 "probe" if ftype == 0 and sub in (4, 5) else "mgmt" if ftype == 0 else "ctrl" if ftype == 1 else "data")
    return s, tree


def mgmt_fixed(d, r, sub, info):
    out, extra = [], ""
    try:
        if sub in (5, 8):
            o = r.at
            out.append(node("Timestamp", r.u64(), o, 8))
            o = r.at
            bi = r.u16()
            info["interval"] = bi
            out.append(node("Beacon Interval", f"{bi * 1.024 / 1000:.6f} seconds ({bi} TU)", o, 2))
        if sub in (0, 1, 2, 3, 5, 8):
            o = r.at
            cap = r.u16()
            out.append(node("Capabilities Information", f"0x{cap:04x}", o, 2, flag_nodes(cap, 16, CAPABILITIES, o, 2)))
        if sub in (0, 2):
            o = r.at
            out.append(node("Listen Interval", r.u16(), o, 2))
        if sub == 2:
            o = r.at
            out.append(node("Current AP", mac(r.take(6)), o, 6))
        if sub in (1, 3):
            o = r.at
            st = r.u16()
            out.append(node("Status code", f"{STATUSES.get(st, 'Reserved')} ({st})", o, 2))
            o = r.at
            aid = r.u16()
            out.append(node("Association ID", aid & 0x3FFF, o, 2))
            extra = f"status {st}"
        if sub == 11:
            o = r.at
            alg = r.u16()
            out.append(node("Authentication Algorithm", f"{AUTH_ALGOS.get(alg, 'Reserved')} ({alg})", o, 2))
            o = r.at
            sq = r.u16()
            out.append(node("Authentication SEQ", sq, o, 2))
            o = r.at
            st = r.u16()
            out.append(node("Status code", f"{STATUSES.get(st, 'Reserved')} ({st})", o, 2))
            extra = f"{AUTH_ALGOS.get(alg, alg)}, seq {sq}" + (f", status {st}" if st else "")
        if sub in (10, 12):
            o = r.at
            rc = r.u16()
            out.append(node("Reason code", f"{REASONS.get(rc, 'Reserved')} ({rc})", o, 2))
            extra = f"Reason: {REASONS.get(rc, 'Reserved')} ({rc})"
        if sub in (13, 14):
            o = r.at
            cat = r.u8()
            out.append(node("Category code", f"{ACTION_CATEGORIES.get(cat, 'Reserved')} ({cat})", o, 1))
            if r.left():
                o = r.at
                out.append(node("Action code", r.u8(), o, 1))
            if r.left():
                o = r.at
                rest = r.take(r.left())
                out.append(node("Action details", hexs(rest), o, len(rest)))
            extra = ACTION_CATEGORIES.get(cat, f"category {cat}")
    except Truncated:
        out.append(node(MALFORMED))
    return out, extra


# ============================================================================================================ Bluetooth
HCI_EVENTS = {0x01: "Inquiry Complete", 0x02: "Inquiry Result", 0x03: "Connection Complete", 0x05: "Disconnect Complete",
              0x07: "Remote Name Request Complete", 0x08: "Encryption Change", 0x0B: "Read Remote Supported Features Complete",
              0x0C: "Read Remote Version Information Complete", 0x0E: "Command Complete", 0x0F: "Command Status", 0x10: "Hardware Error",
              0x13: "Number of Completed Packets", 0x22: "Inquiry Result with RSSI", 0x2F: "Extended Inquiry Result", 0x3E: "LE Meta"}
LE_SUBEVENTS = {0x01: "LE Connection Complete", 0x02: "LE Advertising Report", 0x03: "LE Connection Update Complete",
                0x04: "LE Read Remote Features Complete", 0x0A: "LE Enhanced Connection Complete", 0x0B: "LE Directed Advertising Report",
                0x0D: "LE Extended Advertising Report", 0x0E: "LE Periodic Advertising Sync Established", 0x0F: "LE Periodic Advertising Report",
                0x11: "LE Scan Timeout", 0x12: "LE Advertising Set Terminated"}
OPCODES = {0x0401: "Inquiry", 0x0402: "Inquiry Cancel", 0x0419: "Remote Name Request", 0x0C03: "Reset", 0x0C01: "Set Event Mask",
           0x1001: "Read Local Version Information", 0x1009: "Read BD_ADDR", 0x2001: "LE Set Event Mask", 0x2003: "LE Read Local Supported Features",
           0x200B: "LE Set Scan Parameters", 0x200C: "LE Set Scan Enable", 0x200D: "LE Create Connection", 0x2016: "LE Read Remote Features",
           0x2041: "LE Set Extended Scan Parameters", 0x2042: "LE Set Extended Scan Enable", 0x2043: "LE Extended Create Connection",
           0x0406: "Disconnect", 0x041D: "Read Remote Version Information"}
ADV_TYPES = {0: "ADV_IND", 1: "ADV_DIRECT_IND", 2: "ADV_SCAN_IND", 3: "ADV_NONCONN_IND", 4: "SCAN_RSP"}
LEGACY_EXT = {0x13: "ADV_IND", 0x15: "ADV_DIRECT_IND", 0x12: "ADV_SCAN_IND", 0x10: "ADV_NONCONN_IND", 0x1B: "SCAN_RSP to ADV_IND",
              0x1A: "SCAN_RSP to ADV_SCAN_IND"}
ADDR_TYPES = {0: "Public", 1: "Random", 2: "Public identity", 3: "Random static identity", 0xFF: "Anonymous"}
PHYS = {0: "none", 1: "LE 1M", 2: "LE 2M", 3: "LE Coded"}
AD_TYPES = {0x01: "Flags", 0x02: "Incomplete List of 16-bit Service UUIDs", 0x03: "Complete List of 16-bit Service UUIDs",
            0x04: "Incomplete List of 32-bit Service UUIDs", 0x05: "Complete List of 32-bit Service UUIDs",
            0x06: "Incomplete List of 128-bit Service UUIDs", 0x07: "Complete List of 128-bit Service UUIDs", 0x08: "Shortened Local Name",
            0x09: "Complete Local Name", 0x0A: "Tx Power Level", 0x0D: "Class of Device", 0x10: "Device ID", 0x14: "16-bit Service Solicitation UUIDs",
            0x15: "128-bit Service Solicitation UUIDs", 0x16: "Service Data - 16-bit UUID", 0x19: "Appearance", 0x1A: "Advertising Interval",
            0x1B: "LE Bluetooth Device Address", 0x1C: "LE Role", 0x20: "Service Data - 32-bit UUID", 0x21: "Service Data - 128-bit UUID",
            0x24: "URI", 0x27: "LE Supported Features", 0x2C: "BIGInfo", 0x2E: "Resolvable Set Identifier", 0x30: "Broadcast Name",
            0xFF: "Manufacturer Specific"}
SERVICES = {0x1800: "Generic Access", 0x1801: "Generic Attribute", 0x180A: "Device Information", 0x180D: "Heart Rate", 0x180F: "Battery",
            0x1812: "Human Interface Device", 0x1802: "Immediate Alert", 0x1803: "Link Loss", 0x1804: "Tx Power", 0x1805: "Current Time",
            0x1809: "Health Thermometer", 0x1810: "Blood Pressure", 0x1814: "Running Speed and Cadence", 0x1816: "Cycling Speed and Cadence",
            0x1818: "Cycling Power", 0x181A: "Environmental Sensing", 0x181C: "User Data", 0x181D: "Weight Scale", 0x1822: "Pulse Oximeter",
            0x1826: "Fitness Machine", 0x183B: "Binary Sensor", 0x1844: "Volume Control", 0x184E: "Audio Stream Control", 0x1850: "Published Audio Capabilities",
            0x1852: "Broadcast Audio Announcement", 0x1853: "Common Audio", 0x1856: "Public Broadcast Announcement", 0x185C: "Ranging",
            0xFD6F: "Exposure Notification", 0xFE2C: "Google Fast Pair", 0xFEAA: "Eddystone", 0xFE9F: "Google", 0xFD5A: "Samsung SmartTag",
            0xFFF6: "Matter", 0xFCF1: "Google", 0xFE07: "Sonos", 0xFE78: "HP", 0xFD44: "Apple", 0xFCB2: "Apple", 0xFE95: "Xiaomi", 0xFD69: "Samsung",
            0xFEED: "Tile", 0xFE33: "Chipolo", 0xFE03: "Amazon"}
APPLE_TYPES = {0x02: "iBeacon", 0x03: "AirPrint", 0x05: "AirDrop", 0x06: "HomeKit", 0x07: "Proximity Pairing", 0x08: "Hey Siri", 0x09: "AirPlay Target",
               0x0A: "AirPlay Source", 0x0B: "Magic Switch", 0x0C: "Handoff", 0x0D: "Tethering Target", 0x0E: "Tethering Source",
               0x0F: "Nearby Action", 0x10: "Nearby Info", 0x12: "Find My", 0x16: "AirPods / Beats"}
MAJOR_CLASSES = ("Miscellaneous", "Computer", "Phone", "LAN/Network Access Point", "Audio/Video", "Peripheral", "Imaging", "Wearable", "Toy", "Health")
SERVICE_CLASSES = {13: "Limited Discoverable", 16: "Positioning", 17: "Networking", 18: "Rendering", 19: "Capturing", 20: "Object Transfer",
                   21: "Audio", 22: "Telephony", 23: "Information"}


def bdaddr(b, atype=None):
    a = rev_mac(b)
    if atype in (1, 3):
        kind = {3: "static", 1: "resolvable private", 0: "non-resolvable private"}.get(b[5] >> 6, "reserved")
        return a, f"{a} (random, {kind})"
    return a, a


def uuid128(b):
    h = bytes(reversed(b)).hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def ad_structures(d, at, end, s):
    out = []
    while at < end:
        n = d[at]
        if n == 0:
            out.append(node("Padding", f"{end - at} bytes", at, end - at))
            break
        if at + 1 + n > end:
            out.append(node("Advertising data", MALFORMED, at, end - at))
            break
        t, v, vo = d[at + 1], d[at + 2:at + 1 + n], at + 2
        name = AD_TYPES.get(t, f"Type 0x{t:02x}")
        kids, val = [node("Length", n, at, 1), node("Type", f"{name} (0x{t:02x})", at + 1, 1)], None
        if t == 0x01 and v:
            val = f"0x{v[0]:02x}"
            kids += flag_nodes(v[0], 8, ((0x01, "LE Limited Discoverable Mode", None), (0x02, "LE General Discoverable Mode", None),
                                         (0x04, "BR/EDR Not Supported", None), (0x08, "Simultaneous LE and BR/EDR (Controller)", None),
                                         (0x10, "Simultaneous LE and BR/EDR (Host)", None)), vo, 1)
        elif t in (0x02, 0x03, 0x14):
            names = []
            for j in range(0, len(v) - 1, 2):
                u = v[j] | v[j + 1] << 8
                names.append(f"{SERVICES.get(u, 'UUID')} (0x{u:04x})")
                kids.append(node("UUID 16", names[-1], vo + j, 2))
            val = ", ".join(names)
        elif t in (0x04, 0x05):
            for j in range(0, len(v) - 3, 4):
                kids.append(node("UUID 32", f"0x{int.from_bytes(v[j:j + 4], 'little'):08x}", vo + j, 4))
        elif t in (0x06, 0x07, 0x15):
            for j in range(0, len(v) - 15, 16):
                kids.append(node("UUID 128", uuid128(v[j:j + 16]), vo + j, 16))
            val = ", ".join(k["v"] for k in kids[2:])
        elif t in (0x08, 0x09, 0x30):
            val = text(v)
            s.setdefault("name", val)
        elif t == 0x0A and v:
            val = f"{struct.unpack('b', v[:1])[0]} dBm"
        elif t == 0x0D and len(v) >= 3:
            val, kids2 = cod(v, vo)
            kids += kids2
        elif t == 0x16 and len(v) >= 2:
            u = v[0] | v[1] << 8
            val = f"{SERVICES.get(u, 'UUID')} (0x{u:04x})"
            kids += [node("UUID 16", val, vo, 2), node("Service Data", hexs(v[2:]), vo + 2, len(v) - 2)]
            s.setdefault("service", SERVICES.get(u, f"0x{u:04x}"))
        elif t == 0x19 and len(v) >= 2:
            val = f"0x{v[0] | v[1] << 8:04x}"
        elif t == 0xFF and len(v) >= 2:
            cid = v[0] | v[1] << 8
            company = bt_company(cid) or f"Company 0x{cid:04x}"
            val = f"{company} (0x{cid:04x})"
            kids.append(node("Company ID", val, vo, 2))
            s.setdefault("company", company)
            if cid == 0x004C and len(v) >= 4:
                kids += apple(v, vo, s)
            elif len(v) > 2:
                kids.append(node("Data", hexs(v[2:]), vo + 2, len(v) - 2))
        elif v:
            val = hexs(v, 32)
        out.append(node(f"Advertising Data: {name}", val, at, 1 + n, kids))
        at += 1 + n
    return out


def apple(v, vo, s):
    out, j = [], 2
    while j + 2 <= len(v):
        t, n = v[j], v[j + 1]
        name = APPLE_TYPES.get(t, f"type 0x{t:02x}")
        s.setdefault("apple", name)
        body = v[j + 2:j + 2 + n]
        kids = []
        if t == 0x02 and len(body) >= 21:
            kids = [node("Proximity UUID", uuid128(bytes(reversed(body[:16]))), vo + j + 2, 16),
                    node("Major", int.from_bytes(body[16:18], "big"), vo + j + 18, 2), node("Minor", int.from_bytes(body[18:20], "big"), vo + j + 20, 2),
                    node("Measured power", f"{struct.unpack('b', body[20:21])[0]} dBm", vo + j + 22, 1)]
        out.append(node(f"Apple: {name}", hexs(body, 24), vo + j, 2 + min(n, len(v) - j - 2), kids))
        j += 2 + n
    return out


def cod(v, off):
    c = int.from_bytes(v[:3], "little")
    major = c >> 8 & 0x1F
    services = [n for b, n in SERVICE_CLASSES.items() if c >> b & 1]
    major_name = MAJOR_CLASSES[major] if major < len(MAJOR_CLASSES) else "Uncategorized" if major == 31 else f"Reserved ({major})"
    return (f"0x{c:06x} ({major_name}" + (f"; {', '.join(services)}" if services else "") + ")",
            [node("Major device class", major_name, off + 1, 1), node("Minor device class", c >> 2 & 0x3F, off, 1),
             node("Major service classes", ", ".join(services) or "none", off + 1, 2)])


def bluetooth(raw, meta, vendor_name):
    s = {"proto": "HCI_EVT", "dst": "", "src": "", "color": "bt"}
    tree = []
    if not raw or raw[0] != 0x04 or len(raw) < 3:
        tree.append(node("Bluetooth HCI", "not an HCI event", 0, len(raw)))
        s.update(info="Not an HCI event", color="bad")
        return s, tree
    tree.append(node("Bluetooth HCI H4", "Rcvd HCI Event", 0, 1, [node("Direction", "Rcvd"), node("HCI Packet Type", "HCI Event (0x04)", 0, 1)]))
    code, plen = raw[1], raw[2]
    ename = HCI_EVENTS.get(code, f"Unknown (0x{code:02x})")
    kids = [node("Event Code", f"{ename} (0x{code:02x})", 1, 1), node("Parameter Total Length", plen, 2, 1)]
    end = min(len(raw), 3 + plen)
    info = ename
    try:
        r = Reader(raw, 3, end)
        if code == 0x3E:
            sub = r.u8()
            sname = LE_SUBEVENTS.get(sub, f"Unknown (0x{sub:02x})")
            kids.append(node("Sub Event", f"{sname} (0x{sub:02x})", 3, 1))
            info = sname
            if sub == 0x02:
                info = le_reports(raw, r, kids, s, extended=False)
            elif sub == 0x0D:
                info = le_reports(raw, r, kids, s, extended=True)
            elif r.left():
                o = r.at
                rest = r.take(r.left())
                kids.append(node("Parameters", hexs(rest), o, len(rest)))
        elif code in (0x02, 0x22, 0x2F):
            info = inquiry(raw, r, kids, s, code)
        elif code == 0x0E:
            o = r.at
            kids.append(node("Number of Allowed Command Packets", r.u8(), o, 1))
            o = r.at
            op = r.u16()
            kids.append(node("Command Opcode", f"{OPCODES.get(op, 'Unknown')} (0x{op:04x})", o, 2,
                             [node(bits(op, 16, 0xFC00, "Opcode Group Field"), off=o, length=2), node(bits(op, 16, 0x03FF, "Opcode Command Field"), off=o, length=2)]))
            if r.left():
                o = r.at
                st = r.u8()
                kids.append(node("Status", "Success (0x00)" if st == 0 else f"Error (0x{st:02x})", o, 1))
            if r.left():
                o = r.at
                rest = r.take(r.left())
                kids.append(node("Return parameters", hexs(rest), o, len(rest)))
            info = f"Command Complete ({OPCODES.get(op, f'0x{op:04x}')})"
            s["color"] = "hci"
        elif code == 0x0F:
            o = r.at
            st = r.u8()
            kids.append(node("Status", "Pending (0x00)" if st == 0 else f"Error (0x{st:02x})", o, 1))
            o = r.at
            kids.append(node("Number of Allowed Command Packets", r.u8(), o, 1))
            o = r.at
            op = r.u16()
            kids.append(node("Command Opcode", f"{OPCODES.get(op, 'Unknown')} (0x{op:04x})", o, 2))
            info = f"Command Status ({OPCODES.get(op, f'0x{op:04x}')})"
            s["color"] = "hci"
        elif r.left():
            o = r.at
            rest = r.take(r.left())
            kids.append(node("Parameters", hexs(rest), o, len(rest)))
            s["color"] = "hci"
    except Truncated:
        kids.append(node(MALFORMED))
        s["color"] = "bad"
    if 3 + plen > len(raw):
        kids.append(node(MALFORMED))
        s["color"] = "bad"
    tree.append(node("Bluetooth HCI Event", ename, 1, end - 1, kids))
    s["info"] = info
    s["type"] = s.get("type") or ename
    return s, tree


def le_reports(raw, r, kids, s, extended):
    o = r.at
    n = r.u8()
    kids.append(node("Num Reports", n, o, 1))
    first = None
    for i in range(n):
        start = r.at
        rk = []
        if extended:
            o = r.at
            et = r.u16()
            legacy = et & 0x10
            pdu = LEGACY_EXT.get(et & 0x1F, "legacy") if legacy else ("connectable " if et & 1 else "") + ("scannable " if et & 2 else "") + \
                ("directed " if et & 4 else "") + ("scan response" if et & 8 else "extended advertisement")
            rk.append(node("Event Type", f"0x{et:04x} ({pdu.strip()})", o, 2, flag_nodes(et, 16, (
                (0x0001, "Connectable", None), (0x0002, "Scannable", None), (0x0004, "Directed", None), (0x0008, "Scan Response", None),
                (0x0010, "Legacy", None), (0x0060, "Data Status", lambda x: ("Complete", "Incomplete, more to come", "Incomplete, truncated", "Reserved")[x >> 5])), o, 2)))
        else:
            o = r.at
            et = r.u8()
            pdu = ADV_TYPES.get(et, f"0x{et:02x}")
            rk.append(node("Event Type", f"{pdu} (0x{et:02x})", o, 1))
        o = r.at
        at_ = r.u8()
        rk.append(node("Peer Address Type", f"{ADDR_TYPES.get(at_, 'Reserved')} (0x{at_:02x})", o, 1))
        o = r.at
        addr, shown = bdaddr(r.take(6), at_)
        rk.append(node("BD_ADDR", shown, o, 6))
        rssi = None
        if extended:
            o = r.at
            p1, p2, sid = r.u8(), r.u8(), r.u8()
            rk += [node("Primary PHY", PHYS.get(p1, p1), o, 1), node("Secondary PHY", PHYS.get(p2, p2), o + 1, 1),
                   node("Advertising SID", "not present" if sid == 0xFF else sid, o + 2, 1)]
            o = r.at
            tx = struct.unpack("b", r.take(1))[0]
            rk.append(node("TX Power", "not available" if tx == 127 else f"{tx} dBm", o, 1))
            o = r.at
            rssi = struct.unpack("b", r.take(1))[0]
            rk.append(node("RSSI", f"{rssi} dBm", o, 1))
            o = r.at
            iv = r.u16()
            rk.append(node("Periodic Advertising Interval", f"{iv * 1.25:g} ms" if iv else "none", o, 2))
            o = r.at
            dt = r.u8()
            rk.append(node("Direct Address Type", ADDR_TYPES.get(dt, dt), o, 1))
            o = r.at
            rk.append(node("Direct BD_ADDR", rev_mac(r.take(6)), o, 6))
        o = r.at
        dl = r.u8()
        rk.append(node("Data Length", dl, o, 1))
        o = r.at
        r.take(dl)
        rk += ad_structures(raw, o, o + dl, s)
        if not extended:
            o = r.at
            rssi = struct.unpack("b", r.take(1))[0]
            rk.append(node("RSSI", f"{rssi} dBm", o, 1))
        kids.append(node(f"Report {i + 1}", f"{pdu.strip()}, {addr}", start, r.at - start, rk))
        if first is None:
            first = (pdu.strip(), addr, rssi)
            s.update(src=addr, dst="Broadcast", rssi=rssi, type=pdu.strip())
    s["proto"] = "LE ADV" if not extended else "LE EXT ADV"
    s["color"] = "ble"
    if first is None:
        return "LE Advertising Report (no reports)"
    parts = [first[0]]
    if s.get("name"):
        parts.append(f'"{s["name"]}"')
    if s.get("apple"):
        parts.append(f"Apple {s['apple']}")
    elif s.get("company"):
        parts.append(s["company"])
    if s.get("service"):
        parts.append(s["service"])
    if n > 1:
        parts.append(f"{n} reports")
    return ", ".join(parts)


def inquiry(raw, r, kids, s, code):
    o = r.at
    n = r.u8()
    kids.append(node("Number of responses", n, o, 1))
    n = min(n, 1) if code == 0x2F else n  # the extended result always holds one (its EIR data fills the rest)
    for i in range(n):
        start = r.at
        rk = []
        o = r.at
        addr, _ = bdaddr(r.take(6))
        rk.append(node("BD_ADDR", addr, o, 6))
        o = r.at
        rk.append(node("Page Scan Repetition Mode", f"R{r.u8()}", o, 1))
        r.take(2 if code == 0x02 else 1)  # reserved
        o = r.at
        c = r.take(3)
        v, ck = cod(c, o)
        rk.append(node("Class of Device", v, o, 3, ck))
        o = r.at
        rk.append(node("Clock Offset", f"0x{r.u16() & 0x7FFF:04x}", o, 2))
        rssi = None
        if code in (0x22, 0x2F):
            o = r.at
            rssi = struct.unpack("b", r.take(1))[0]
            rk.append(node("RSSI", f"{rssi} dBm", o, 1))
        if code == 0x2F:
            o = r.at
            eir = r.take(r.left())
            rk.append(node("Extended Inquiry Response Data", None, o, len(eir), ad_structures(raw, o, o + len(eir), s)))
        kids.append(node(f"Response {i + 1}", addr, start, r.at - start, rk))
        if i == 0:
            s.update(src=addr, dst="", rssi=rssi, cod=v)
    s["proto"] = "BR/EDR"
    s["color"] = "bt"
    s["type"] = HCI_EVENTS[code]
    return HCI_EVENTS[code] + (f', "{s["name"]}"' if s.get("name") else "") + (f", {s['cod']}" if s.get("cod") else "")


# ======================================================================================================== 802.15.4
MAC_TYPES = ("Beacon", "Data", "Ack", "Command", "Reserved", "Multipurpose", "Fragment", "Extended")
ADDR_MODES = ("None", "Reserved", "Short/16-bit", "Long/64-bit")
MAC_COMMANDS = {0x01: "Association Request", 0x02: "Association Response", 0x03: "Disassociation Notification", 0x04: "Data Request",
                0x05: "PAN ID Conflict", 0x06: "Orphan Notification", 0x07: "Beacon Request", 0x08: "Coordinator Realignment", 0x09: "GTS Request"}
SEC_LEVELS = ("None", "MIC-32", "MIC-64", "MIC-128", "ENC", "ENC-MIC-32", "ENC-MIC-64", "ENC-MIC-128")
LOWPAN = ((0xC0, 0xF8, "Fragmentation header (first)"), (0xE0, 0xF8, "Fragmentation header (subsequent)"), (0x80, 0xC0, "Mesh header"),
          (0x60, 0xE0, "IPHC (compressed IPv6)"), (0x41, 0xFF, "Uncompressed IPv6"), (0x40, 0xFF, "ESC"))


def zb_addr(r, mode):
    if mode == 2:
        return f"0x{r.u16():04x}", 2
    return rev_mac(r.take(8)), 8


def zigbee(raw, meta, vendor_name):
    s = {"proto": "IEEE 802.15.4", "src": "", "dst": "", "color": "zigbee"}
    tree = []
    r = Reader(raw)
    mk = []
    header_done = False
    try:
        fc = r.u16()
        ftype, ver = fc & 7, fc >> 12 & 3
        dmode, smode = fc >> 10 & 3, fc >> 14 & 3
        secured, compressed = fc & 0x08, fc & 0x40
        mk.append(node("Frame Control Field", f"0x{fc:04x}, Frame Type: {MAC_TYPES[ftype]}", 0, 2, [
            node(bits(fc, 16, 0x0007, "Frame Type", MAC_TYPES[ftype]), off=0, length=2),
            node(bits(fc, 16, 0x0008, "Security Enabled"), off=0, length=2), node(bits(fc, 16, 0x0010, "Frame Pending"), off=0, length=2),
            node(bits(fc, 16, 0x0020, "Acknowledge Request"), off=0, length=2), node(bits(fc, 16, 0x0040, "PAN ID Compression"), off=0, length=2),
            node(bits(fc, 16, 0x0100, "Sequence Number Suppression"), off=0, length=2), node(bits(fc, 16, 0x0200, "Information Elements Present"), off=0, length=2),
            node(bits(fc, 16, 0x0C00, "Destination Addressing Mode", ADDR_MODES[dmode]), off=0, length=2),
            node(bits(fc, 16, 0x3000, "Frame Version", ("IEEE Std 802.15.4-2003", "IEEE Std 802.15.4-2006", "IEEE Std 802.15.4-2015", "Reserved")[ver]), off=0, length=2),
            node(bits(fc, 16, 0xC000, "Source Addressing Mode", ADDR_MODES[smode]), off=0, length=2)]))
        seq = None
        if not (fc & 0x0100 and ver == 2):
            seq = r.u8()
            mk.append(node("Sequence Number", seq, 2, 1))
        dst = src = dpan = None
        if ftype in (0, 1, 2, 3) and dmode != 1 and smode != 1 and ver != 3:
            dp, sp = _pans_present(ver, dmode, smode, compressed)
            if dp:
                o = r.at
                dpan = r.u16()
                mk.append(node("Destination PAN", f"0x{dpan:04x}", o, 2))
            if dmode:
                o = r.at
                dst, n = zb_addr(r, dmode)
                mk.append(node("Destination", dst + (" (broadcast)" if dst == "0xffff" else ""), o, n))
            if sp:
                o = r.at
                span = r.u16()
                mk.append(node("Source PAN", f"0x{span:04x}", o, 2))
            if smode:
                o = r.at
                src, n = zb_addr(r, smode)
                mk.append(node("Source", src, o, n))
        if secured:
            o = r.at
            sc = r.u8()
            km = sc >> 3 & 3
            ak = [node("Security Control Field", f"0x{sc:02x}", o, 1, [
                node(bits(sc, 8, 0x07, "Security Level", SEC_LEVELS[sc & 7]), off=o, length=1),
                node(bits(sc, 8, 0x18, "Key Identifier Mode", ("Implicit", "Key index", "4-byte key source", "8-byte key source")[km]), off=o, length=1)])]
            if not (ver == 2 and sc & 0x20):
                o2 = r.at
                ak.append(node("Frame Counter", r.u32(), o2, 4))
            n = (0, 1, 5, 9)[km]
            if n:
                o2 = r.at
                ak.append(node("Key Identifier", hexs(r.take(n)), o2, n))
            mk.append(node("Auxiliary Security Header", SEC_LEVELS[sc & 7], o, r.at - o, ak))
        tree.append(node(f"IEEE 802.15.4 {MAC_TYPES[ftype]}", ", ".join(x for x in (f"Seq: {seq}" if seq is not None else "",
                         f"Dst: {dst}" if dst else "", f"Src: {src}" if src else "") if x), 0, r.at, mk))
        header_done = True
        s.update(src=src or "", dst=dst or "", type=MAC_TYPES[ftype], pan=f"0x{dpan:04x}" if dpan is not None else None)
        info = MAC_TYPES[ftype]
        if ftype == 2:
            s["color"] = "ack"
            info = "Ack" + (f", seq {seq}" if seq is not None else "")
        elif secured:
            rest = r.left()
            tree.append(node("Encrypted payload and MIC", f"{rest} bytes", r.at, rest))
            info += ", encrypted at the MAC layer"
        elif ftype == 0:
            info = zb_beacon(raw, r, tree, s)
        elif ftype == 3 and r.left():
            o = r.at
            cid = r.u8()
            cname = MAC_COMMANDS.get(cid, f"0x{cid:02x}")
            ck = [node("Command Identifier", f"{cname} (0x{cid:02x})", o, 1)]
            if cid == 0x01 and r.left():
                o2 = r.at
                cap = r.u8()
                ck.append(node("Association Request", f"0x{cap:02x}", o2, 1, flag_nodes(cap, 8, (
                    (0x01, "Alternate PAN Coordinator", None), (0x02, "Device Type", lambda x: "FFD (can route)" if x else "RFD"),
                    (0x04, "Power Source", lambda x: "Mains" if x else "Battery"), (0x08, "Receive On When Idle", None),
                    (0x40, "Security Capability", None), (0x80, "Allocate Address", None)), o2, 1)))
            elif cid == 0x02 and r.left() >= 3:
                o2 = r.at
                ck.append(node("Short Address", f"0x{r.u16():04x}", o2, 2))
                o2 = r.at
                st = r.u8()
                ck.append(node("Association Status", ("Successful", "PAN at capacity", "PAN access denied")[st] if st < 3 else f"0x{st:02x}", o2, 1))
            elif r.left():
                o2 = r.at
                rest = r.take(r.left())
                ck.append(node("Command payload", hexs(rest), o2, len(rest)))
            tree.append(node("Command", cname, o, r.at - o, ck))
            info = cname
            s["color"] = "zbcmd"
        elif ftype == 1 and r.left():
            info = zb_data(raw, r, tree, s)
        elif r.left():
            tree.append(node("Payload", hexs(raw[r.at:]), r.at, r.left()))
    except Truncated:
        tree.append(node(MALFORMED) if header_done else node("IEEE 802.15.4", MALFORMED, 0, len(raw), mk))
        s.update(color="bad")
        info = "Malformed frame"
    s["info"] = info
    return s, tree


def zb_beacon(d, r, tree, s):
    o = r.at
    sf = r.u16()
    bk = [node("Superframe Specification", f"0x{sf:04x}", o, 2, flag_nodes(sf, 16, (
        (0x000F, "Beacon Interval", None), (0x00F0, "Superframe Interval", None), (0x0F00, "Final CAP Slot", None),
        (0x1000, "Battery Extension", None), (0x4000, "PAN Coordinator", None), (0x8000, "Association Permit", None)), o, 2))]
    o = r.at
    g = r.u8()
    gk = node("GTS", f"{g & 7} slot(s)", o, 1)
    if g & 7:
        r.take(1 + 3 * (g & 7))
        gk["l"] = r.at - o
    bk.append(gk)
    o = r.at
    pa = r.u8()
    ns, ne = pa & 7, pa >> 4 & 7
    r.take(2 * ns + 8 * ne)
    bk.append(node("Pending Addresses", f"{ns} short, {ne} long", o, r.at - o))
    tree.append(node("Beacon", "association permitted" if sf & 0x8000 else "association not permitted", None, None, bk))
    tree[-1]["o"], tree[-1]["l"] = bk[0]["o"], r.at - bk[0]["o"]
    info = "Beacon"
    if r.left() >= 1:
        o = r.at
        pid = r.u8()
        if pid == 0 and r.left() >= 2:
            sp = r.u16()
            zk = [node("Protocol ID", 0, o, 1), node("Beacon", f"0x{sp:04x}", o + 1, 2, flag_nodes(sp, 16, (
                (0x000F, "Stack Profile", lambda x: {1: "ZigBee (2006)", 2: "ZigBee PRO"}.get(x, str(x))), (0x00F0, "Protocol Version", None),
                (0x0400, "Router Capacity", None), (0x7800, "Device Depth", None), (0x8000, "End Device Capacity", None)), o + 1, 2))]
            epid = None
            if r.left() >= 8:
                o2 = r.at
                epid = rev_mac(r.take(8))
                zk.append(node("Extended PAN ID", epid, o2, 8))
            if r.left() >= 3:
                o2 = r.at
                zk.append(node("Tx Offset", r.u24(), o2, 3))
            if r.left() >= 1:
                o2 = r.at
                zk.append(node("Update ID", r.u8(), o2, 1))
            tree.append(node("ZigBee Beacon", f"EPID: {epid}" if epid else None, o, r.at - o, zk))
            s.update(proto="ZigBee", epid=epid)
            info = f"Beacon, Src: {s['src']}" + (f", EPID: {epid}" if epid else "")
        elif pid == 3 and r.left() >= 25:
            fl = r.u8()
            name = bytes(r.take(16)).split(b"\x00")[0].decode("utf-8", "replace")
            xp = r.take(8).hex(":")
            tree.append(node("Thread Beacon", f'"{name}"', o, r.at - o, [
                node("Protocol ID", 3, o, 1), node("Beacon flags", f"0x{fl:02x}", o + 1, 1, flag_nodes(fl, 8, (
                    (0xF0, "Version", None), (0x08, "Native Commissioner", None), (0x01, "Joining Permitted", None)), o + 1, 1)),
                node("Network Name", name, o + 2, 16), node("Extended PAN ID", xp, o + 18, 8)]))
            s.update(proto="Thread", network=name)
            info = f'Beacon, Thread network "{name}"'
        else:
            rest = r.left()
            r.take(rest)
            tree.append(node("Beacon payload", hexs(d[o:]), o, 1 + rest))
    s["color"] = "zbbeacon"
    return info


def zb_data(d, r, tree, s):
    o = r.at
    b0 = d[o]
    if b0 & 3 <= 1 and (b0 >> 2) & 15 in (2, 3) and r.left() >= 8:
        return zb_nwk(d, r, tree, s)
    for val, mask, name in LOWPAN:
        if b0 & mask == val:
            rest = r.left()
            r.take(rest)
            tree.append(node("6LoWPAN", name, o, rest, [node("Dispatch", f"0x{b0:02x}: {name}", o, 1), node("Payload", hexs(d[o + 1:]), o + 1, rest - 1)]))
            s.update(proto="6LoWPAN", color="thread")
            return f"Data, 6LoWPAN {name}"
    rest = r.left()
    r.take(rest)
    tree.append(node("Data payload", hexs(d[o:]), o, rest))
    return "Data"


def zb_nwk(d, r, tree, s):
    o = r.at
    fc = r.u16()
    ftype, ver = fc & 3, fc >> 2 & 15
    nk = [node("Frame Control Field", f"0x{fc:04x}", o, 2, flag_nodes(fc, 16, (
        (0x0003, "Frame Type", lambda x: ("Data", "Command", "Reserved", "Inter-PAN")[x]), (0x003C, "Protocol Version", None),
        (0x00C0, "Discover Route", None), (0x0100, "Multicast", None), (0x0200, "Security", None), (0x0400, "Source Route", None),
        (0x0800, "Destination IEEE Address", None), (0x1000, "Source IEEE Address", None), (0x2000, "End Device Initiator", None)), o, 2))]
    if ver == 3:  # Zigbee Green Power: a different header that this does not take apart
        rest = r.left()
        r.take(rest)
        tree.append(node("ZigBee Green Power", None, o, r.at - o, nk + [node("Payload", hexs(d[o + 2:]), o + 2, rest)]))
        s.update(proto="ZigBee GP", color="zigbee")
        return "Green Power frame"
    o2 = r.at
    dst = r.u16()
    nk.append(node("Destination", f"0x{dst:04x}", o2, 2))
    o2 = r.at
    src = r.u16()
    nk.append(node("Source", f"0x{src:04x}", o2, 2))
    o2 = r.at
    nk.append(node("Radius", r.u8(), o2, 1))
    o2 = r.at
    nk.append(node("Sequence Number", r.u8(), o2, 1))
    if fc & 0x0800:
        o2 = r.at
        nk.append(node("Destination IEEE", rev_mac(r.take(8)), o2, 8))
    if fc & 0x1000:
        o2 = r.at
        nk.append(node("Extended Source", rev_mac(r.take(8)), o2, 8))
    if fc & 0x0100:
        o2 = r.at
        nk.append(node("Multicast Control", f"0x{r.u8():02x}", o2, 1))
    if fc & 0x0400:
        o2 = r.at
        n = r.u8()
        r.u8()
        r.take(2 * n)
        nk.append(node("Source Route", f"{n} relay(s)", o2, r.at - o2))
    secured = fc & 0x0200
    if secured:
        o2 = r.at
        sc = r.u8()
        sk = [node("Security Control Field", f"0x{sc:02x}", o2, 1, [
            node(bits(sc, 8, 0x18, "Key Id", ("Data Key", "Network Key", "Key-Transport Key", "Key-Load Key")[sc >> 3 & 3]), off=o2, length=1),
            node(bits(sc, 8, 0x20, "Extended Nonce"), off=o2, length=1)])]
        o3 = r.at
        sk.append(node("Frame Counter", r.u32(), o3, 4))
        if sc & 0x20:
            o3 = r.at
            sk.append(node("Extended Source", rev_mac(r.take(8)), o3, 8))
        if sc >> 3 & 3 == 1:
            o3 = r.at
            sk.append(node("Key Sequence Number", r.u8(), o3, 1))
        nk.append(node("ZigBee Security Header", None, o2, r.at - o2, sk))
    tree.append(node("ZigBee Network Layer " + ("Data" if ftype == 0 else "Command"), f"Dst: 0x{dst:04x}, Src: 0x{src:04x}", o, r.at - o, nk))
    rest = r.left()
    if secured and rest >= 4:
        tree.append(node("Encrypted payload", f"{rest - 4} bytes", r.at, rest - 4))
        tree.append(node("Message Integrity Code", hexs(d[r.at + rest - 4:r.at + rest]), r.at + rest - 4, 4))
    elif rest:
        tree.append(node("NWK payload", hexs(d[r.at:]), r.at, rest))
    s.update(proto="ZigBee", src=f"0x{src:04x}", dst=f"0x{dst:04x}", color="zigbee")
    return f"{'Data' if ftype == 0 else 'Command'}, Dst: 0x{dst:04x}, Src: 0x{src:04x}" + (", encrypted" if secured else "")


# ================================================================================================================= LoRa
LW_MTYPES = ("Join Request", "Join Accept", "Unconfirmed Data Up", "Unconfirmed Data Down", "Confirmed Data Up", "Confirmed Data Down",
             "Rejoin Request", "Proprietary")


def lora(raw, meta, vendor_name):
    """The sniffer line; the hex view shows the payload of the LoRa frame in it."""
    from .lora import parse_rx  # here, not at the top: lora.py imports capture.py, which imports this module
    line = bytes(raw).decode("ascii", "replace").strip()
    rx = parse_rx(line)
    s = {"proto": "LoRa", "src": "", "dst": "", "color": "lora"}
    if not rx:
        s.update(info=line[:120], type="sniffer line")
        return s, [node("Sniffer line", line[:300])]
    p = bytes.fromhex(rx["hex"])
    head = node("LoRa radio", f"{rx['freq']:g} MHz, SF{rx['sf']}, BW {rx['bw']:g} kHz", None, None, [
        node("Frequency", f"{rx['freq']:g} MHz"), node("Spreading factor", f"SF{rx['sf']}"), node("Bandwidth", f"{rx['bw']:g} kHz"),
        node("Sync word", f"0x{rx['sync']:02x}"), node("RSSI", f"{rx['rssi']:g} dBm"), node("SNR", f"{rx['snr']:g} dB"),
        node("Frequency error", f"{rx['ferr']:g} Hz"), node("Payload length", len(p))])
    tree = [node("Sniffer line", line[:300]), head]
    c = classify(p, rx["sync"])
    try:
        if c["protocol"] == "meshtastic":
            tree.append(meshtastic(p))
        elif c["protocol"] == "lorawan":
            tree.append(lorawan(p))
        elif c["protocol"] == "meshcore":
            tree.append(meshcore(p))
        elif c["protocol"] == "lora-aprs":
            tree.append(node("LoRa APRS", None, 0, len(p), [node("Header", "<\\xff\\x01", 0, 3), node("TNC2 text", text(p[3:]), 3, len(p) - 3)]))
        else:
            tree.append(node("Payload", f"{len(p)} bytes, not recognised ({c['kind']})", 0, len(p)))
    except (Truncated, IndexError):
        tree.append(node(c["label"], MALFORMED, 0, len(p)))
    tree[-1].setdefault("v", f"{c['label']}, {c['level']} confidence" if c["protocol"] != "unknown" else None)
    info = [c.get("kind") if c["protocol"] != "unknown" else "Unidentified"]
    if c.get("name"):
        info.append(f'"{c["name"]}"')
    info.append(f"SF{rx['sf']}/{rx['bw']:g} kHz, SNR {rx['snr']:g} dB")
    s.update(proto=c["label"] if c["protocol"] != "unknown" else "LoRa", src=c.get("src") or "", dst=c.get("dst") or "",
             info=", ".join(x for x in info if x), rssi=rx["rssi"], channel=f"{rx['freq']:g} MHz", type=c.get("kind"), payload=p)
    return s, tree


def meshtastic(p):
    r = Reader(p)
    to, frm, pid = r.u32(), r.u32(), r.u32()
    fl, ch, nh, relay = r.u8(), r.u8(), r.u8(), r.u8()
    return node("Meshtastic", f"From !{frm:08x} to {'broadcast' if to == 0xFFFFFFFF else f'!{to:08x}'}", 0, len(p), [
        node("Destination", "broadcast (!ffffffff)" if to == 0xFFFFFFFF else f"!{to:08x}", 0, 4), node("Sender", f"!{frm:08x}", 4, 4),
        node("Packet ID", f"0x{pid:08x}", 8, 4),
        node("Flags", f"0x{fl:02x}", 12, 1, flag_nodes(fl, 8, ((0x07, "Hop limit", None), (0x08, "Want ack", None), (0x10, "Via MQTT", None),
                                                              (0xE0, "Hop start", None)), 12, 1)),
        node("Channel hash", f"0x{ch:02x}", 13, 1), node("Next hop", f"0x{nh:02x}", 14, 1), node("Relay node", f"0x{relay:02x}", 15, 1),
        node("Encrypted data", f"{len(p) - 16} bytes", 16, len(p) - 16)])


def lorawan(p):
    r = Reader(p, 0, len(p) - 4)
    mh = r.u8()
    mt = mh >> 5
    kids = [node("MHDR", f"0x{mh:02x}", 0, 1, flag_nodes(mh, 8, ((0xE0, "Message Type", lambda x: LW_MTYPES[x >> 5]), (0x1C, "RFU", None),
                                                               (0x03, "Major", None)), 0, 1))]
    if mt == 0 and len(p) == 23:
        kids += [node("JoinEUI", rev_mac(r.take(8)), 1, 8), node("DevEUI", rev_mac(r.take(8)), 9, 8), node("DevNonce", r.u16(), 17, 2)]
    elif mt in (2, 3, 4, 5):
        dev = rev_mac(r.take(4)).replace(":", "")
        fc = r.u8()
        fcnt = r.u16()
        n = fc & 15
        kids += [node("DevAddr", dev, 1, 4), node("FCtrl", f"0x{fc:02x}", 5, 1, flag_nodes(fc, 8, (
            (0x80, "ADR", None), (0x40, "ADRACKReq", None), (0x20, "ACK", None), (0x10, "FPending / ClassB", None), (0x0F, "FOptsLen", None)), 5, 1)),
            node("FCnt", fcnt, 6, 2)]
        if n:
            kids.append(node("FOpts", hexs(r.take(n)), 8, n))
        if r.left():
            o = r.at
            kids.append(node("FPort", r.u8(), o, 1))
            if r.left():
                kids.append(node("FRMPayload (encrypted)", f"{r.left()} bytes", r.at, r.left()))
    elif r.left():
        kids.append(node("Payload", hexs(p[1:-4]), 1, len(p) - 5))
    kids.append(node("MIC", p[-4:].hex(), len(p) - 4, 4))
    return node("LoRaWAN", LW_MTYPES[mt], 0, len(p), kids)


def meshcore(p):
    r = Reader(p)
    h = r.u8()
    route, ptype = h & 3, h >> 2 & 15
    from .lora_protocols import MC_ROUTES, MC_TYPES
    kids = [node("Header", f"0x{h:02x}", 0, 1, flag_nodes(h, 8, ((0x03, "Route type", lambda x: MC_ROUTES[x]),
                                                                 (0x3C, "Payload type", lambda x: MC_TYPES.get(x >> 2, str(x >> 2))), (0xC0, "Version", None)), 0, 1))]
    if route in (0, 3):
        kids.append(node("Transport codes", hexs(r.take(4)), 1, 4))
    o = r.at
    pl = r.u8()
    hops, hsize = pl & 0x3F, (pl >> 6) + 1
    kids.append(node("Path length", f"{hops} hop(s) of {hsize} byte(s)", o, 1))
    if hops:
        o = r.at
        kids.append(node("Path", hexs(r.take(hops * hsize)), o, hops * hsize))
    o = r.at
    body = p[o:]
    bk = []
    if ptype == 4 and len(body) >= 100:
        bk = [node("Public key", body[:32].hex(), o, 32), node("Timestamp", int.from_bytes(body[32:36], "little"), o + 32, 4),
              node("Signature", hexs(body[36:100], 16), o + 36, 64)]
        if len(body) > 100:
            bk.append(node("App data", text(body[101:]) if body[100] & 0x80 else hexs(body[100:]), o + 100, len(body) - 100))
    kids.append(node("Payload", f"{MC_TYPES.get(ptype, ptype)}, {len(body)} bytes", o, len(body), bk))
    return node("MeshCore", MC_TYPES.get(ptype, str(ptype)), 0, len(p), kids)


# ================================================================================================================ entry
DISSECTORS = {"wifi": wifi, "bt": bluetooth, "zigbee": zigbee, "lora": lora}


def summarize(rec, vendor_name=None):
    """Just the summary of a frame, for the frame list: the same decoding without the bit-by-bit fields (about twice as fast)."""
    LIGHT.on = True
    try:
        return dissect(rec, vendor_name=vendor_name)[0]
    finally:
        LIGHT.on = False


def dissect(rec, number=1, first_ts=None, vendor_name=None):
    """(summary, tree, bytes shown in the hex view) of one recorded frame (capture.read's dict)."""
    vendor_name = vendor_name or (lambda _: None)
    raw = rec["raw"]
    try:
        s, tree = DISSECTORS[rec["radio"]](raw, rec, vendor_name)
    except Exception as e:  # a decoder bug must not take the page down: show the bytes and say so
        s, tree = {"proto": rec["radio"], "src": "", "dst": "", "info": f"Could not be decoded: {type(e).__name__}", "color": "bad"}, []
    shown = s.pop("payload", None) if rec["radio"] == "lora" else raw
    shown = raw if shown is None else shown
    if rec.get("rssi") is not None and s.get("rssi") is None:
        s["rssi"] = rec["rssi"]
    if rec.get("channel") is not None and not s.get("channel"):
        s["channel"] = rec["channel"]
    if rec.get("tuned") and not s.get("channel"):
        s["channel"] = freq_channel(rec["tuned"])
    s["len"] = len(shown)
    if getattr(LIGHT, "on", False):
        return s, tree, bytes(shown)
    ts = rec.get("ts") or 0
    frame = [node("Arrival time", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) + f".{int(ts % 1 * 1e6):06d}"),
             node("Time since the first frame", f"{ts - (first_ts if first_ts is not None else ts):.6f} seconds"),
             node("Radio", {"wifi": "Wi-Fi", "bt": "Bluetooth", "zigbee": "Zigbee / Thread (IEEE 802.15.4)", "lora": "LoRa"}[rec["radio"]]),
             node("Interface", rec.get("src") or "?"), node("Frame length", f"{len(shown)} bytes")]
    for key, label in (("channel", "Channel"), ("rssi", "Signal"), ("lqi", "Link quality (LQI)"), ("tuned", "Tuned to")):
        if rec.get(key) is not None:
            frame.append(node(label, f"{rec[key]} dBm" if key == "rssi" else f"{rec[key]} MHz" if key == "tuned" else rec[key]))
    tree.insert(0, node(f"Frame {number}", f"{len(shown)} bytes on {rec.get('src') or '?'}", None, None, frame))
    s["len"] = len(shown)
    return s, tree, bytes(shown)
