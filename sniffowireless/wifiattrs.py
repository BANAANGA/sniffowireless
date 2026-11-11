"""Wi-Fi attributes beyond the basic capability fingerprint, all read passively from frames we already capture.

Access points (beacons / probe responses): security suites, load, country, uptime, roaming support, Wi-Fi 6/7 details,
neighbouring APs. Clients: what their capability elements say. Radiotap: link rate and noise. Frame sequence numbers,
which an opt-in feature can use to link a device across its randomised MAC addresses.

Bit and suite numbers come from the IEEE 802.11 definitions as published in hostapd (src/common/ieee802_11_defs.h and
wpa_common.h). Nothing here transmits.
"""

# ---- RSN (WPA2 / WPA3) suite selectors, OUI 00-0f-ac
RSN_AKM = {1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK", 5: "802.1X-SHA256", 6: "PSK-SHA256", 8: "SAE", 9: "FT-SAE",
           11: "Suite B", 12: "Suite B 192", 14: "FILS-SHA256", 15: "FILS-SHA384", 16: "FT-FILS-SHA256", 17: "FT-FILS-SHA384",
           18: "OWE", 19: "FT-PSK-SHA384", 20: "PSK-SHA384", 22: "FT-802.1X-SHA384", 23: "802.1X-SHA384", 24: "SAE-EXT",
           25: "FT-SAE-EXT"}
RSN_CIPHER = {0: "none", 1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104", 6: "BIP-CMAC", 8: "GCMP", 9: "GCMP-256",
              10: "CCMP-256", 11: "BIP-GMAC", 12: "BIP-GMAC-256", 13: "BIP-CMAC-256"}
PSK_LIKE = {"PSK", "FT-PSK", "PSK-SHA256", "PSK-SHA384", "FT-PSK-SHA384"}
SAE_LIKE = {"SAE", "FT-SAE", "SAE-EXT", "FT-SAE-EXT"}

# ---- Extended Capabilities: bit number -> label (only the ones that say something useful)
EXTCAP_BITS = {12: "proxy ARP", 19: "802.11v BSS transition", 22: "multiple BSSID", 23: "timing measurement", 31: "interworking",
               37: "TDLS", 46: "WNM notification", 62: "operating mode notification", 70: "FTM responder", 71: "FTM initiator",
               72: "FILS", 84: "beacon protection"}
LEGACY_RATES = {1.0, 2.0, 5.5, 11.0}  # 802.11b (DSSS / CCK)


def _le16(b, i=0):
    return b[i] | b[i + 1] << 8


def _mac(b):
    return ":".join(f"{x:02x}" for x in b)


def _suite(b):
    """(oui, type) of a 4-byte suite selector."""
    return bytes(b[:3]), b[3]


def parse_rsn(info):
    """RSN element -> {"akm": [...], "pairwise": [...], "group": str, "pmf": "required|optional|off", ...} or None."""
    if len(info) < 8:
        return None
    try:
        gname = _cipher_name(info[2:6])
        i = 6
        n = _le16(info, i)
        i += 2
        pairwise = [_cipher_name(info[i + 4 * k:i + 4 * k + 4]) for k in range(min(n, 8)) if i + 4 * k + 4 <= len(info)]
        i += 4 * n
        if i + 2 > len(info):
            return None
        n = _le16(info, i)
        i += 2
        akm = [_akm_name(info[i + 4 * k:i + 4 * k + 4]) for k in range(min(n, 12)) if i + 4 * k + 4 <= len(info)]
        i += 4 * n
        caps = _le16(info, i) if i + 2 <= len(info) else 0
    except IndexError:
        return None
    pmf = "required" if caps & 0x40 else "optional" if caps & 0x80 else "off"
    out = {"akm": akm, "pairwise": pairwise, "group": gname, "pmf": pmf}
    if akm and SAE_LIKE & set(akm) and PSK_LIKE & set(akm):
        out["transition"] = True  # WPA3 and WPA2 on the same network: the WPA2 side can still be attacked as WPA2
    return out


def _cipher_name(sel):
    oui, t = _suite(sel)
    if oui == b"\x00\x0f\xac":
        return RSN_CIPHER.get(t, f"cipher {t}")
    return "vendor " + ":".join(f"{x:02x}" for x in sel[:3]) + f"/{t}"


def _akm_name(sel):
    oui, t = _suite(sel)
    if oui == b"\x00\x0f\xac":
        return RSN_AKM.get(t, f"akm {t}")
    if oui == b"\x50\x6f\x9a" and t == 2:
        return "DPP"
    if oui == b"\x00\x40\x96" and t == 0:
        return "CCKM"
    return "vendor " + ":".join(f"{x:02x}" for x in sel[:3]) + f"/{t}"


def parse_rnr(info, limit=12):
    """Reduced Neighbor Report -> [{"bssid", "ch", "oc"}]: APs (often on 6 GHz) that this AP advertises."""
    out, i = [], 0
    while i + 4 <= len(info) and len(out) < limit:
        hdr = _le16(info, i)
        count, tlen = ((hdr >> 4) & 0xF) + 1, (hdr >> 8) & 0xFF
        opclass, chan = info[i + 2], info[i + 3]
        i += 4
        if tlen == 0:
            break
        for _ in range(count):
            ent = info[i:i + tlen]
            i += tlen
            if len(ent) < tlen:
                return out
            if tlen in (7, 8, 11, 12, 13, 16) and len(ent) >= 7 and len(out) < limit:  # TBTT offset, then the BSSID
                out.append({"bssid": _mac(ent[1:7]), "ch": chan, "oc": opclass})
    return out


def _wps_state(info):
    """(configured?, setup locked?) from the WPS vendor element body (after the 00:50:f2:04 prefix)."""
    state = locked = None
    i = 0
    while i + 4 <= len(info):
        t, ln = int.from_bytes(info[i:i + 2], "big"), int.from_bytes(info[i + 2:i + 4], "big")
        v = info[i + 4:i + 4 + ln]
        i += 4 + ln
        if t == 0x1044 and v:
            state = v[0] == 2
        elif t == 0x1057 and v:
            locked = bool(v[0])
    return state, locked


def beacon_signature(elts, capability=None, beacon_tu=None):
    """A short hash of how an access point builds its beacon: the order of its information elements (vendor ones by OUI and type),
    the capability bits and the beacon interval. The same firmware on the same chipset builds beacons the same way, so this tells
    models and firmware apart without reading any name; an administrator cannot change it from the settings page."""
    import hashlib
    parts = []
    for eid, info in elts:
        parts.append(f"{eid}-{bytes(info[:4]).hex()}" if eid == 221 else str(eid))
    parts.append(f"cap{capability if capability is not None else ''}")
    parts.append(f"tu{beacon_tu if beacon_tu is not None else ''}")
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:12]


def ap_attributes(elts, beacon_tu=None, capability=None):
    """What a beacon / probe response says about the access point itself. Empty values are left out."""
    out = {"bsig": beacon_signature(elts, capability, beacon_tu)}
    roaming = []
    for eid, info in elts:
        if eid == 7 and len(info) >= 3:  # Country
            cc = bytes(info[:2]).decode("ascii", "replace")
            if cc.isalpha() and cc.isupper():
                out["country"] = cc
                env = chr(info[2]) if info[2] in (0x20, 0x4F, 0x49) else ""
                if env.strip():
                    out["country_env"] = "indoor" if env == "I" else "outdoor"
        elif eid == 11 and len(info) >= 5:  # BSS Load
            out["load"] = {"sta": _le16(info, 0), "util": round(info[2] * 100 / 255)}
        elif eid == 48:
            r = parse_rsn(info)
            if r:
                out["rsn"] = r
        elif eid == 54 and len(info) >= 3:
            roaming.append("11r")
        elif eid == 70:
            roaming.append("11k")
        elif eid == 127:
            bits = _bits(info)
            if 19 in bits:
                roaming.append("11v")
            if 22 in bits:
                out["mbssid"] = True
            if 70 in bits:
                out["ftm"] = True
            if 84 in bits:
                out["beacon_protection"] = True
        elif eid == 71:
            out["mbssid"] = True
        elif eid == 107:
            out["interworking"] = True
        elif eid == 114 and info:
            out["mesh_id"] = bytes(info[:32]).decode("utf-8", "replace")
        elif eid == 201:
            n = parse_rnr(info)
            if n:
                out.setdefault("rnr", []).extend(n)
                out["rnr"] = out["rnr"][:12]
        elif eid == 221 and len(info) >= 4 and bytes(info[:3]) in (b"\x00\x15\x6d", b"\x00\x0b\x86"):   # Ubiquiti / Aruba AP-name elements
            from .apmodels import ARUBA_SUBTYPES, vendor_ap_name
            vendor, name, sub = vendor_ap_name(info) or (None, None, None)
            if vendor == "Aruba" and sub in ARUBA_SUBTYPES:
                out.setdefault("aruba", [])
                if ARUBA_SUBTYPES[sub] not in out["aruba"]:
                    out["aruba"].append(ARUBA_SUBTYPES[sub])
            if name:
                out["ap_name"], out["ap_name_src"] = name, vendor
        elif eid == 221 and len(info) >= 4:
            oui, vtype = bytes(info[:3]), info[3]
            if oui == b"\x00\x50\xf2" and vtype == 1:
                out["wpa1"] = True
            elif oui == b"\x00\x50\xf2" and vtype == 4:
                state, locked = _wps_state(info[4:])
                if state is not None:
                    out["wps_configured"] = state
                if locked:
                    out["wps_locked"] = True
        elif eid == 255 and info:
            ext = info[0]
            if ext == 36 and len(info) >= 5:  # HE Operation: BSS colour is bits 24-29 of the 4-byte parameters, bit 31 disables it
                params = int.from_bytes(info[1:5], "little")
                if not params & 0x80000000:
                    out["bss_color"] = (params >> 24) & 0x3F
            elif ext == 107:  # Multi-Link element: a Wi-Fi 7 multi-link-operation AP
                out["mlo"] = True
    if roaming:
        out["roaming"] = sorted(set(roaming))
    if beacon_tu:
        out["beacon_tu"] = int(beacon_tu)
    return out


def _bits(info):
    """Set bit numbers of an Extended Capabilities element (bit 0 = least significant bit of the first octet)."""
    return {o * 8 + b for o, v in enumerate(info) for b in range(8) if v >> b & 1}


def client_caps(elts):
    """What a client's capability elements (probe / association request) say it can do."""
    out = {}
    caps = []
    rates = set()
    for eid, info in elts:
        if eid in (1, 50):
            rates.update((b & 0x7F) * 0.5 for b in info)
        elif eid == 127:
            bits = _bits(info)
            caps += [label for bit, label in sorted(EXTCAP_BITS.items()) if bit in bits and bit not in (12, 22, 70, 84)]
            out["extcap"] = bytes(info[:16]).hex()
        elif eid == 70:
            caps.append("802.11k radio measurement")
        elif eid == 54:
            caps.append("802.11r fast roaming")
        elif eid == 45 and len(info) >= 2:
            v = _le16(info)
            caps += [name for bit, name in ((0, "LDPC"), (7, "TX STBC"), (5, "short GI 20 MHz")) if v >> bit & 1]
            if (v >> 8) & 3:
                caps.append("RX STBC")
        elif eid == 191 and len(info) >= 4:
            v = int.from_bytes(info[:4], "little")
            if v >> 12 & 1:
                caps.append("SU beamformee")
            if v >> 20 & 1:
                caps.append("MU-MIMO beamformee")
            if v >> 11 & 1 or v >> 19 & 1:
                caps.append("beamformer")
        elif eid == 36 and len(info) >= 2:  # Supported Channels: (first channel, count) pairs
            out["chan_count"] = sum(info[i + 1] for i in range(0, len(info) - 1, 2))
        elif eid == 33 and len(info) >= 2:  # Power Capability, signed dBm
            lo, hi = (b - 256 if b > 127 else b for b in info[:2])
            out["txp"] = [lo, hi]
        elif eid == 59 and info:
            out["opcls"] = list(info[:16])
    if rates:
        out["dsss"] = bool(rates & LEGACY_RATES)  # False: no 802.11b rates, so a modern device
    seen = []
    for c in caps:
        if c not in seen:
            seen.append(c)
    if seen:
        out["caps"] = seen
    return out


def radio_quality(pkt):
    """Link rate / MCS / noise floor from the radiotap header, when the driver supplies them. {} if nothing."""
    out = {}
    try:
        rt = pkt.getlayer("RadioTap")
    except Exception:
        rt = None
    if rt is None:
        return out
    from .survey import rate_from_radiotap  # (imported here: survey needs nothing from this module)
    try:
        rate = rate_from_radiotap(rt)
    except (TypeError, IndexError):
        rate = None
    if rate:
        out["phy_rate"] = round(float(rate), 1)
    noise = getattr(rt, "dBm_AntNoise", None)
    if isinstance(noise, int) and -120 < noise < -20:
        out["noise"] = noise
    return out


def seq_number(pkt):
    """The 12-bit 802.11 sequence number of a management / data frame, or None."""
    try:
        sc = pkt.getlayer("Dot11").SC
    except Exception:
        return None
    return None if sc is None else (int(sc) >> 4) & 0xFFF


class SeqLinker:
    """Opt-in: guess that two randomised MAC addresses are one device because the second one carries on counting where
    the first stopped. Weak evidence on its own (12-bit counter, many devices): a link is only proposed when exactly one
    recently-silent randomised address fits, and it is shown as "possibly the same device", never merged."""
    WINDOW = 4.0       # seconds the old address may have been silent
    MAX_STEP = 40      # frames the counter may have advanced in between
    KEEP = 20_000

    def __init__(self):
        self.last = {}   # mac -> (ts, seq)
        self.seen = set()

    def feed(self, mac, ts, seq):
        """Returns [(old_mac, step)] when `mac` is new and exactly one earlier address fits, else []."""
        new = mac not in self.seen
        if new:
            if len(self.seen) > self.KEEP:
                self.seen.clear()
                self.last.clear()
            self.seen.add(mac)
        out = []
        if len(self.last) > 500:  # keep only the addresses that could still match
            for m in [m for m, (t, _) in self.last.items() if ts - t > self.WINDOW * 5]:
                del self.last[m]
        if new and seq is not None:
            cands = [(m, (seq - s) % 4096) for m, (t, s) in self.last.items()
                     if m != mac and 0 <= ts - t <= self.WINDOW and 1 <= (seq - s) % 4096 <= self.MAX_STEP]
            if len(cands) == 1:
                out = cands
        if seq is not None:
            self.last[mac] = (ts, seq)
        return out
