"""LoRa protocols: the radio settings ("profiles") worth listening on, and a classifier that recognises which protocol a
received frame belongs to from its clear-text structure.

Receive-only and metadata-only. Encrypted payloads are never decrypted and nothing of a message's content is kept: what comes
out is who sent it (an address or name the sender broadcasts itself), who it is for, how it was routed, and how strongly it
was received. A LoRa radio only hears a network while it is set to that network's frequency, bandwidth, spreading factor and
sync word, so the sensor hops between profiles; a profile also says which protocol is expected there, which raises the
confidence of a frame that fits that protocol's structure.

Sources: Meshtastic's firmware (RadioInterface.h/.cpp, Channels.cpp) and docs for the header, sync word and frequency slots;
docs.meshcore.io (packet_format, payloads, radio_presets) and the MeshCore firmware for its packets and defaults; the LoRaWAN
specification for the PHY payload; the LoRa APRS convention of a 3-byte header before the TNC2 text.
"""
import math
import re
import struct
from dataclasses import dataclass
from typing import Optional

SYNC_PRIVATE, SYNC_LORAWAN, SYNC_MESHTASTIC = 0x12, 0x34, 0x2B
BANDWIDTHS = (7.8, 10.4, 15.6, 20.8, 31.25, 41.7, 62.5, 125.0, 250.0, 500.0)  # what the SX126x supports (kHz)
PROTOCOLS = {"meshtastic": "Meshtastic", "meshcore": "MeshCore", "lorawan": "LoRaWAN", "lora-aprs": "LoRa APRS", "unknown": "Unidentified LoRa"}


@dataclass(frozen=True)
class Profile:
    name: str
    label: str
    freq: float      # MHz
    bw: float        # kHz
    sf: int
    cr: int          # 5..8 means coding rate 4/5..4/8
    sync: int
    preamble: int = 8  # the receiver needs a minimum: longer preambles are still detected
    hint: Optional[str] = None  # the protocol expected on these settings

    def describe(self):
        return f"{self.freq:g} MHz · SF{self.sf} · {self.bw:g} kHz"


# ------------------------------------------------------------------------------------------------ Meshtastic
# Region plans (start MHz, end MHz, spacing MHz) and presets (bandwidth kHz, spreading factor, coding rate) from the Meshtastic
# docs (radio-settings, lora configuration) and firmware.
MESHTASTIC_REGIONS = {"US": (902.0, 928.0, 0.0), "EU868": (869.4, 869.65, 0.0), "EU433": (433.0, 434.0, 0.0),
                      "ANZ": (915.0, 928.0, 0.0), "ANZ433": (433.05, 434.79, 0.0)}
MESHTASTIC_PRESETS = {"ShortTurbo": (500, 7, 5), "ShortFast": (250, 7, 5), "ShortSlow": (250, 8, 5),
                      "MediumTurbo": (500, 9, 5), "MediumFast": (250, 9, 5), "MediumSlow": (250, 10, 5),
                      "LongTurbo": (500, 11, 8), "LongFast": (250, 11, 5), "LongModerate": (125, 11, 8),
                      "LiteFast": (125, 9, 5), "LiteSlow": (125, 10, 5), "NarrowFast": (62.5, 7, 6), "NarrowSlow": (62.5, 8, 6),
                      "TinyFast": (15.6, 7, 5), "TinySlow": (15.6, 8, 6)}


def airtime_ms(length, sf, bw_khz, cr=5, preamble=8, crc=True, explicit_header=True):
    """How long a frame of `length` bytes occupies the channel (Semtech's time-on-air formula, SX127x/SX126x datasheets).
    cr is the coding rate denominator 5..8 (4/5 .. 4/8)."""
    tsym = (2 ** sf) / (bw_khz * 1000.0)
    de = 1 if tsym > 0.016 else 0  # low data rate optimisation
    ih = 0 if explicit_header else 1
    bits = 8 * length - 4 * sf + 28 + (16 if crc else 0) - 20 * ih
    symbols = 8 + max(math.ceil(bits / (4 * (sf - 2 * de))) * cr, 0)
    return ((preamble + 4.25) * tsym + symbols * tsym) * 1000.0


# What the senders of each protocol use for the preamble (the receiver listens for 8 so it also hears shorter ones).
AIR_PREAMBLE = {"meshtastic": 16, "meshcore": 16}


def meshtastic_hash(name):
    """djb2 as in the firmware: the default channel's name (the preset's) picks its frequency slot."""
    h = 5381
    for c in name.encode("utf-8"):
        h = ((h << 5) + h + c) & 0xFFFFFFFF
    return h


def meshtastic_frequency(region, preset="LongFast"):
    """The frequency (MHz) the default channel of a preset is on in a region, by the firmware's formula."""
    start, end, spacing = MESHTASTIC_REGIONS[region]
    bw = MESHTASTIC_PRESETS[preset][0]
    slots = max(1, math.floor(round((end - start) / (spacing + bw / 1000), 6)))
    return round(start + bw / 2000 + (meshtastic_hash(preset) % slots) * (bw / 1000), 4)


def meshtastic_profile(region, preset="LongFast"):
    bw, sf, cr = MESHTASTIC_PRESETS[preset]
    f = meshtastic_frequency(region, preset)
    return Profile(f"meshtastic-{region.lower()}" if preset == "LongFast" else f"meshtastic-{region.lower()}-{preset.lower()}",
                   f"Meshtastic {preset} ({region})", f, bw, sf, cr, SYNC_MESHTASTIC, 8, "meshtastic")


PROFILES = {p.name: p for p in (
    [meshtastic_profile(r) for r in ("EU868", "US", "ANZ", "EU433")]
    + [Profile("meshcore-eu868", "MeshCore (EU/UK 869.618, the firmware default)", 869.618, 62.5, 8, 5, SYNC_PRIVATE, 8, "meshcore"),
       Profile("meshcore-au-narrow", "MeshCore (Australia narrow)", 916.575, 62.5, 7, 7, SYNC_PRIVATE, 8, "meshcore"),
       Profile("meshcore-nz-narrow", "MeshCore (New Zealand narrow)", 917.375, 62.5, 7, 5, SYNC_PRIVATE, 8, "meshcore"),
       Profile("lorawan-eu868", "LoRaWAN EU868 (868.1 MHz, SF7)", 868.1, 125, 7, 5, SYNC_LORAWAN, 8, "lorawan"),
       Profile("lorawan-us915-sb2", "LoRaWAN US915 sub-band 2 (903.9 MHz, SF7)", 903.9, 125, 7, 5, SYNC_LORAWAN, 8, "lorawan"),
       Profile("lora-aprs-433", "LoRa APRS (433.775 MHz, SF12)", 433.775, 125, 12, 5, SYNC_PRIVATE, 8, "lora-aprs")])}

REGION_DEFAULTS = {"EU868": ["meshtastic-eu868", "meshcore-eu868"], "US915": ["meshtastic-us"],
                   "ANZ": ["meshtastic-anz", "meshcore-au-narrow"]}


def parse_profiles(spec, region="EU868"):
    """The profiles for LORA_PROFILES: comma separated names from PROFILES, `meshtastic:<region>[:<preset>]`, or a custom
    `name=freq/bw/sf/cr/sync[/preamble]` (MHz, kHz, spreading factor, coding rate 5-8, sync word like 0x12). Empty means the
    region's defaults. Raises ValueError saying what is wrong."""
    items = [x.strip() for x in (spec or "").split(",") if x.strip()]
    if not items:
        key = (region or "EU868").upper()
        if key not in REGION_DEFAULTS:
            raise ValueError(f"unknown LORA_REGION {region!r}; use one of {', '.join(REGION_DEFAULTS)}")
        items = REGION_DEFAULTS[key]
    out = []
    for item in items:
        if item.lower() in PROFILES:
            out.append(PROFILES[item.lower()])
        elif item.lower().startswith("meshtastic:"):
            parts = item.split(":")
            reg = parts[1].upper() if len(parts) > 1 else ""
            preset = next((p for p in MESHTASTIC_PRESETS if p.lower() == (parts[2] if len(parts) > 2 else "LongFast").lower()), None)
            if reg not in MESHTASTIC_REGIONS or preset is None or len(parts) > 3:
                raise ValueError(f"{item!r}: use meshtastic:<{'|'.join(MESHTASTIC_REGIONS)}>[:<preset>]")
            out.append(meshtastic_profile(reg, preset))
        elif "=" in item:
            name, _, params = item.partition("=")
            f = params.split("/")
            if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", name) or len(f) not in (5, 6):
                raise ValueError(f"{item!r}: use name=freq/bw/sf/cr/sync[/preamble], for example mesh=868.3/125/7/5/0x34")
            try:
                freq, bw, sf, cr, sync = float(f[0]), float(f[1]), int(f[2]), int(f[3]), int(f[4], 0)
                preamble = int(f[5]) if len(f) == 6 else 8
            except ValueError:
                raise ValueError(f"{item!r}: the settings must be numbers")
            if not (150 <= freq <= 960 and bw in BANDWIDTHS and 5 <= sf <= 12 and 5 <= cr <= 8 and 0 <= sync <= 255 and 6 <= preamble <= 65535):
                raise ValueError(f"{item!r}: frequency 150-960 MHz, bandwidth one of {', '.join(f'{b:g}' for b in BANDWIDTHS)} kHz, "
                                 "SF 5-12, coding rate 5-8, sync 0-255")
            hint = {SYNC_MESHTASTIC: "meshtastic", SYNC_LORAWAN: "lorawan"}.get(sync)
            out.append(Profile(name.lower(), name, freq, bw, sf, cr, sync, preamble, hint))
        else:
            raise ValueError(f"unknown LoRa profile {item!r}; known: {', '.join(PROFILES)}")
    return list({p.name: p for p in out}.values())


# ------------------------------------------------------------------------------------------------ classification
def _printable(b):
    return sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13)) / len(b) if b else 0.0


def _entropy(b):
    if not b:
        return 0.0
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in (b.count(v) for v in set(b)))


def _meshtastic(p, sync, hint):
    """16-byte clear header (to, from, id, flags, channel hash, next hop, relay node) then the encrypted Data protobuf."""
    if len(p) < 17:
        return None
    to, frm, pid = struct.unpack_from("<III", p, 0)
    flags, chan, next_hop, relay = p[12], p[13], p[14], p[15]
    hop_limit, hop_start = flags & 0x07, flags >> 5
    score = 20 + (15 if frm not in (0, 0xFFFFFFFF) else 0) + (10 if pid else 0) + (5 if to else 0) \
        + (10 if hop_start == 0 or hop_start >= hop_limit else 0)
    # The sync word is a hardware filter and Meshtastic always uses 0x2B: without it nothing here is evidence enough.
    prior = 40 if sync == SYNC_MESHTASTIC else 15 if hint == "meshtastic" else 0
    score = min(100, score + prior) if prior else min(score, 40)
    info = {"id": f"{pid:08x}", "hop_limit": hop_limit, "channel": f"{chan:02x}", "payload_bytes": len(p) - 16}
    if hop_start:
        info.update(hop_start=hop_start, hops_taken=max(0, hop_start - hop_limit), relay=f"{relay:02x}",
                    next_hop=f"{next_hop:02x}" if next_hop else None)
    if flags & 0x08:
        info["want_ack"] = True
    if flags & 0x10:
        info["via_mqtt"] = True
    return {"protocol": "meshtastic", "score": score, "kind": "broadcast" if to == 0xFFFFFFFF else "direct",
            "src": f"!{frm:08x}", "dst": "broadcast" if to == 0xFFFFFFFF else f"!{to:08x}", "hops": info.get("hops_taken"),
            "node": (f"!{frm:08x}", None, "node") if frm not in (0, 0xFFFFFFFF) else None, "info": {k: v for k, v in info.items() if v is not None}}


MC_ROUTES = ("transport flood", "flood", "direct", "transport direct")
MC_TYPES = {0: "request", 1: "response", 2: "text message", 3: "ack", 4: "advert", 5: "group text", 6: "group data",
            7: "anonymous request", 8: "path", 9: "trace", 10: "multipart", 11: "control", 15: "custom"}
MC_NODE_TYPES = {1: "chat node", 2: "repeater", 3: "room server", 4: "sensor"}


def _meshcore(p, sync, hint):
    """[header][transport codes?][path length][path][payload], from docs.meshcore.io/packet_format."""
    if len(p) < 2:
        return None
    h = p[0]
    route, ptype, ver = h & 3, (h >> 2) & 15, h >> 6
    if ptype in (12, 13, 14):  # reserved
        return None
    o = 1
    if route in (0, 3):
        o += 4  # transport codes
    if o >= len(p):
        return None
    hops, hsize = p[o] & 0x3F, (p[o] >> 6) + 1
    o += 1
    if hsize == 4 or hops * hsize > 64 or o + hops * hsize > len(p):
        return None
    path = p[o:o + hops * hsize]
    body = p[o + hops * hsize:]
    if len(body) > 184:
        return None
    score = 20 + (10 if ver == 0 else 0)
    info = {"route": MC_ROUTES[route], "hops": hops, "hash_bytes": hsize, "payload_bytes": len(body)}
    if hops:
        info["path"] = path.hex()
    kind, src, dst, name, node = MC_TYPES[ptype], None, None, None, None
    if ptype == 4 and len(body) >= 101:  # advert: public key 32, timestamp 4, signature 64, then app data
        flags = body[100]
        off, ntype = 101, flags & 0x0F
        off += 8 if flags & 0x10 else 0
        off += 2 if flags & 0x20 else 0
        off += 2 if flags & 0x40 else 0
        if ntype in MC_NODE_TYPES and off <= len(body):
            text = body[off:].decode("utf-8", "replace") if flags & 0x80 else None
            score += 45 + (10 if text and _printable(text.encode()) > 0.9 else 0)
            name = text
            node = (f"pk:{body[:4].hex()}", text, MC_NODE_TYPES[ntype])
            info.update(node_type=MC_NODE_TYPES[ntype], location_shared=bool(flags & 0x10), public_key=body[:8].hex())
            src = node[0]
    elif ptype == 3 and len(body) == 4:
        score += 25
    elif ptype in (0, 1, 2, 8) and len(body) >= 5:
        score += 10
        dst, src = f"h:{body[0]:02x}", f"h:{body[1]:02x}"
        node = (src, None, "hash")
    elif ptype == 7 and len(body) >= 36:
        score += 10
        dst = f"h:{body[0]:02x}"
        node = (f"pk:{body[1:5].hex()}", None, "node")
        src = node[0]
    elif ptype in (5, 6) and len(body) >= 4:
        score += 10
        info["channel"] = f"{body[0]:02x}"
    elif ptype == 11 and body:
        score += 5
        info["control"] = body[0] >> 4
    prior = 20 if hint == "meshcore" else 0
    prior += 5 if sync == SYNC_PRIVATE else 0
    score = min(100, score + prior) if prior else min(score, 35)
    return {"protocol": "meshcore", "score": score, "kind": kind, "src": src, "dst": dst or ("flood" if route in (0, 1) else None),
            "hops": hops, "name": name, "node": node, "info": info}


LW_MTYPES = ("join request", "join accept", "unconfirmed uplink", "unconfirmed downlink", "confirmed uplink", "confirmed downlink",
             "rejoin request", "proprietary")


def _lorawan(p, sync, hint):
    """MHDR | MACPayload | MIC (4), from the LoRaWAN specification."""
    if len(p) < 12:
        return None
    mtype, rfu, major = p[0] >> 5, (p[0] >> 2) & 7, p[0] & 3
    if major != 0:
        return None
    score = 15 + (10 if rfu == 0 else 0)
    info = {"payload_bytes": len(p)}
    src = dst = node = None
    if mtype == 0 and len(p) == 23:  # join request: JoinEUI 8, DevEUI 8, DevNonce 2 (little endian on the wire)
        score += 30
        join_eui, dev_eui = p[1:9][::-1].hex(), p[9:17][::-1].hex()
        info.update(join_eui=join_eui, dev_eui=dev_eui)
        src, node = f"eui:{dev_eui}", (f"eui:{dev_eui}", None, "device")
    elif mtype in (0, 1):  # join request / accept have exact sizes: any other length is not one
        if mtype == 1 and len(p) in (17, 33):
            score += 30
        else:
            score -= 25
    elif mtype in (2, 3, 4, 5):
        fopts = p[5] & 0x0F
        if len(p) >= 12 + fopts:
            score += 25
            dev_addr = p[1:5][::-1].hex()
            fcnt = struct.unpack_from("<H", p, 6)[0]
            fctrl = p[5]
            info.update(dev_addr=dev_addr, fcnt=fcnt)
            if len(p) > 12 + fopts:
                info["fport"] = p[8 + fopts]
            if fctrl & 0x80:
                info["adr"] = True
            if fctrl & 0x20:
                info["ack"] = True
            if mtype in (2, 4):
                src, node = dev_addr, (dev_addr, None, "device")
            else:
                dst = dev_addr
        else:
            score -= 25
    elif mtype in (6, 7):
        score += 5
    prior = 40 if sync == SYNC_LORAWAN else 10 if hint == "lorawan" else 0
    score = min(100, score + prior) if prior else min(score, 40)
    return {"protocol": "lorawan", "score": score, "kind": LW_MTYPES[mtype], "src": src, "dst": dst, "hops": None, "node": node, "info": info}


def _aprs(p, sync, hint):
    """LoRa APRS: 3-byte header `<` 0xFF 0x01, then TNC2 text `SRC>DEST[,PATH]:data`."""
    if p[:3] != b"<\xff\x01" or len(p) < 8:
        return None
    text = p[3:].decode("latin-1")
    m = re.match(r"^([A-Za-z0-9-]{1,9})>([A-Za-z0-9-]{1,9})((?:,[A-Za-z0-9*-]{1,9})*):(.*)$", text, re.S)
    if not m:
        return {"protocol": "lora-aprs", "score": 60, "kind": "frame", "src": None, "dst": None, "hops": None, "node": None, "info": {}}
    src, dst, path, data = m.group(1), m.group(2), m.group(3), m.group(4)
    kinds = {"!": "position", "=": "position", "/": "position", "@": "position", ":": "message", ">": "status", "_": "weather", ";": "object"}
    return {"protocol": "lora-aprs", "score": 95, "kind": kinds.get(data[:1], "frame"), "src": src, "dst": dst, "hops": path.count(",") or None,
            "node": (src, None, "station"), "info": {"path": path.lstrip(",") or None}}


LEVELS = ((80, "high"), (65, "medium"), (50, "low"))


def classify(payload, sync=None, hint=None):
    """Work out which protocol a received frame is, from its structure and the settings it was heard on.

    `sync` is the sync word the radio listened with and `hint` the protocol its profile is meant for. Returns a dict with the
    protocol id and label, a confidence (0-100) and level, the message kind, the sender and destination as the packet
    names them, hops, a name if the sender broadcast one, the sender as a node (address, name, kind) and a small `info` dict.
    A frame no protocol fits comes back as "unknown" with the figures that help to recognise it later."""
    best = None
    for fn in (_aprs, _meshtastic, _lorawan, _meshcore):
        try:
            r = fn(payload, sync, hint)
        except (struct.error, IndexError, ValueError):
            r = None
        if r and (best is None or r["score"] > best["score"]):
            best = r
    if best is None or best["score"] < 50:
        pr = _printable(payload)
        return {"protocol": "unknown", "label": PROTOCOLS["unknown"], "confidence": 0, "level": "none",
                "kind": "plain text" if pr >= 0.9 and len(payload) >= 4 else "unidentified", "src": None, "dst": None, "hops": None,
                "name": None, "node": None, "info": {"payload_bytes": len(payload), "entropy": round(_entropy(payload), 1)}}
    level = next((name for floor, name in LEVELS if best["score"] >= floor), "low")
    best.setdefault("name", None)
    best.update(label=PROTOCOLS[best["protocol"]], confidence=best.pop("score"), level=level)
    return best
