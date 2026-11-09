"""Reading Meshtastic packets that are meant to be read by anyone: the ones on a channel that uses the public default key
(the "AQ==" every Meshtastic device ships with, published in the firmware and the documentation) and the ones sent without
encryption. Text messages, positions, node names and telemetry of those channels are broadcast to every receiver in range by
design, and are also relayed to the public MQTT server.

What this does NOT do: it has only that one published key. A channel with its own key, and direct messages (which are
public-key encrypted) stay unreadable and are reported as they were before: who sent it, to whom, how it was relayed.

Format (Meshtastic firmware: RadioInterface, CryptoEngine, mesh.proto, portnums.proto): a 16-byte clear header, then the Data
protobuf encrypted with AES-128-CTR; the counter block is  packet id (u64 LE) | sender node (u32 LE) | 0 (u32).
No dependencies: AES is written out below (encryption only; CTR mode needs nothing else) and checked against FIPS-197 in the tests.
"""
import math
import struct

DEFAULT_KEY = bytes.fromhex("d4f1bb3a20290759f0bcffabcf4e6901")

PORTS = {1: "text message", 3: "position", 4: "node info", 5: "routing", 6: "admin", 8: "waypoint", 10: "detection sensor",
         32: "reply", 34: "paxcounter", 65: "store and forward", 66: "range test", 67: "telemetry", 70: "traceroute",
         71: "neighbor info", 73: "map report"}
HW_MODELS = {4: "T-Beam", 5: "Heltec V2.0", 7: "T-Echo", 9: "RAK4631", 10: "Heltec V2.1", 12: "LilyGO T-LoRa V2.1", 13: "Heltec V1",
             39: "T-Deck", 43: "Heltec V3", 44: "Heltec WSL V3", 48: "Heltec Wireless Tracker", 50: "Seeed Xiao ESP32S3", 51: "Seeed Wio Tracker L1",
             47: "RP2040 LoRa", 255: "Private hardware"}
ROLES = {0: "client", 1: "client mute", 2: "router", 3: "router client", 4: "repeater", 5: "tracker", 6: "sensor", 7: "TAK",
         8: "client hidden", 9: "lost and found", 10: "TAK tracker", 11: "router late", 12: "client base"}

# ------------------------------------------------------------------------------------------------ AES-128 (encrypt)
_SBOX = bytearray(256)


def _build_sbox():
    p = q = 1
    while True:  # multiplicative inverse by walking the field with generators 3 and its inverse (the standard construction)
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) & 0xFF ^ ((q << 2) | (q >> 6)) & 0xFF ^ ((q << 3) | (q >> 5)) & 0xFF ^ ((q << 4) | (q >> 4)) & 0xFF
        _SBOX[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    _SBOX[0] = 0x63


_build_sbox()


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _expand_key(key):
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [_SBOX[t[1]] ^ rcon, _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
            rcon = _xtime(rcon)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum(w[r * 4:r * 4 + 4], []) for r in range(11)]


def aes128_encrypt_block(key, block):
    rk = _expand_key(key)
    s = [b ^ k for b, k in zip(block, rk[0])]
    for rnd in range(1, 11):
        s = [_SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]  # ShiftRows (column-major state)
        if rnd < 10:
            out = []
            for c in range(0, 16, 4):
                a = s[c:c + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                out += [a[i] ^ t ^ _xtime(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
            s = out
        s = [b ^ k for b, k in zip(s, rk[rnd])]
    return bytes(s)


def aes_ctr(key, nonce, data):
    """AES-128 in counter mode: the 16-byte `nonce` is the first counter block, counted up as a big-endian number."""
    out = bytearray()
    counter = int.from_bytes(nonce, "big")
    for i in range(0, len(data), 16):
        ks = aes128_encrypt_block(key, counter.to_bytes(16, "big"))
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], ks))
        counter = (counter + 1) & ((1 << 128) - 1)
    return bytes(out)


# ------------------------------------------------------------------------------------------------ protobuf (just enough)
class BadProto(ValueError):
    pass


def _varint(b, i):
    v = shift = 0
    while True:
        if i >= len(b) or shift > 63:
            raise BadProto("varint")
        x = b[i]
        i += 1
        v |= (x & 0x7F) << shift
        if not x & 0x80:
            return v, i
        shift += 7


def fields(b):
    """{field number: value} of a protobuf message (the last occurrence wins). Values: int for varints, 4 / 8 raw bytes for
    fixed32 / fixed64, bytes for length-delimited. Raises BadProto unless the bytes are exactly a message."""
    out, i = {}, 0
    while i < len(b):
        tag, i = _varint(b, i)
        num, wire = tag >> 3, tag & 7
        if num == 0:
            raise BadProto("field 0")
        if wire == 0:
            out[num], i = _varint(b, i)
        elif wire == 1:
            out[num], i = b[i:i + 8], i + 8
        elif wire == 2:
            n, i = _varint(b, i)
            if i + n > len(b):
                raise BadProto("length")
            out[num], i = b[i:i + n], i + n
        elif wire == 5:
            out[num], i = b[i:i + 4], i + 4
        else:
            raise BadProto("wire type")
        if i > len(b):
            raise BadProto("truncated")
    return out


def _s32(v):
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v


def _f32(raw):
    return struct.unpack("<f", raw)[0] if isinstance(raw, bytes) and len(raw) == 4 else None


def _i32(raw):
    return struct.unpack("<i", raw)[0] if isinstance(raw, bytes) and len(raw) == 4 else None


def _text(raw, limit=240):
    if not isinstance(raw, bytes):
        return None
    t = raw.decode("utf-8")  # UnicodeDecodeError (a ValueError) when it is not text
    if not t or sum(1 for c in t if c.isprintable() or c in "\n\t") < len(t) * 0.9:
        raise BadProto("not text")
    return "".join(c for c in t if c.isprintable() or c in "\n\t")[:limit]


# ------------------------------------------------------------------------------------------------ payloads
def _position(b):
    f = fields(b)
    lat, lon = _i32(f.get(1)), _i32(f.get(2))
    out = {}
    if lat is not None and lon is not None and (lat or lon) and abs(lat) <= 900000000 and abs(lon) <= 1800000000:
        out.update(lat=round(lat / 1e7, 6), lon=round(lon / 1e7, 6))
    if isinstance(f.get(3), int):
        out["alt"] = _s32(f[3])
    if isinstance(f.get(19), int):
        out["sats"] = f[19]
    if isinstance(f.get(23), int):
        out["precision_bits"] = f[23]
    if isinstance(f.get(15), int):
        out["speed"] = f[15]  # m/s
    if not out:
        raise BadProto("empty position")
    return out


def _user(b):
    f = fields(b)
    out = {}
    for key, num in (("long_name", 2), ("short_name", 3), ("id", 1)):
        t = _text(f.get(num), 40) if num in f else None
        if t:
            out[key] = t
    if isinstance(f.get(5), int):
        out["hardware"] = HW_MODELS.get(f[5], f"model {f[5]}")
    if isinstance(f.get(7), int):
        out["role"] = ROLES.get(f[7], f"role {f[7]}")
    if not out:
        raise BadProto("empty user")
    return out


def _telemetry(b):
    f = fields(b)
    out = {}
    if isinstance(f.get(2), bytes):  # device metrics
        m = fields(f[2])
        for key, num, kind in (("battery", 1, "int"), ("voltage", 2, "f"), ("channel_util", 3, "f"), ("air_util_tx", 4, "f"), ("uptime", 5, "int")):
            v = m.get(num)
            v = v if kind == "int" and isinstance(v, int) else _f32(v) if kind == "f" else None
            if v is not None and not (isinstance(v, float) and not math.isfinite(v)):
                out[key] = round(v, 2) if isinstance(v, float) else v
    elif isinstance(f.get(3), bytes):  # environment metrics
        m = fields(f[3])
        for key, num in (("temperature", 1), ("humidity", 2), ("pressure", 3)):
            v = _f32(m.get(num))
            if v is not None and math.isfinite(v):
                out[key] = round(v, 1)
    if not out:
        raise BadProto("no readable telemetry")
    return out


def _waypoint(b):
    f = fields(b)
    out = {}
    lat, lon = _i32(f.get(2)), _i32(f.get(3))
    if lat is not None and lon is not None:
        out.update(lat=round(lat / 1e7, 6), lon=round(lon / 1e7, 6))
    for key, num in (("name", 6), ("description", 7)):
        if num in f:
            t = _text(f[num], 100)
            if t:
                out[key] = t
    if not out:
        raise BadProto("empty waypoint")
    return out


# ------------------------------------------------------------------------------------------------ the entry point
def decode_data(plain):
    """The Data message of a packet, as {port, port_name, ...contents} - or None when `plain` is not one (so wrong key / no key)."""
    try:
        f = fields(plain)
        port = f.get(1)
        if not isinstance(port, int) or port not in PORTS or not isinstance(f.get(2), bytes):
            return None
        body = f[2]
        out = {"port": port, "port_name": PORTS[port]}
        if port == 1:
            t = _text(body)
            if not t:
                return None
            out["text"] = t
        elif port == 3:
            out["position"] = _position(body)
        elif port == 4:
            out["user"] = _user(body)
        elif port == 67:
            out["telemetry"] = _telemetry(body)
        elif port == 8:
            out["waypoint"] = _waypoint(body)
        # other ports (routing, admin, traceroute...) are named but their contents are not looked at
        return out
    except (BadProto, UnicodeDecodeError, struct.error):
        return None


def decode(packet, key=DEFAULT_KEY):
    """Decode a Meshtastic radio packet (header + encrypted Data) that the public default key, or no key at all, opens.
    Returns the decode_data dict (plus `encrypted`: whether the default key was needed), or None when it is private."""
    if len(packet) < 18:
        return None
    pid, frm = struct.unpack_from("<I", packet, 8)[0], struct.unpack_from("<I", packet, 4)[0]
    body = packet[16:]
    out = decode_data(body)  # a channel without encryption
    if out:
        return {**out, "encrypted": False}
    nonce = struct.pack("<QI", pid, frm) + bytes(4)
    out = decode_data(aes_ctr(key, nonce, body))
    return {**out, "encrypted": True} if out else None
