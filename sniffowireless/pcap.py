"""Recordings as pcapng, for Wireshark and the other tools that read it, and pcap / pcapng files made elsewhere as recordings.

Each radio has a link type Wireshark decodes; every (radio, interface) pair of a recording becomes an interface of its own in the
file, named after the interface the frame came from:

    Wi-Fi       127 IEEE802_11_RADIOTAP    the frame with its radiotap header, as recorded
    Bluetooth   201 BLUETOOTH_HCI_H4_WITH_PHDR   direction "received" + the H4 HCI event
    Zigbee      283 IEEE802_15_4_TAP       TLVs for FCS type (none), channel, signal and LQI + the 802.15.4 frame
    LoRa        270 LORATAP                LoRaTap v0 (frequency, bandwidth, SF, RSSI, SNR, sync word) + the LoRa payload

Importing reads pcap (micro- or nanosecond, either byte order), pcapng (enhanced and simple packet blocks, every section and
interface) and either of them gzipped. Besides the four above it takes 105 IEEE802_11 (given an empty radiotap header),
187 BLUETOOTH_HCI_H4, 195 IEEE802_15_4_WITHFCS and 230 IEEE802_15_4_NOFCS. Packets of other link types (Ethernet, USB, ...) and
Bluetooth packets that are not HCI events are counted and left out. Wi-Fi data frames are cut to their headers, as in a recording.
"""
import gzip
import io
import struct
import zlib

LT_80211, LT_RADIOTAP, LT_H4, LT_H4_PHDR = 105, 127, 187, 201
LT_154_FCS, LT_154_NOFCS, LT_LORATAP, LT_154_TAP = 195, 230, 270, 283
LINKTYPE_NAMES = {0: "Null", 1: "Ethernet", 101: "Raw IP", 105: "IEEE 802.11", 113: "Linux cooked", 119: "Prism", 127: "802.11 radiotap",
                  163: "AVS", 187: "Bluetooth H4", 189: "USB Linux", 192: "PPI", 195: "802.15.4 with FCS", 201: "Bluetooth H4 with header",
                  215: "802.15.4 non-ASK PHY", 220: "USB Linux mmapped", 230: "802.15.4 without FCS", 249: "USBPcap", 270: "LoRaTap",
                  276: "Linux cooked v2", 283: "802.15.4 TAP"}
LINKTYPE = {"wifi": LT_RADIOTAP, "bt": LT_H4_PHDR, "zigbee": LT_154_TAP, "lora": LT_LORATAP}
SNAPLEN = 262144
GUNZIP_MAX = 256 * 1024 * 1024   # an imported file after gunzip


def _block(btype, body):
    body += b"\0" * (-len(body) % 4)
    n = 12 + len(body)
    return struct.pack("<II", btype, n) + body + struct.pack("<I", n)


def _opt(code, value):
    return struct.pack("<HH", code, len(value)) + value + b"\0" * (-len(value) % 4)


def _opts(*pairs):
    out = b"".join(_opt(c, v) for c, v in pairs if v)
    return out + (struct.pack("<HH", 0, 0) if out else b"")


def header(app="sniffowireless"):
    """The section header block that starts the file."""
    return _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + _opts((4, app.encode())))


def interface(linktype, name, description=""):
    return _block(1, struct.pack("<HHI", linktype, 0, SNAPLEN) + _opts((2, name.encode("utf-8", "replace")), (3, description.encode())))


def packet(iface, ts, data, comment=None):
    t = int(round((ts or 0) * 1e6))
    return _block(6, struct.pack("<IIIII", iface, t >> 32, t & 0xFFFFFFFF, len(data), len(data)) + data
                  + b"\0" * (-len(data) % 4) + _opts((1, comment.encode("utf-8", "replace") if comment else b"")))


def _rssi_byte(v):
    return max(0, min(255, int(round(v + 139))))


def loratap(line):
    """A sniffer line (`RX,...`) as a LoRaTap v0 header + the LoRa payload, or None if it is not a received frame."""
    from .lora import parse_rx
    rx = parse_rx(bytes(line).decode("ascii", "replace").strip())
    if not rx:
        return None
    bw = {125: 1, 250: 2, 500: 3}.get(int(round(rx["bw"])), 0)
    snr = max(-128, min(127, int(round(rx["snr"] * 4))))
    rssi = _rssi_byte(rx["rssi"])
    head = struct.pack(">BBHIBBBBBbB", 0, 0, 15, int(round(rx["freq"] * 1e6)), bw, rx["sf"] & 0xFF, rssi, rssi, rssi, snr, rx["sync"] & 0xFF)
    return head + bytes.fromhex(rx["hex"])


def tap154(rec):
    """IEEE 802.15.4 TAP header: FCS type none (a stick hands over the frame without it), channel, signal and LQI."""
    tlvs = struct.pack("<HHB", 0, 1, 0) + b"\0" * 3
    if isinstance(rec.get("rssi"), (int, float)):
        tlvs += struct.pack("<HHf", 1, 4, float(rec["rssi"]))
    if isinstance(rec.get("channel"), int):
        tlvs += struct.pack("<HHHB", 3, 3, rec["channel"], 0) + b"\0"
    if isinstance(rec.get("lqi"), int):
        tlvs += struct.pack("<HHB", 10, 1, rec["lqi"] & 0xFF) + b"\0" * 3
    return struct.pack("<BBH", 0, 0, 4 + len(tlvs)) + tlvs


def encode(rec):
    """(link type, packet bytes) of one recorded frame (capture.read's dict), or None when it cannot be written."""
    radio, raw = rec["radio"], bytes(rec["raw"])
    if radio == "wifi":
        return LT_RADIOTAP, raw
    if radio == "bt":
        return LT_H4_PHDR, struct.pack(">I", 1) + raw
    if radio == "zigbee":
        return LT_154_TAP, tap154(rec) + raw
    if radio == "lora":
        p = loratap(raw)
        return (LT_LORATAP, p) if p else None
    return None


def export(records):
    """The pcapng file, block by block, of an iterable of recorded frames: for a streamed response."""
    yield header()
    ifaces = {}
    for rec in records:
        enc = encode(rec)
        if not enc:
            continue
        lt, data = enc
        key = (rec["radio"], rec.get("src") or rec["radio"])
        if key not in ifaces:
            ifaces[key] = len(ifaces)
            yield interface(lt, key[1], {"wifi": "Wi-Fi", "bt": "Bluetooth", "zigbee": "Zigbee / Thread", "lora": "LoRa"}[rec["radio"]])
        yield packet(ifaces[key], rec.get("ts"), data)


# ------------------------------------------------------------------ import
class NotCapture(ValueError):
    pass


def gunzip(data):
    if data[:2] != b"\x1f\x8b":
        return data
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
            out = f.read(GUNZIP_MAX + 1)
    except (OSError, EOFError, zlib.error) as e:
        raise NotCapture(f"the gzip file could not be read ({e})") from None
    if len(out) > GUNZIP_MAX:
        raise NotCapture("the file is too large once unpacked")
    return out


def packets(data):
    """(link type, timestamp, bytes, interface name or None) of every packet in a pcap or pcapng file."""
    data = gunzip(data)
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        yield from _pcap(data)
    elif magic == b"\x0a\x0d\x0d\x0a":
        yield from _pcapng(data)
    else:
        raise NotCapture("it is not a pcap or pcapng file")


def _pcap(data):
    e = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    div = 1e9 if data[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
    if len(data) < 24:
        raise NotCapture("the pcap header is cut short")
    lt = struct.unpack(e + "I", data[20:24])[0] & 0x0FFFFFFF
    at = 24
    while at + 16 <= len(data):
        sec, frac, incl, _ = struct.unpack(e + "IIII", data[at:at + 16])
        at += 16
        if incl > SNAPLEN or at + incl > len(data):
            return   # cut short: what came before is kept
        yield lt, sec + frac / div, data[at:at + incl], None
        at += incl


def _pcapng(data):
    e, ifaces, at = "<", [], 0
    while at + 12 <= len(data):
        btype = struct.unpack(e + "I", data[at:at + 4])[0]
        if btype == 0x0A0D0D0A:   # a section header: its byte order and a fresh list of interfaces
            e = "<" if data[at + 8:at + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            ifaces = []
        blen = struct.unpack(e + "I", data[at + 4:at + 8])[0]
        if blen < 12 or blen % 4 or at + blen > len(data):
            return
        body = data[at + 8:at + blen - 4]
        at += blen
        if btype == 1 and len(body) >= 8:
            ifaces.append(_interface(body, e))
        elif btype == 6 and len(body) >= 20:
            iid, hi, lo, cap, _ = struct.unpack(e + "IIIII", body[:20])
            if iid < len(ifaces) and cap <= len(body) - 20:
                lt, div, name = ifaces[iid]
                yield lt, ((hi << 32) | lo) / div, body[20:20 + cap], name
        elif btype == 3 and len(body) >= 4 and ifaces:   # simple packet block: interface 0, no time
            orig = struct.unpack(e + "I", body[:4])[0]
            yield ifaces[0][0], 0, body[4:4 + min(orig, len(body) - 4)], ifaces[0][2]


def _options(opts, e):
    out, at = {}, 0
    while at + 4 <= len(opts):
        code, n = struct.unpack(e + "HH", opts[at:at + 4])
        if code == 0:
            break
        out.setdefault(code, opts[at + 4:at + 4 + n])
        at += 4 + n + (-n % 4)
    return out


def _interface(body, e):
    """(link type, timestamp units per second, name) of an interface description block."""
    o = _options(body[8:], e)
    v = o.get(9, b"\x06")[:1] or b"\x06"
    div = float(2 ** (v[0] & 0x7F)) if v[0] & 0x80 else float(10 ** v[0])
    name = "".join(ch for ch in o.get(2, b"").decode("utf-8", "replace")[:64] if ch.isprintable()) or None
    return struct.unpack(e + "H", body[:2])[0], div, name


def _from_tap154(p):
    if len(p) < 4:
        return None
    hlen = struct.unpack("<H", p[2:4])[0]
    if hlen < 4 or hlen > len(p):
        return None
    meta, fcs, at = {}, 0, 4
    while at + 4 <= hlen:
        t, n = struct.unpack("<HH", p[at:at + 4])
        v = p[at + 4:at + 4 + n]
        if t == 0 and n >= 1:
            fcs = v[0]
        elif t == 1 and n == 4:
            meta["rssi"] = round(struct.unpack("<f", v)[0], 1)
        elif t == 3 and n >= 2:
            meta["channel"] = struct.unpack("<H", v[:2])[0]
        elif t == 10 and n >= 1:
            meta["lqi"] = v[0]
        at += 4 + n + (-n % 4)
    frame = p[hlen:]
    frame = frame[:-2] if fcs == 1 else frame[:-4] if fcs == 2 else frame
    return frame, meta


def _from_loratap(p):
    if len(p) < 15 or p[0] != 0:
        return None
    hlen = struct.unpack(">H", p[2:4])[0]
    if hlen < 15 or hlen > len(p):
        return None
    freq, bw, sf, rssi, _, _, snr, sync = struct.unpack(">IBBBBBbB", p[4:15])
    payload = p[hlen:]
    if not 1 <= len(payload) <= 255:
        return None
    bw = {1: 125, 2: 250, 3: 500}.get(bw, 125)
    return (f"RX,0,{freq / 1e6:g},{bw},{sf},0x{sync:02x},{rssi - 139},{snr / 4:g},0,{len(payload)},{payload.hex()}").encode()


def to_record(lt, ts, p, name=None):
    """(record or None, reason it was left out). The record is what capture.read yields, raw as bytes; its interface is the one
    the file names (so a file this module wrote comes back as it was), else pcap:<radio>."""
    from .capture import trim_wifi
    rec = {"ts": round(ts, 6) if 0 < ts < 4e9 else 0}
    rec, why = _record(lt, p, rec, trim_wifi)
    if rec and name:
        rec["src"] = name
    return rec, why


def _record(lt, p, rec, trim_wifi):
    if lt == LT_RADIOTAP:
        if len(p) < 8 or p[0] != 0:
            return None, "not a radiotap frame"
        rec.update(radio="wifi", src="pcap:wifi", raw=trim_wifi(p))
    elif lt == LT_80211:
        rec.update(radio="wifi", src="pcap:wifi", raw=trim_wifi(b"\0\0\x08\0\0\0\0\0" + p))
    elif lt in (LT_H4, LT_H4_PHDR):
        h4 = p[4:] if lt == LT_H4_PHDR else p
        if not h4 or h4[0] != 0x04:
            return None, "Bluetooth: not an HCI event"
        rec.update(radio="bt", src="pcap:bt", raw=h4)
    elif lt in (LT_154_FCS, LT_154_NOFCS):
        rec.update(radio="zigbee", src="pcap:zigbee", raw=p[:-2] if lt == LT_154_FCS else p)
    elif lt == LT_154_TAP:
        got = _from_tap154(p)
        if not got:
            return None, "not an 802.15.4 TAP frame"
        rec.update(radio="zigbee", src="pcap:zigbee", raw=got[0], **got[1])
    elif lt == LT_LORATAP:
        line = _from_loratap(p)
        if not line:
            return None, "not a LoRaTap frame"
        rec.update(radio="lora", src="pcap:lora", raw=line)
    else:
        return None, f"link type {LINKTYPE_NAMES.get(lt, lt)}"
    return rec, None
