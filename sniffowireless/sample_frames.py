"""Frames built by hand from the published layouts, for the demo's sample recording and the frame inspector's tests.

Each builder returns the bytes a radio would deliver: Wi-Fi with a radiotap header, Bluetooth as an HCI event (with the H4 type
byte), Zigbee as an 802.15.4 frame without its checksum, LoRa as the line the sniffer board prints. The addresses are made up.
"""
import gzip
import json
import os
import random
import struct
import time

BSSID, CLIENT, PHONE = bytes.fromhex("02a0c5112233"), bytes.fromhex("da12f3a4b5c6"), bytes.fromhex("3c2ef9010203")
BCAST = b"\xff" * 6


def radiotap(freq=2437, rssi=-52, rate=12, fcs=False):
    """Present: flags, rate, channel, antenna signal (8-byte header, fields aligned)."""
    flags = 0x10 if fcs else 0x00
    return struct.pack("<BBHI", 0, 0, 15, 0x0000002E) + struct.pack("<BBHHb", flags, rate, freq, 0x00A0 if freq < 3000 else 0x0140, rssi)


def ie(eid, data):
    return bytes([eid, len(data)]) + data


def rsn(akms=(2, 8)):
    return ie(48, struct.pack("<H", 1) + b"\x00\x0f\xac\x04" + struct.pack("<H", 1) + b"\x00\x0f\xac\x04"
              + struct.pack("<H", len(akms)) + b"".join(b"\x00\x0f\xac" + bytes([a]) for a in akms) + struct.pack("<H", 0x0080))


def wps(name="Living Room AP", maker="ExampleNet", model="EX-3000"):
    def attr(t, v):
        return struct.pack(">HH", t, len(v)) + v
    body = attr(0x104A, b"\x10") + attr(0x1044, b"\x02") + attr(0x1021, maker.encode()) + attr(0x1023, model.encode()) \
        + attr(0x1024, b"3000") + attr(0x1011, name.encode())
    return ie(221, b"\x00\x50\xf2\x04" + body)


def ht_caps():
    return ie(45, struct.pack("<HB", 0x01EE, 0x17) + bytes([0xFF, 0xFF, 0, 0]) + bytes(12) + struct.pack("<HIB", 0, 0, 0))


def beacon(ssid=b"HomeNet", seq=100, channel=6, subtype=8, dst=BCAST, freq=2437, rssi=-48):
    fc = bytes([subtype << 4, 0x00])
    hdr = fc + b"\x00\x00" + dst + BSSID + BSSID + struct.pack("<H", seq << 4)
    fixed = struct.pack("<QHH", 123456789, 100, 0x0411)
    tags = ie(0, ssid) + ie(1, bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24])) + ie(3, bytes([channel])) \
        + ie(5, bytes([0, 1, 0, 0])) + ie(7, b"NL\x20" + bytes([1, 13, 20])) + ie(11, struct.pack("<HBH", 4, 51, 0)) + rsn() + ht_caps() \
        + ie(61, bytes([channel, 0x00]) + bytes(20)) + ie(127, bytes([0, 0, 8, 0, 0, 0, 0, 0x40])) \
        + ie(221, b"\x00\x50\xf2\x02\x01\x01\x80\x00") + wps() + ie(255, bytes([36, 0, 0, 0, 0x05, 0, 0]))
    return radiotap(freq, rssi) + hdr + fixed + tags


def probe_request(ssid=b"", seq=7):
    hdr = b"\x40\x00\x00\x00" + BCAST + CLIENT + BCAST + struct.pack("<H", seq << 4)
    return radiotap(2412, -67, 2) + hdr + ie(0, ssid) + ie(1, bytes([0x02, 0x04, 0x0B, 0x16])) + ie(50, bytes([0x0C, 0x12, 0x18, 0x24])) + ht_caps()


def deauth(reason=7, seq=900):
    return radiotap(2437, -55, 2, fcs=False) + b"\xc0\x00\x3a\x01" + CLIENT + BSSID + BSSID + struct.pack("<HH", seq << 4, reason)


def auth(seq=5):
    return radiotap(2437, -61) + b"\xb0\x00\x3a\x01" + BSSID + CLIENT + BSSID + struct.pack("<HHHH", seq << 4, 3, 1, 0)


def qos_data(seq=2001):
    """Header only, as recordings keep it: QoS data from a client to the AP, protected."""
    return radiotap(2437, -58, 108) + b"\x88\x41\x30\x00" + BSSID + CLIENT + BSSID + struct.pack("<HH", seq << 4, 0x0000)


def ack():
    return radiotap(2437, -50, 12) + b"\xd4\x00\x00\x00" + CLIENT


def rts():
    return radiotap(2437, -57, 12) + b"\xb4\x00\x40\x01" + BSSID + CLIENT


def with_fcs(frame):
    """A radiotap frame with the FCS flag set and the right checksum after the 802.11 frame."""
    import zlib
    rt_len = int.from_bytes(frame[2:4], "little")
    frame = frame[:8] + bytes([frame[8] | 0x10]) + frame[9:]
    return frame + struct.pack("<I", zlib.crc32(frame[rt_len:]) & 0xFFFFFFFF)


def ad(t, data):
    return bytes([len(data) + 1, t]) + data


def le_adv(addr=PHONE, name=b"Pixel 8", rssi=-71, random_addr=True, evt=0):
    data = ad(0x01, b"\x06") + ad(0x09, name) + ad(0x03, struct.pack("<HH", 0xFE2C, 0x180F)) + ad(0x0A, b"\xf4")
    rep = bytes([evt, 1 if random_addr else 0]) + addr[::-1] + bytes([len(data)]) + data + struct.pack("b", rssi)
    p = bytes([0x02, 1]) + rep
    return bytes([0x04, 0x3E, len(p)]) + p


def le_findmy(rssi=-80):
    addr = bytes.fromhex("c4f1a2b3c4d5")
    data = ad(0x01, b"\x06") + ad(0xFF, b"\x4c\x00\x12\x19\x10" + bytes(range(24)))
    rep = bytes([3, 1]) + addr[::-1] + bytes([len(data)]) + data + struct.pack("b", rssi)
    p = bytes([0x02, 1]) + rep
    return bytes([0x04, 0x3E, len(p)]) + p


def ibeacon(rssi=-66):
    addr = bytes.fromhex("e2c56db5dffb")
    data = ad(0x01, b"\x04") + ad(0xFF, b"\x4c\x00\x02\x15" + bytes.fromhex("e2c56db5dffb48d2b060d0f5a71096e0") + struct.pack(">HHb", 1, 42, -59))
    rep = bytes([3, 0]) + addr[::-1] + bytes([len(data)]) + data + struct.pack("b", rssi)
    p = bytes([0x02, 1]) + rep
    return bytes([0x04, 0x3E, len(p)]) + p


def le_ext_adv(rssi=-63):
    addr = bytes.fromhex("f0f1f2f3f4f5")
    data = ad(0x01, b"\x06") + ad(0x16, struct.pack("<H", 0x1852) + bytes(6)) + ad(0x30, b"Kitchen speaker")
    rep = struct.pack("<HB", 0x0000, 1) + addr[::-1] + bytes([1, 2, 3]) + struct.pack("bb", 127, rssi) + struct.pack("<HB", 0, 0) + bytes(6) \
        + bytes([len(data)]) + data
    p = bytes([0x0D, 1]) + rep
    return bytes([0x04, 0x3E, len(p)]) + p


def inquiry_eir(rssi=-74):
    addr = bytes.fromhex("001a7dda7113")
    eir = ad(0x09, b"Car Audio") + ad(0x03, struct.pack("<HH", 0x110B, 0x111E))
    eir += bytes(240 - len(eir))
    p = bytes([1]) + addr[::-1] + bytes([1, 0]) + (0x240404).to_bytes(3, "little") + struct.pack("<Hb", 0x1234, rssi) + eir
    return bytes([0x04, 0x2F, len(p)]) + p


def command_complete():
    p = bytes([1]) + struct.pack("<H", 0x200C) + b"\x00"
    return bytes([0x04, 0x0E, len(p)]) + p


def zb_beacon(pan=0x1A2B, src=0x0000, epid=bytes.fromhex("dddddddddddddddd")):
    fc = 0x8000  # beacon, short source, no destination
    return struct.pack("<HBHH", fc, 77, pan, src) + struct.pack("<HBB", 0xCFFF, 0, 0) + bytes([0]) + struct.pack("<H", 0x8422) + epid \
        + b"\xff\xff\xff\x00"


def thread_beacon(pan=0xFACE):
    fc = 0xC000  # beacon, long source
    return struct.pack("<HBH", fc, 3, pan) + bytes.fromhex("1122334455667788") + struct.pack("<HBB", 0xCFFF, 0, 0) \
        + bytes([3, 0x21]) + b"OpenThreadDemo".ljust(16, b"\x00") + bytes.fromhex("dead00beef00cafe")


def beacon_request(seq=12):
    return struct.pack("<HBHHB", 0x0803, seq, 0xFFFF, 0xFFFF, 0x07)


def zb_data(seq=40, src=0x4F21, dst=0x0000, pan=0x1A2B):
    mac = struct.pack("<HBHHH", 0x8861, seq, pan, dst, src)
    nwk = struct.pack("<HHHBB", 0x0208, dst, src, 30, 9)
    sec = bytes([0x28]) + struct.pack("<I", 4242) + bytes.fromhex("00124b0001020304")[::-1] + bytes([0])
    return mac + nwk + sec + bytes(range(12)) + b"\xaa\xbb\xcc\xdd"


def zb_ack(seq=40):
    return struct.pack("<HB", 0x0002, seq)


def data_request(seq=41, src=0x4F21, pan=0x1A2B):
    return struct.pack("<HBHHHB", 0x8863, seq, pan, 0x0000, src, 0x04)


def thread_data(seq=8):
    return struct.pack("<HBH", 0xCC41, seq, 0xFACE) + bytes.fromhex("aabbccddeeff0011")[::-1] + bytes.fromhex("1122334455667788")[::-1] \
        + bytes([0x7E, 0x33, 0xF0]) + bytes(20)


def lora_line(payload, freq=869.525, sf=11, bw=250, sync=0x2B, rssi=-104, snr=-3.5):
    return f"RX,123456,{freq},{bw},{sf},0x{sync:02x},{rssi},{snr},-1200,{len(payload)},{payload.hex()}".encode()


def meshtastic_packet(frm=0xDEADBEEF, to=0xFFFFFFFF):
    return struct.pack("<IIIBBBB", to, frm, 0x1234ABCD, 0x63, 0x08, 0, 0x5A) + bytes(range(20))


def lorawan_uplink():
    return bytes([0x40]) + bytes.fromhex("260b1a2c")[::-1] + bytes([0x80]) + struct.pack("<H", 513) + bytes([1]) + bytes(range(10)) + bytes(4)


def samples():
    """(radio, src, raw, meta) of one of each kind of frame."""
    return [("wifi", "wifi:wlan0mon", beacon(), {"tuned": 2437}), ("wifi", "wifi:wlan0mon", probe_request(), {"tuned": 2412}),
            ("wifi", "wifi:wlan0mon", beacon(subtype=5, dst=CLIENT, seq=101), {"tuned": 2437}), ("wifi", "wifi:wlan0mon", auth(), {"tuned": 2437}),
            ("wifi", "wifi:wlan0mon", qos_data(), {"tuned": 2437}), ("wifi", "wifi:wlan0mon", ack(), {"tuned": 2437}),
            ("wifi", "wifi:wlan0mon", rts(), {"tuned": 2437}), ("wifi", "wifi:wlan0mon", with_fcs(deauth()), {"tuned": 2437}),
            ("bt", "bt:hci0", le_adv(), {}), ("bt", "bt:hci0", le_findmy(), {}), ("bt", "bt:hci0", ibeacon(), {}),
            ("bt", "bt:hci0", le_ext_adv(), {}), ("bt", "bt:hci0", inquiry_eir(), {}), ("bt", "bt:hci0", command_complete(), {}),
            ("zigbee", "zigbee:ttyUSB0", zb_beacon(), {"channel": 15, "rssi": -61, "lqi": 220}),
            ("zigbee", "zigbee:ttyUSB0", thread_beacon(), {"channel": 25, "rssi": -70, "lqi": 180}),
            ("zigbee", "zigbee:ttyUSB0", beacon_request(), {"channel": 15, "rssi": -55, "lqi": 240}),
            ("zigbee", "zigbee:ttyUSB0", zb_data(), {"channel": 15, "rssi": -64, "lqi": 200}),
            ("zigbee", "zigbee:ttyUSB0", zb_ack(), {"channel": 15, "rssi": -64, "lqi": 200}),
            ("zigbee", "zigbee:ttyUSB0", data_request(), {"channel": 15, "rssi": -72, "lqi": 160}),
            ("zigbee", "zigbee:ttyUSB0", thread_data(), {"channel": 25, "rssi": -69, "lqi": 190}),
            ("lora", "lora:ttyACM0", lora_line(meshtastic_packet()), {}),
            ("lora", "lora:ttyACM0", lora_line(lorawan_uplink(), freq=868.1, sf=7, bw=125, sync=0x34, rssi=-112, snr=-6), {})]


def write_recording(path, count=600, start=None, seed=7):
    """A recording file in capture.py's format, with `count` frames spread over a minute, for the demo."""
    rnd = random.Random(seed)
    kinds = samples()
    weights = [30, 6, 3, 1, 12, 10, 3, 1, 14, 6, 3, 3, 1, 1, 4, 2, 1, 6, 6, 3, 2, 3, 1]
    t = start if start is not None else time.time() - 120
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with gzip.open(path, "wt", encoding="ascii") as f:
        for i in range(count):
            radio, src, raw, meta = rnd.choices(kinds, weights)[0]
            if radio == "wifi" and raw[int.from_bytes(raw[2:4], "little")] == 0x80:  # beacons count up their sequence numbers
                raw = beacon(seq=(100 + i) % 4096, rssi=-45 - rnd.randint(0, 8))
            t += rnd.expovariate(10)
            f.write(json.dumps({"ts": round(t, 6), "radio": radio, "src": src, "raw": raw.hex(), **meta}, separators=(",", ":")) + "\n")
    return path
