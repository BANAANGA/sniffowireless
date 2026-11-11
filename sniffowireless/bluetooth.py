"""Bluetooth Classic + BLE scanning over a raw HCI socket (no BlueZ daemon required).

The sensor opens a raw HCI socket on the adapter, enables LE scanning and
periodic classic inquiry, and parses the controller's events. Because a raw
socket sees *all* events, advertisements caught by a host bluetoothd scan and
connections made by the host are recorded as well.
"""
import errno
import fcntl
import logging
import re
import select
import socket
import struct
import threading
import time

from . import status
from .identify import ble_fingerprint
from .oui import bt_company, bt_company_known

log = logging.getLogger("sniffowireless.bt")

SOL_HCI = 0
HCI_FILTER = 2
HCIDEVUP = 0x400448C9
ERFKILL = 132

OGF_LINK, OGF_HOST, OGF_INFO, OGF_LE = 0x01, 0x03, 0x04, 0x08

# HCI/LMP version numbers the controller reports (Assigned Numbers, Link Manager Protocol version).
BT_VERSIONS = {6: "4.0", 7: "4.1", 8: "4.2", 9: "5.0", 10: "5.1", 11: "5.2", 12: "5.3", 13: "5.4", 14: "6.0"}
# LE features of the controller (LE Read Local Supported Features, bit number -> short label). Only bits the Core
# specification and controller vendors agree on are listed; Channel Sounding (Core 6.0) is bit 46.
LE_FEATURES = {8: "2M PHY", 11: "Coded PHY", 12: "Ext. adv", 13: "Periodic adv", 14: "CSA #2",
               28: "LE Audio (CIS)", 30: "LE Audio (BIS)", 46: "Channel Sounding"}
PHY_NAMES = {1: "1M", 2: "2M", 3: "Coded"}
# Service UUIDs of LE Audio broadcasts (Auracast): Public Broadcast Announcement and Broadcast Audio Announcement.
UUID_PBA, UUID_BAA = 0x1856, 0x1852
UUID_MATTER = 0xFFF6   # Matter commissioning service (Connectivity Standards Alliance)

# Reading a device's version by connecting to it (btprobe.py, on request only): limits per adapter, and the addresses being asked
# right now, so the passive scan does not record those connections as the sensor's own Bluetooth links.
PROBING = set()
PROBE_GAP, PROBE_PER_HOUR = 15.0, 30
MAC_RX = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
SENSORS = {}    # status name (bt:hci0) -> the BluetoothSensor of this machine


def bt_version_label(v):
    """'5.4', '6.0', ... for an HCI/LMP version number; versions newer than this list say so instead of guessing."""
    if v in BT_VERSIONS:
        return BT_VERSIONS[v]
    return f">6.0 (0x{v:02x})" if isinstance(v, int) and v > 14 else f"? (0x{v:02x})" if isinstance(v, int) else None


def parse_local_version(ret):
    """Return parameters of Read Local Version Information (after the status byte): HCI version, revision, LMP version,
    manufacturer, subversion. Returns a dict, or None when the answer is too short."""
    if len(ret) < 8:
        return None
    return {"hci_version": ret[0], "lmp_version": ret[3], "company": ret[4] | ret[5] << 8,
            "version": bt_version_label(ret[0]), "chip": bt_company(ret[4] | ret[5] << 8)}


def parse_le_features(ret):
    """The 8 feature bytes of LE Read Local Supported Features -> set of the short labels in LE_FEATURES that are set."""
    if len(ret) < 8:
        return None
    bits = int.from_bytes(ret[:8], "little")
    return [label for bit, label in LE_FEATURES.items() if bits >> bit & 1]

COD_MAJOR = {1: "computer", 2: "phone", 3: "network", 4: "audio/video", 5: "peripheral",
             6: "imaging", 7: "wearable", 8: "toy", 9: "health"}
APPEARANCE = {1: "phone", 2: "computer", 3: "watch", 4: "clock", 5: "display", 6: "remote",
              7: "eyeglasses", 8: "tag", 9: "keyring", 10: "media player", 11: "barcode scanner",
              12: "thermometer", 13: "heart rate", 14: "blood pressure", 15: "HID", 16: "glucose",
              17: "running sensor", 18: "cycling sensor", 21: "light", 41: "audio sink",
              42: "audio source", 49: "sensor"}


def opcode(ogf, ocf):
    return (ogf << 10) | ocf


def bdaddr(b):
    return ":".join(f"{x:02x}" for x in reversed(b))


def _rssi(b):
    v = b - 256 if b > 127 else b
    return None if v == 127 or v >= 20 else v


def parse_ad(data):
    """Parse BLE advertising / classic EIR data into a dict of interesting fields."""
    out, uuids = {}, []
    i = 0
    while i < len(data):
        ln = data[i]
        if ln == 0 or i + 1 + ln > len(data):
            break
        t, v = data[i + 1], data[i + 2:i + 1 + ln]
        if t in (0x08, 0x09) and v:
            name = v.decode("utf-8", "replace").strip("\x00").strip()
            if name and (t == 0x09 or "name" not in out):
                out["name"] = name
        elif t == 0x0A and v:
            out["tx_power"] = v[0] - 256 if v[0] > 127 else v[0]
        elif t == 0x19 and len(v) >= 2:
            a = v[0] | v[1] << 8
            out["appearance"] = APPEARANCE.get(a >> 6, f"0x{a:04x}")
        elif t == 0xFF and len(v) >= 2:
            out["company_id"] = v[0] | v[1] << 8
            out["mfg"] = bytes(v[2:34])
        elif t == 0x01 and v:  # Flags: bit0 limited / bit1 general discoverable, bit2 "BR/EDR not supported"
            out["flags"] = v[0]
        elif t in (0x02, 0x03):
            uuids += [f"{v[j] | v[j + 1] << 8:04x}" for j in range(0, len(v) - 1, 2)]
        elif t in (0x04, 0x05):  # 32-bit UUIDs
            uuids += [uuid_label(bytes(v[j:j + 4][::-1])) for j in range(0, len(v) - 3, 4)]
        elif t in (0x06, 0x07):  # 128-bit UUIDs (most vendor-specific services)
            uuids += [uuid_label(bytes(v[j:j + 16][::-1])) for j in range(0, len(v) - 15, 16)]
        elif t == 0x12 and len(v) >= 4:  # Peripheral connection interval range, units of 1.25 ms (0xFFFF: no preference)
            lo, hi = v[0] | v[1] << 8, v[2] | v[3] << 8
            if 6 <= lo <= hi <= 3200:
                out["conn_interval"] = [round(lo * 1.25, 2), round(hi * 1.25, 2)]
        elif t == 0x16 and len(v) >= 2:
            u = v[0] | v[1] << 8
            uuids.append(f"{u:04x}")
            if u == UUID_PBA and len(v) >= 3:  # Public Broadcast Announcement: bit 0 encrypted, bit 1 standard / bit 2 high quality audio
                out["auracast"] = {"encrypted": bool(v[2] & 1), "quality": "high" if v[2] & 4 else "standard" if v[2] & 2 else None}
            elif u == UUID_MATTER and len(v) >= 9 and v[2] == 0:   # Matter commissionable device: opcode 0, discriminator + version, vendor ID, product ID
                out["matter"] = {"discriminator": (v[3] | v[4] << 8) & 0x0FFF, "vendor": v[5] | v[6] << 8, "product": v[7] | v[8] << 8}
            elif u == UUID_BAA and len(v) >= 5:  # Broadcast Audio Announcement: the 3-byte Broadcast_ID
                out["broadcast_id"] = bytes(v[2:5][::-1]).hex()
        elif t == 0x30 and v:  # Broadcast_Name (LE Audio / Auracast)
            name = v.decode("utf-8", "replace").strip("\x00").strip()
            if name:
                out["broadcast_name"] = name[:64]
        elif t == 0x31:  # Encrypted Advertising Data (Bluetooth 5.4)
            out["encrypted_ad"] = True
        elif t == 0x34:  # Electronic Shelf Label (Bluetooth 5.4)
            out["esl"] = True
        i += 1 + ln
    if uuids:
        out["uuids"] = sorted(set(uuids), key=lambda u: (len(u), u))[:16]  # standard short ones first
    beacon = ibeacon(out.get("mfg"), out.get("company_id"))
    if beacon:
        out["ibeacon"] = beacon
    return out


BASE_UUID_TAIL = bytes.fromhex("00001000800000805f9b34fb")  # the Bluetooth base UUID after its first 4 bytes


def raw_mfg(cid, mfg):
    """The manufacturer-specific data as hex, company-ID field first (the way it went over the air), for the device page.
    Apple's changes constantly and is decoded separately, so it is not kept."""
    if cid is None or cid == 0x004C:
        return None
    return (bytes([cid & 0xFF, cid >> 8]) + bytes(mfg or b"")).hex()


def uuid_label(b):
    """A UUID given most-significant byte first: 16-bit ones as '180f', other 32-bit ones as 8 hex digits, everything
    else as the dashed 128-bit form. A 128-bit UUID on the Bluetooth base is shortened to its 16/32-bit form."""
    if len(b) == 4:
        return b.hex()[4:] if b[:2] == b"\x00\x00" else b.hex()
    if len(b) == 16 and b[4:] == BASE_UUID_TAIL:
        return uuid_label(b[:4])
    h = b.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def ibeacon(mfg, cid):
    """Apple iBeacon: manufacturer data 02 15 <16-byte UUID> <major BE> <minor BE> <measured power at 1 m>."""
    if cid != 0x004C or not mfg or len(mfg) < 23 or mfg[0] != 0x02 or mfg[1] != 0x15:
        return None
    mp = mfg[22]
    return {"uuid": uuid_label(bytes(mfg[2:18])), "major": mfg[18] << 8 | mfg[19], "minor": mfg[20] << 8 | mfg[21],
            "power": mp - 256 if mp > 127 else mp}


class AdvInterval:
    """Estimate how often a device advertises from the gaps between its packets (scan responses left out).
    The scanner hears one of three channels at a time, so the estimate is the typical gap among the shortest
    plausible ones; it is only reported after enough samples and is rounded."""
    MIN_GAP, MAX_GAP, NEED, KEEP = 0.020, 5.0, 8, 24

    def __init__(self, limit=20000):
        self.limit, self.d = limit, {}

    def update(self, mac, now):
        last, gaps = self.d.get(mac, (None, []))
        if last is not None and self.MIN_GAP <= now - last <= self.MAX_GAP:
            gaps = (gaps + [now - last])[-self.KEEP:]
        if len(self.d) >= self.limit and mac not in self.d:
            self.d.clear()
        self.d[mac] = (now, gaps)
        if len(gaps) < self.NEED:
            return None
        lo = min(gaps)
        near = sorted(g for g in gaps if g <= lo * 1.3)
        est = near[len(near) // 2] * 1000
        return int(round(est / 10.0) * 10) if est < 1000 else int(round(est / 50.0) * 50)


def classify_le_addr(addr_type, mac):
    """Return (label, randomized) for an LE address."""
    if addr_type in (0, 2):
        return "public", False
    top = int(mac[0:2], 16) >> 6
    if top == 0b11:
        return "random-static", False
    if top == 0b01:
        return "random-resolvable", True
    return "random-nonresolvable", True


def parse_event(pkt):
    """Parse one HCI event packet (including the leading 0x04) into a list of dicts."""
    if len(pkt) < 3 or pkt[0] != 0x04:
        return []
    code, p = pkt[1], pkt[3:3 + pkt[2]]
    out = []
    if code == 0x3E and p:
        sub = p[0]
        if sub in (0x02, 0x0D) and len(p) < 2:  # a report event without its count: nothing to read
            return out
        if sub == 0x02:  # LE advertising report
            n, i = p[1], 2
            for _ in range(n):
                if i + 9 > len(p):
                    break
                evt_type, atype, addr, ln = p[i], p[i + 1], p[i + 2:i + 8], p[i + 8]
                data = p[i + 9:i + 9 + ln]
                r = _rssi(p[i + 9 + ln]) if i + 9 + ln < len(p) else None
                i += 10 + ln
                out.append({"ev": "adv", "mac": bdaddr(addr), "addr_type": atype, "rssi": r,
                            "connectable": evt_type in (0, 1), "ad": parse_ad(data), "srsp": evt_type == 4})
        elif sub == 0x0D:  # LE extended advertising report
            n, i = p[1], 2
            for _ in range(n):
                if i + 24 > len(p):
                    break
                evt_type = p[i] | p[i + 1] << 8
                atype, addr = p[i + 2], p[i + 3:i + 9]
                r = _rssi(p[i + 13])
                ln = p[i + 23]
                data = p[i + 24:i + 24 + ln]
                phy = PHY_NAMES.get(p[i + 10] or p[i + 9])  # secondary PHY when there is one, else the primary
                i += 24 + ln
                out.append({"ev": "adv", "mac": bdaddr(addr), "addr_type": atype, "rssi": r,
                            "connectable": bool(evt_type & 0x01), "ad": parse_ad(data),
                            "ext": not evt_type & 0x10, "phy": phy, "srsp": bool(evt_type & 0x08)})  # evt_type bit 4 set = legacy PDU
        elif sub in (0x01, 0x0A, 0x29) and len(p) >= 12 and p[1] == 0:  # LE (enhanced, v2) connection complete
            handle = p[2] | (p[3] & 0x0F) << 8
            out.append({"ev": "conn", "handle": handle, "mac": bdaddr(p[6:12]), "le": True,
                        "addr_type": p[5]})
    elif code == 0x02 and p:  # inquiry result
        n = p[0]
        for k in range(n):
            o = 1 + k * 14
            if o + 14 > len(p):
                break
            cod = int.from_bytes(p[o + 9:o + 12], "little")
            out.append({"ev": "inq", "mac": bdaddr(p[o:o + 6]), "rssi": None, "cod": cod,
                        "psrm": p[o + 6], "clock": p[o + 12] | p[o + 13] << 8, "ad": {}})
    elif code == 0x22 and p:  # inquiry result with RSSI
        n = p[0]
        for k in range(n):
            o = 1 + k * 14
            if o + 14 > len(p):
                break
            cod = int.from_bytes(p[o + 8:o + 11], "little")
            out.append({"ev": "inq", "mac": bdaddr(p[o:o + 6]), "rssi": _rssi(p[o + 13]), "cod": cod,
                        "psrm": p[o + 6], "clock": p[o + 11] | p[o + 12] << 8, "ad": {}})
    elif code == 0x2F and len(p) >= 15:  # extended inquiry result
        cod = int.from_bytes(p[9:12], "little")
        out.append({"ev": "inq", "mac": bdaddr(p[1:7]), "rssi": _rssi(p[14]), "cod": cod,
                    "psrm": p[7], "clock": p[12] | p[13] << 8, "ad": parse_ad(p[15:])})
    elif code == 0x07 and len(p) >= 7:  # remote name request complete
        if p[0] == 0:
            name = p[7:].split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
            out.append({"ev": "name", "mac": bdaddr(p[1:7]), "name": name})
        else:
            out.append({"ev": "name_fail", "mac": bdaddr(p[1:7])})
    elif code == 0x03 and len(p) >= 11 and p[0] == 0:  # classic connection complete
        out.append({"ev": "conn", "handle": p[1] | (p[2] & 0x0F) << 8, "mac": bdaddr(p[3:9]), "le": False})
    elif code == 0x05 and len(p) >= 4 and p[0] == 0:  # disconnection complete
        out.append({"ev": "disc", "handle": p[1] | (p[2] & 0x0F) << 8, "reason": p[3]})
    elif code == 0x01:
        out.append({"ev": "inq_done"})
    elif code == 0x0C and len(p) >= 8 and p[0] == 0:  # read remote version information complete (the host's stack asks every peer)
        out.append({"ev": "peerver", "handle": p[1] | (p[2] & 0x0F) << 8, "version": p[3], "company": p[4] | p[5] << 8})
    elif code == 0x0E and len(p) >= 4:  # command complete
        out.append({"ev": "cmd", "opcode": p[1] | p[2] << 8, "status": p[3], "ret": bytes(p[4:])})
    elif code == 0x0F and len(p) >= 4:  # command status
        out.append({"ev": "cmd", "opcode": p[2] | p[3] << 8, "status": p[0]})
    return out


class BluetoothSensor:
    def __init__(self, dev, cfg, store):
        self.dev, self.cfg, self.store = dev, cfg, store
        self.dev_id = int(dev.replace("hci", "")) if dev.startswith("hci") else int(dev)
        self.name = f"bt:{dev}"
        self.sock = None
        self.handles = {}       # connection handle -> (mac, le)
        self.classic = {}       # mac -> (psrm, clock) for name resolution
        self.named = set()
        self.name_pending = None
        self.inquiring = False
        self.last_adv = 0.0
        self.last_scan_setup = 0.0
        self.ext_scan = False   # use LE extended scan commands (Bluetooth 5 controllers)
        self.coded = False      # also scan on the LE Coded PHY (long range), when the controller has it
        self.mode_switches = 0  # legacy <-> extended scan changes after a refusal, bounded so two refusals cannot ping-pong
        self.caps = []          # LE features of the controller (LE_FEATURES labels)
        self.version = None     # {"version": "6.0", "chip": "Intel", ...} from Read Local Version Information
        self.fp_seen = {}       # mac -> (fingerprint, ts) to avoid re-sending identical fingerprints
        self.intervals = AdvInterval()
        self.interval_sent = {}  # mac -> last estimate sent, to resend only on a real change
        self.probe_lock = threading.Lock()
        self.probe_busy, self.probe_times = False, []
        self.packets = 0
        self.stop = None
        status.register(self.name, type="bluetooth", iface=dev, adverts=0, inquiries=0)
        SENSORS[self.name] = self

    def start(self, stop):
        self.stop = stop
        threading.Thread(target=self._loop, daemon=True, name=self.name).start()

    # ------------------------------------------------------------------ HCI
    def _open(self):
        s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
        try:
            fcntl.ioctl(s.fileno(), HCIDEVUP, self.dev_id)
        except OSError as e:
            if e.errno == ERFKILL:
                s.close()
                raise RuntimeError(f"{self.dev} is blocked by rfkill (run: rfkill unblock bluetooth)")
            if e.errno == errno.ENODEV:
                s.close()
                raise RuntimeError(f"{self.dev} not found (is the dongle plugged in?)")
            if e.errno not in (errno.EALREADY, errno.EBUSY):
                log.debug("HCIDEVUP: %s", e)
        s.bind((self.dev_id,))
        # struct hci_ufilter is 16 bytes incl. padding; recent kernels reject the unpadded 14 with EINVAL.
        s.setsockopt(SOL_HCI, HCI_FILTER, struct.pack("<IIIH2x", 1 << 0x04, 0xFFFFFFFF, 0xFFFFFFFF, 0))
        return s

    def _cmd(self, ogf, ocf, params=b""):
        self.sock.send(bytes([0x01]) + struct.pack("<HB", opcode(ogf, ocf), len(params)) + params)

    def _cmd_sync(self, ogf, ocf, timeout=1.5):
        """Send a command with no parameters and wait for its Command Complete: the bytes after the status, or None."""
        op = opcode(ogf, ocf)
        self._cmd(ogf, ocf)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            r, _, _ = select.select([self.sock], [], [], max(0.0, end - time.monotonic()))
            if not r:
                break
            for ev in parse_event(self.sock.recv(4096)):
                if ev["ev"] == "cmd" and ev["opcode"] == op:
                    return ev["ret"] if ev["status"] == 0 else None
        return None

    def _probe(self):
        """What the controller is (Bluetooth version, chip, LE features) decides how to scan: extended scanning (Bluetooth 5 and
        6 advertisements, LE Audio broadcasts) and the Coded PHY are used when it has them."""
        try:
            self.version = parse_local_version(self._cmd_sync(OGF_INFO, 0x0001) or b"")
            feats = parse_le_features(self._cmd_sync(OGF_LE, 0x0003) or b"")
        except OSError as e:
            log.debug("%s: could not read the controller's capabilities: %s", self.name, e)
            return
        if feats is None:
            return
        self.caps = feats
        if self.cfg.bt_extended_scan and "Ext. adv" in feats:
            self.ext_scan = True
        self.coded = self.ext_scan and "Coded PHY" in feats
        v = self.version or {}
        warning = None
        if "Ext. adv" not in feats:
            warning = (f"This adapter (Bluetooth {v.get('version') or '4.x'}) has no extended advertising: Bluetooth 5 and 6 "
                       "advertisements, such as LE Audio broadcasts, cannot be seen. A Bluetooth 5.x/6.0 dongle can.")
        status.update(self.name, bt_version=v.get("version"), chip=v.get("chip"), caps=feats,
                      scan="extended" if self.ext_scan else None, warning=warning)
        log.info("%s: Bluetooth %s (%s), LE features: %s", self.name, v.get("version") or "?", v.get("chip") or "unknown chip",
                 ", ".join(feats) or "none")

    def _configure(self):
        self._probe()
        # Make sure LE meta + inquiry events reach the host (superset of what BlueZ enables).
        self._cmd(OGF_HOST, 0x0001, struct.pack("<Q", 0x3DBFF807FFFBFFFF | 0x20001FFFFFFFFFFF))
        self._cmd(OGF_LE, 0x0001, struct.pack("<Q", 0x00000000000FFFFF))
        self._cmd(OGF_HOST, 0x0045, bytes([2]))  # inquiry mode: extended inquiry result
        self._start_le_scan()

    def _start_le_scan(self):
        active = 1 if self.cfg.bt_active_scan else 0
        if self.ext_scan:
            # Bluetooth 5 extended scanning: once the host has used extended commands, controllers refuse
            # the legacy ones with "Command Disallowed" (0x0c).
            self._cmd(OGF_LE, 0x0042, struct.pack("<BBHH", 0, 0, 0, 0))
            phys = [0x01] + ([0x04] if self.coded else [])  # 1M, and the Coded PHY (long range) when the controller has it
            self._cmd(OGF_LE, 0x0041, struct.pack("<BBB", 0, 0, sum(phys)) + b"".join(
                struct.pack("<BHH", active, 0x0030, 0x0030) for _ in phys))
            self._cmd(OGF_LE, 0x0042, struct.pack("<BBHH", 1, 0, 0, 0))  # enable, no duplicate filtering
        else:
            self._cmd(OGF_LE, 0x000C, bytes([0, 0]))
            self._cmd(OGF_LE, 0x000B, struct.pack("<BHHBB", active, 0x0030, 0x0030, 0, 0))
            self._cmd(OGF_LE, 0x000C, bytes([1, 0]))  # enable, no duplicate filtering
        self.last_scan_setup = time.time()

    def _stop_le_scan(self):
        if self.ext_scan:
            self._cmd(OGF_LE, 0x0042, struct.pack("<BBHH", 0, 0, 0, 0))
        else:
            self._cmd(OGF_LE, 0x000C, bytes([0, 0]))

    def _inquiry(self):
        # General inquiry access code 0x9E8B33, ~10 s, unlimited responses.
        self._cmd(OGF_LINK, 0x0001, bytes([0x33, 0x8B, 0x9E, 8, 0]))
        self.inquiring = True
        status.update(self.name, inquiries=status.SENSORS[self.name].get("inquiries", 0) + 1)

    def _request_name(self):
        for mac, (psrm, clock) in self.classic.items():
            if mac not in self.named:
                self.named.add(mac)
                self.name_pending = (mac, time.time())
                addr = bytes(int(x, 16) for x in reversed(mac.split(":")))
                self._cmd(OGF_LINK, 0x0019, addr + bytes([psrm, 0]) + struct.pack("<H", clock | 0x8000))
                return

    # ----------------------------------------------------------------- reading a version by connecting (on request)
    def request_probe(self, mac, addr_type):
        """Ask the LE device `mac` (addr_type 0 public, 1 random) for its Bluetooth version by connecting to it for a moment. Returns at
        once (ValueError with a sentence when not possible); the answer comes as an observation: extra.bt_probe and, on success,
        extra.bt_version. This transmits, unlike everything else this class does, so it only ever runs on an admin's request."""
        if not self.cfg.bt_active_probe:
            raise ValueError("Reading a version by connecting is switched off on this machine (BT_ACTIVE_PROBE=0)")
        mac = str(mac or "").lower()
        if not MAC_RX.match(mac) or addr_type not in (0, 1):
            raise ValueError("Not a Bluetooth LE address")
        with self.probe_lock:
            now = time.time()
            self.probe_times = [t for t in self.probe_times if now - t < 3600]
            if self.probe_busy:
                raise ValueError(f"{self.name} is busy asking another device")
            if self.probe_times and now - self.probe_times[-1] < PROBE_GAP:
                raise ValueError("Wait a few seconds between requests")
            if len(self.probe_times) >= PROBE_PER_HOUR:
                raise ValueError(f"{self.name} has made {PROBE_PER_HOUR} such requests in the last hour; try again later")
            self.probe_busy = True
            self.probe_times.append(now)
        threading.Thread(target=self._probe_version, args=(mac, addr_type), daemon=True, name=f"{self.name}-version").start()

    def probe_from_server(self, mac, addr_type):
        """request_probe for a request that came from the server: a refusal is reported back as the result, since nobody waits for this call."""
        try:
            self.request_probe(mac, addr_type)
        except ValueError as e:
            mac = str(mac or "").lower()
            if MAC_RX.match(mac):
                self.store.put({"t": "bt", "kind": "ble", "ts": time.time(), "mac": mac, "rssi": None,
                                "extra": {"bt_probe": {"ts": time.time(), "ok": False, "error": str(e)[:200], "adapter": self.name}}})
            else:
                log.warning("%s: ignoring a version request for %r", self.name, mac)

    def _probe_version(self, mac, addr_type):
        from .btprobe import ProbeError, read_version
        result, extra = {"ts": time.time(), "ok": False, "error": None, "adapter": self.name}, {}
        try:
            got = read_version(self.dev, mac, addr_type)
            result["ok"] = True
            extra = {"bt_version": got["version"], "chip": got["company"]}
            log.info("%s: %s reports Bluetooth %s", self.name, mac, got["version"])
        except ProbeError as e:
            result["error"] = str(e)[:200]
            log.info("%s: could not read the version of %s: %s", self.name, mac, e)
        except Exception as e:  # never let a surprise leave the adapter marked busy
            log.exception("%s: version request failed", self.name)
            result["error"] = f"Unexpected error: {e}"[:200]
        finally:
            with self.probe_lock:
                self.probe_busy = False
        self.store.put({"t": "bt", "kind": "ble", "ts": time.time(), "mac": mac, "rssi": None, "extra": {**extra, "bt_probe": result}})

    # ----------------------------------------------------------------- loop
    def _loop(self):
        while not self.stop.is_set():
            try:
                self.sock = self._open()
                self._configure()
                status.update(self.name, state="scanning", error=None)
                self._run()
            except Exception as e:
                log.error("%s: %s", self.name, e)
                status.update(self.name, state="error", error=str(e))
            finally:
                if self.sock:
                    try:
                        self._stop_le_scan()
                    except OSError:
                        pass
                    try:
                        self.sock.close()
                    except OSError:
                        pass
                    self.sock = None
            self.stop.wait(10)

    def _run(self):
        next_inq = time.time() + 5
        last_rate, last_pk = time.time(), 0
        while not self.stop.is_set():
            r, _, _ = select.select([self.sock], [], [], 1.0)
            now = time.time()
            if r:
                pkt = self.sock.recv(4096)
                for ev in parse_event(pkt):
                    self._handle(ev, now)
            if self.cfg.bt_inquiry and not self.inquiring and now >= next_inq:
                self._inquiry()
                next_inq = now + self.cfg.bt_inquiry_interval
            if self.inquiring and now - next_inq + self.cfg.bt_inquiry_interval > 20:
                self.inquiring = False  # inquiry complete event never arrived
            if self.name_pending and now - self.name_pending[1] > 15:
                self.name_pending = None
            if self.cfg.bt_resolve_names and not self.inquiring and not self.name_pending:
                self._request_name()
            if now - self.last_adv > 60 and now - self.last_scan_setup > 60:
                self._start_le_scan()  # someone (bluetoothd) may have disabled our scan
            if now - last_rate >= 5:
                status.update(self.name, packets=self.packets,
                              pps=round((self.packets - last_pk) / (now - last_rate), 1))
                last_rate, last_pk = now, self.packets

    def _handle(self, ev, now):
        kind = ev["ev"]
        if kind == "adv":
            self.packets += 1
            self.last_adv = now
            ad = ev["ad"]
            label, randomized = classify_le_addr(ev["addr_type"], ev["mac"])
            cid = ad.get("company_id")
            fp = ble_fingerprint(ad, ev.get("ext", False))
            prev = self.fp_seen.get(ev["mac"])
            if fp and (not prev or prev[0] != fp or now - prev[1] > 600):
                if len(self.fp_seen) > 50_000:
                    self.fp_seen.clear()
                self.fp_seen[ev["mac"]] = (fp, now)
            else:
                fp = None
            est = None if ev.get("srsp") else self.intervals.update(ev["mac"], now)
            if est is not None:
                sent = self.interval_sent.get(ev["mac"])
                if sent is not None and abs(est - sent) <= max(20, sent * 0.2):
                    est = None
                else:
                    if len(self.interval_sent) > 50_000:
                        self.interval_sent.clear()
                    self.interval_sent[ev["mac"]] = est
            broadcast = {"name": ad.get("broadcast_name"), "id": ad.get("broadcast_id"), **(ad.get("auracast") or {})}
            self.store.put({
                "t": "bt", "kind": "ble", "ts": now, "mac": ev["mac"], "rssi": ev["rssi"],
                "name": ad.get("name") or ad.get("broadcast_name"), "randomized": randomized, "addr_random": label != "public",
                "vendor": bt_company_known(cid) if label != "public" else None,
                "extra": {"addr_type": label, "company": bt_company(cid), "appearance": ad.get("appearance"),
                          "mfg_raw": raw_mfg(cid, ad.get("mfg")),
                          "tx_power": ad.get("tx_power"), "uuids": ad.get("uuids"),
                          "connectable": ev["connectable"], "phy": ev.get("phy") if ev.get("ext") else None,
                          "ext_adv": True if ev.get("ext") else None,
                          "auracast": {k: v for k, v in broadcast.items() if v is not None} or None,
                          "esl": True if ad.get("esl") else None, "encrypted_ad": True if ad.get("encrypted_ad") else None,
                          "matter": ad.get("matter"), "flags": ad.get("flags"), "conn_interval": ad.get("conn_interval"), "ibeacon": ad.get("ibeacon"),
                          "adv_interval": est},
                "fp": {"ble": fp} if fp else None,
            })
            status.update(self.name, adverts=self.packets)
        elif kind == "inq":
            self.packets += 1
            ad = ev["ad"]
            self.classic[ev["mac"]] = (ev["psrm"], ev["clock"])
            if ad.get("name"):
                self.named.add(ev["mac"])
            cod = ev["cod"]
            self.store.put({
                "t": "bt", "kind": "bt_classic", "ts": now, "mac": ev["mac"], "rssi": ev["rssi"],
                "name": ad.get("name"), "randomized": False,
                "extra": {"class": COD_MAJOR.get((cod >> 8) & 0x1F, "uncategorized"),
                          "cod": f"0x{cod:06x}", "tx_power": ad.get("tx_power"), "uuids": ad.get("uuids")},
            })
        elif kind == "inq_done":
            self.inquiring = False
        elif kind == "name":
            self.name_pending = None
            if ev["name"]:
                self.store.put({"t": "bt", "kind": "bt_classic", "ts": now, "mac": ev["mac"],
                                "rssi": None, "name": ev["name"], "randomized": False})
        elif kind == "name_fail":
            self.name_pending = None
        elif kind == "conn":
            if ev["mac"] in PROBING:  # our own, short version request (btprobe.py): not one of the host's links
                return
            self.handles[ev["handle"]] = (ev["mac"], ev["le"])
            randomized = False
            if ev["le"]:
                _, randomized = classify_le_addr(ev.get("addr_type", 0), ev["mac"])
            self.store.put({"t": "bt_conn", "kind": "ble" if ev["le"] else "bt_classic", "ts": now,
                            "mac": ev["mac"], "connected": True, "peer": self.dev,
                            "randomized": randomized, "detail": "LE link" if ev["le"] else "ACL link"})
        elif kind == "disc":
            h = self.handles.pop(ev["handle"], None)
            if h:
                self.store.put({"t": "bt_conn", "kind": "ble" if h[1] else "bt_classic", "ts": now,
                                "mac": h[0], "connected": False, "peer": self.dev,
                                "detail": f"reason 0x{ev['reason']:02x}"})
        elif kind == "peerver":
            h = self.handles.get(ev["handle"])
            if h:
                self.store.put({"t": "bt", "kind": "ble" if h[1] else "bt_classic", "ts": now, "mac": h[0], "rssi": None,
                                "extra": {"bt_version": bt_version_label(ev["version"]), "chip": bt_company(ev["company"])}})
        elif kind == "cmd" and ev["status"] == 0x0C and ev["opcode"] in (0x200B, 0x200C) and not self.ext_scan \
                and self.mode_switches < 2:
            log.info("%s: legacy LE scan refused (controller uses extended advertising); switching to extended scan",
                     self.name)
            self.ext_scan = True
            self.mode_switches += 1
            status.update(self.name, scan="extended")
            self._start_le_scan()
        elif kind == "cmd" and ev["status"] != 0 and ev["opcode"] == 0x2041 and self.ext_scan and self.coded:
            log.info("%s: the controller refused scanning on the Coded PHY (0x%02x); scanning on 1M only", self.name, ev["status"])
            self.coded = False
            self._start_le_scan()
        elif kind == "cmd" and ev["status"] != 0 and ev["opcode"] in (0x2041, 0x2042) and self.ext_scan and self.mode_switches < 2:
            log.info("%s: extended LE scan refused (0x%02x); using legacy scan commands", self.name, ev["status"])
            self.ext_scan = False
            self.mode_switches += 1
            status.update(self.name, scan=None)
            self._start_le_scan()
        elif kind == "cmd" and ev["status"] not in (0,):
            log.debug("%s: command 0x%04x failed with status 0x%02x", self.name, ev["opcode"], ev["status"])
