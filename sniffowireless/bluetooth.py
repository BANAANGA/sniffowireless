"""Bluetooth Classic + BLE scanning over a raw HCI socket (no BlueZ daemon required).

The sensor opens a raw HCI socket on the adapter, enables LE scanning and
periodic classic inquiry, and parses the controller's events. Because a raw
socket sees *all* events, advertisements caught by a host bluetoothd scan and
connections made by the host are recorded as well.
"""
import errno
import fcntl
import logging
import select
import socket
import struct
import threading
import time

from . import status
from .identify import ble_fingerprint
from .oui import bt_company

log = logging.getLogger("sniffowireless.bt")

SOL_HCI = 0
HCI_FILTER = 2
HCIDEVUP = 0x400448C9
ERFKILL = 132

OGF_LINK, OGF_HOST, OGF_LE = 0x01, 0x03, 0x08

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
        elif t in (0x02, 0x03):
            uuids += [f"{v[j] | v[j + 1] << 8:04x}" for j in range(0, len(v) - 1, 2)]
        elif t == 0x16 and len(v) >= 2:
            uuids.append(f"{v[0] | v[1] << 8:04x}")
        i += 1 + ln
    if uuids:
        out["uuids"] = sorted(set(uuids))[:16]
    return out


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
                            "connectable": evt_type in (0, 1), "ad": parse_ad(data)})
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
                i += 24 + ln
                out.append({"ev": "adv", "mac": bdaddr(addr), "addr_type": atype, "rssi": r,
                            "connectable": bool(evt_type & 0x01), "ad": parse_ad(data),
                            "ext": not evt_type & 0x10})  # bit 4 set = legacy PDU
        elif sub in (0x01, 0x0A) and len(p) >= 12 and p[1] == 0:  # LE (enhanced) connection complete
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
    elif code == 0x0E and len(p) >= 4:  # command complete
        out.append({"ev": "cmd", "opcode": p[1] | p[2] << 8, "status": p[3]})
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
        self.fp_seen = {}       # mac -> (fingerprint, ts) to avoid re-sending identical fingerprints
        self.packets = 0
        self.stop = None
        status.register(self.name, type="bluetooth", iface=dev, adverts=0, inquiries=0)

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

    def _configure(self):
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
            self._cmd(OGF_LE, 0x0041, struct.pack("<BBBBHH", 0, 0, 0x01, active, 0x0030, 0x0030))  # 1M PHY
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
            self.store.put({
                "t": "bt", "kind": "ble", "ts": now, "mac": ev["mac"], "rssi": ev["rssi"],
                "name": ad.get("name"), "randomized": randomized, "addr_random": label != "public",
                "vendor": bt_company(cid) if label != "public" and cid is not None else None,
                "extra": {"addr_type": label, "company": bt_company(cid), "appearance": ad.get("appearance"),
                          "tx_power": ad.get("tx_power"), "uuids": ad.get("uuids"),
                          "connectable": ev["connectable"]},
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
        elif kind == "cmd" and ev["status"] == 0x0C and ev["opcode"] in (0x200B, 0x200C) and not self.ext_scan:
            log.info("%s: legacy LE scan refused (controller uses extended advertising); switching to extended scan",
                     self.name)
            self.ext_scan = True
            status.update(self.name, scan="extended")
            self._start_le_scan()
        elif kind == "cmd" and ev["status"] not in (0,):
            log.debug("%s: command 0x%04x failed with status 0x%02x", self.name, ev["opcode"], ev["status"])
