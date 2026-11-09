"""Read a Bluetooth LE device's version by connecting to it for a moment (the admin asks for it with a button on the device page).

This is the one place where sniffowireless transmits Bluetooth: everything else in this program only listens. The adapter makes a
connection to the device (the device may notice it), asks the controller "Read Remote Version Information" - a standard link-layer
request every device must answer, which carries the version of the Bluetooth Core Specification it implements and the maker's
company ID - and disconnects at once. No pairing, no service discovery, nothing is read or written on the device.

Runs on a separate, short-lived raw HCI socket, like tracker_sound.py, so the passive scan keeps running. The link-layer and HCI
procedures follow the Bluetooth Core Specification but have not been exercised against many physical devices: if a device does
not answer as expected, the likely bug is here.
"""
import logging
import select
import struct
import threading
import time

from .bluetooth import OGF_LE, OGF_LINK, PROBING, bt_version_label, opcode
from .oui import bt_company
from .tracker_sound import _cmd, _open_socket

log = logging.getLogger("sniffowireless.btprobe")

CONNECT_TIMEOUT = 8     # seconds to wait for the connection
VERSION_TIMEOUT = 5     # seconds to wait for the answer once connected
DISCONNECT_WAIT = 2     # seconds to wait for the link to be torn down

_lock = threading.Lock()

CONNECT_ERRORS = {0x02: "the device was not there any more", 0x08: "the connection timed out", 0x0D: "the device refused the connection",
                  0x0F: "the device refused the connection", 0x3E: "the connection could not be established (the device may be out of range, "
                  "asleep, not connectable or already connected elsewhere)", 0x3C: "the device stopped advertising"}


class ProbeError(Exception):
    """Could not read the version; the message is meant to be shown to the admin as it is."""


def _events(pkt):
    """The HCI events this exchange cares about, from one raw packet (a dict) or None."""
    if len(pkt) < 3 or pkt[0] != 0x04:
        return None
    code, p = pkt[1], pkt[3:3 + pkt[2]]
    if code == 0x3E and p and p[0] in (0x01, 0x0A, 0x29) and len(p) >= 4:  # LE (enhanced, v2) connection complete
        return {"ev": "conn", "status": p[1], "handle": p[2] | (p[3] & 0x0F) << 8}
    if code == 0x05 and len(p) >= 4:  # disconnection complete
        return {"ev": "disc", "handle": p[1] | (p[2] & 0x0F) << 8}
    if code == 0x0C and len(p) >= 8:  # read remote version information complete
        return {"ev": "ver", "status": p[0], "handle": p[1] | (p[2] & 0x0F) << 8, "version": p[3], "company": p[4] | p[5] << 8}
    if code == 0x0F and len(p) >= 4:  # command status
        return {"ev": "status", "status": p[0], "opcode": p[2] | p[3] << 8}
    return None


def _wait(sock, timeout, match):
    end = time.monotonic() + timeout
    while True:
        left = end - time.monotonic()
        if left <= 0:
            return None
        r, _, _ = select.select([sock], [], [], left)
        if not r:
            return None
        ev = _events(sock.recv(4096))
        if ev and match(ev):
            return ev


def _create_connection(sock, addr, addr_type):
    """Start connecting. Controllers that have been used with the extended LE commands refuse the legacy one with "command disallowed"
    (0x0c), so then the extended command is used."""
    legacy = struct.pack("<HHBB6sBHHHHHH", 0x0060, 0x0030, 0, addr_type, addr, 0, 0x0018, 0x0028, 0, 0x00C8, 0, 0)
    _cmd(sock, OGF_LE, 0x000D, legacy)
    st = _wait(sock, 2, lambda e: e["ev"] == "status" and e["opcode"] == opcode(OGF_LE, 0x000D))
    if st and st["status"] == 0x0C:
        extended = struct.pack("<BBB6sB", 0, 0, addr_type, addr, 0x01) + struct.pack("<HHHHHHHH", 0x0060, 0x0030, 0x0018, 0x0028, 0, 0x00C8, 0, 0)
        _cmd(sock, OGF_LE, 0x0043, extended)
        st = _wait(sock, 2, lambda e: e["ev"] == "status" and e["opcode"] == opcode(OGF_LE, 0x0043))
    if st and st["status"] != 0:
        raise ProbeError(f"the Bluetooth adapter refused to connect (status 0x{st['status']:02x})")


def read_version(iface, mac, addr_type=1):
    """Connect to `mac` over `iface` ("hci0"), read its Bluetooth version and disconnect. Returns {"version": "5.2", "company": "Bose"}.
    `addr_type` is 0 for a public address, 1 for a random one (a private address only works if it has not rotated since it was heard).
    Raises ProbeError with a sentence for the admin."""
    dev_id = int(iface.replace("hci", "")) if iface.startswith("hci") else int(iface)
    addr = bytes(int(x, 16) for x in reversed(mac.split(":")))
    try:
        sock = _open_socket(dev_id)
    except Exception as e:  # SoundError from the shared helper, or an OSError
        raise ProbeError(str(e))
    handle = None
    with _lock:
        PROBING.add(mac)
    try:
        _create_connection(sock, addr, addr_type)
        ev = _wait(sock, CONNECT_TIMEOUT, lambda e: e["ev"] == "conn")
        if not ev:
            _cmd(sock, OGF_LE, 0x000E)  # LE Create Connection Cancel
            _wait(sock, 1, lambda e: e["ev"] == "conn")
            raise ProbeError("no connection in time: the device may be out of range, asleep, not connectable, or its address has changed")
        if ev["status"] != 0:
            raise ProbeError(CONNECT_ERRORS.get(ev["status"], f"the connection failed (Bluetooth status 0x{ev['status']:02x})").capitalize())
        handle = ev["handle"]
        _cmd(sock, OGF_LINK, 0x001D, struct.pack("<H", handle))  # Read Remote Version Information
        ans = _wait(sock, VERSION_TIMEOUT, lambda e: e["ev"] == "ver" and e["handle"] == handle)
        if not ans:
            raise ProbeError("connected, but the device did not answer the version request")
        if ans["status"] != 0:
            raise ProbeError(f"the device refused the version request (status 0x{ans['status']:02x})")
        return {"version": bt_version_label(ans["version"]), "company": bt_company(ans["company"])}
    finally:
        if handle is not None:
            try:
                _cmd(sock, OGF_LINK, 0x0006, struct.pack("<HB", handle, 0x13))  # Disconnect: remote user terminated
                _wait(sock, DISCONNECT_WAIT, lambda e: e["ev"] == "disc" and e["handle"] == handle)
            except OSError:
                pass
        sock.close()
        with _lock:
            PROBING.discard(mac)
