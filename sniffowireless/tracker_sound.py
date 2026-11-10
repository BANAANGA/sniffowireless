"""Remote "play sound" for generic BLE tracker tags (key finders, Tile-style tags, and anything else that
implements the standard Bluetooth SIG Immediate Alert Service) by connecting and writing its Alert Level
characteristic (UUID 0x2A06) — the same, open, unauthenticated mechanism those devices use for their own
"find my phone" button in reverse.

This deliberately does NOT work on genuine Apple AirTags or other Find My network accessories: those
reject connections from anything that isn't an authenticated Apple device (confirmed by public teardowns
and the SEEMOO research group's reverse-engineering work), and nobody has published a way around that.
Pressing the button on one will fail with a clear error rather than silently doing nothing useful.

Connects over the same kind of raw HCI socket sniffowireless/bluetooth.py's passive scanner uses — a separate,
short-lived socket opened just for this one action, so the passive scan on the adapter keeps running.
The Bluetooth LE connection / ATT (GATT) procedures below follow the Bluetooth Core Specification, but
this has not been exercised against physical tracker hardware: if a supported tracker doesn't respond as
expected, the likely bug is here, not in the tracker.
"""
import errno
import fcntl
import logging
import select
import socket
import struct
import time

from .bluetooth import ERFKILL, HCIDEVUP, HCI_FILTER, OGF_LE, SOL_HCI, opcode

log = logging.getLogger("sniffowireless.tracker_sound")

ALERT_LEVEL_UUID = 0x2A06
HIGH_ALERT = 2
CONNECT_TIMEOUT = 10   # seconds to wait for the LE connection to complete
GATT_TIMEOUT = 5       # seconds to wait for each GATT (ATT) response


class SoundError(Exception):
    """Could not make the device play a sound; the message is meant to be shown to the admin as-is."""


def _open_socket(dev_id):
    if not hasattr(socket, "AF_BLUETOOTH"):  # a Python built without Bluetooth support has no such constant
        raise SoundError("This Python has no Bluetooth socket support (it was built without it)")
    s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    try:
        fcntl.ioctl(s.fileno(), HCIDEVUP, dev_id)
    except OSError as e:
        if e.errno == ERFKILL:
            s.close()
            raise SoundError(f"hci{dev_id} is blocked by rfkill (run: rfkill unblock bluetooth)")
        if e.errno == errno.ENODEV:
            s.close()
            raise SoundError(f"hci{dev_id} not found (is the adapter plugged in?)")
        if e.errno not in (errno.EALREADY, errno.EBUSY):
            log.debug("HCIDEVUP: %s", e)
    s.bind((dev_id,))
    # HCI_EVENT_PKT (0x04, connection/command status) and HCI_ACLDATA_PKT (0x02, our GATT traffic).
    type_mask = (1 << 0x02) | (1 << 0x04)
    s.setsockopt(SOL_HCI, HCI_FILTER, struct.pack("<IIIH2x", type_mask, 0xFFFFFFFF, 0xFFFFFFFF, 0))
    return s


def _cmd(sock, ogf, ocf, params=b""):
    sock.send(bytes([0x01]) + struct.pack("<HB", opcode(ogf, ocf), len(params)) + params)


def _att_write(sock, handle, att_pdu):
    """Send one ATT PDU over this connection's fixed ATT channel (L2CAP CID 0x0004)."""
    l2cap = struct.pack("<HH", len(att_pdu), 0x0004) + att_pdu
    # Packet Boundary Flag 0b10: "first (and only) automatically-flushable packet" — the conventional
    # value host stacks use to send one complete, unfragmented L2CAP packet.
    handle_flags = (handle & 0x0FFF) | (0b10 << 12)
    sock.send(bytes([0x02]) + struct.pack("<HH", handle_flags, len(l2cap)) + l2cap)


def _parse_packet(pkt):
    """One HCI packet (event or ACL data) relevant to this connection, as a dict, else None."""
    if len(pkt) < 1:
        return None
    if pkt[0] == 0x04:  # event
        if len(pkt) < 3:
            return None
        code, p = pkt[1], pkt[3:3 + pkt[2]]
        if code == 0x3E and p and p[0] in (0x01, 0x0A) and len(p) >= 12:  # LE (enhanced) connection complete
            return {"ev": "conn", "status": p[1], "handle": p[2] | (p[3] & 0x0F) << 8}
        if code == 0x05 and len(p) >= 4:  # disconnection complete
            return {"ev": "disc", "handle": p[1] | (p[2] & 0x0F) << 8}
        return None
    if pkt[0] == 0x02:  # ACL data; assumes one complete, unfragmented L2CAP packet per HCI packet (true
        if len(pkt) < 9:  # for the small ATT PDUs this exchange uses)
            return None
        handle = (pkt[1] | pkt[2] << 8) & 0x0FFF
        l2len, cid = struct.unpack_from("<HH", pkt, 5)
        if cid != 0x0004:  # something other than the ATT fixed channel; not our concern
            return None
        return {"ev": "att", "handle": handle, "data": pkt[9:9 + l2len]}
    return None


def _wait_for(sock, deadline, match):
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None
        r, _, _ = select.select([sock], [], [], remaining)
        if not r:
            return None
        ev = _parse_packet(sock.recv(4096))
        if ev and match(ev):
            return ev


def play_sound(iface, mac, addr_type=1):
    """Connect to `mac` (a BLE device) over `iface` (e.g. "hci0") and write High Alert to its Immediate
    Alert Service. `addr_type` is 0 for a public Bluetooth address, 1 for a random one (static or private
    — sniffowireless doesn't use the device's identity resolving key, so a private address only works if it hasn't
    rotated since it was last seen). Raises SoundError, with a message fit to show the admin, on anything
    that didn't work — including a device that simply doesn't have this service (e.g. a real AirTag).
    """
    dev_id = int(iface.replace("hci", "")) if iface.startswith("hci") else int(iface)
    addr = bytes(int(x, 16) for x in reversed(mac.split(":")))
    sock = _open_socket(dev_id)
    handle = None
    try:
        # LE Create Connection (OGF 0x08 / OCF 0x000D): scan fast while connecting, modest connection
        # parameters, no special filtering (we connect to this one peer address directly).
        params = struct.pack("<HHBB6sBHHHHHH", 0x0060, 0x0060, 0, addr_type, addr, 0,
                             0x0018, 0x0028, 0, 0x01F4, 0x0000, 0x0000)
        _cmd(sock, OGF_LE, 0x000D, params)
        deadline = time.time() + CONNECT_TIMEOUT
        ev = _wait_for(sock, deadline, lambda e: e["ev"] == "conn")
        if not ev:
            _cmd(sock, OGF_LE, 0x000E)  # LE Create Connection Cancel — give up trying to reach it
            raise SoundError("Timed out connecting — the device may be out of range, asleep, or already connected elsewhere")
        if ev["status"] != 0:
            raise SoundError(f"Connection refused (Bluetooth status 0x{ev['status']:02x})")
        handle = ev["handle"]

        # Find the Alert Level characteristic: ATT Read By Type Request for UUID 0x2A06 over the whole handle range.
        _att_write(sock, handle, struct.pack("<BHHH", 0x08, 0x0001, 0xFFFF, ALERT_LEVEL_UUID))
        ev = _wait_for(sock, time.time() + GATT_TIMEOUT, lambda e: e["ev"] == "att" and e["handle"] == handle)
        if not ev or not ev["data"]:
            raise SoundError("No response discovering a sound-alert service — this doesn't look like a supported tracker")
        op = ev["data"][0]
        if op == 0x01:  # ATT Error Response: no such characteristic
            raise SoundError("This device has no sound-alert service — it isn't a supported tracker "
                             "(genuine Apple AirTags don't support this: Apple restricts them to its own devices)")
        if op != 0x09 or len(ev["data"]) < 5:  # Read By Type Response
            raise SoundError(f"Unexpected response (0x{op:02x}) while looking for the sound-alert service")
        char_handle = struct.unpack_from("<H", ev["data"], 2)[0]

        # Write High Alert to it, acknowledged (ATT Write Request / Write Response).
        _att_write(sock, handle, struct.pack("<BHB", 0x12, char_handle, HIGH_ALERT))
        ev = _wait_for(sock, time.time() + GATT_TIMEOUT, lambda e: e["ev"] == "att" and e["handle"] == handle)
        if not ev or not ev["data"]:
            raise SoundError("No response to the sound command")
        if ev["data"][0] == 0x01:
            raise SoundError("Device refused the sound command")
        if ev["data"][0] != 0x13:  # ATT Write Response
            raise SoundError(f"Unexpected response (0x{ev['data'][0]:02x}) to the sound command")
    finally:
        if handle is not None:
            try:
                _cmd(sock, 0x01, 0x0006, struct.pack("<HB", handle, 0x13))  # HCI Disconnect (OGF Link Control)
            except OSError:
                pass
        sock.close()
