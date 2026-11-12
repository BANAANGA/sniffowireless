"""Talking to USB Zigbee sticks, and decoding what they hear. No dependencies, no threads, no storage.

Two firmware families are supported. Both are only used in ways that leave the stick's stored network settings alone,
so scanning can't damage the network a stick coordinates, and nothing here ever transmits a frame of its own:

- EmberZNet / EZSP (Sonoff ZBDongle-E, SkyConnect, ZBT-1): over ASH serial framing. Can scan for networks, measure
  channel energy and, if the firmware includes the manufacturing library (mfglib), capture raw 802.15.4 frames.
- Z-Stack / ZNP (Sonoff ZBDongle-P, CC2652, CC2531): over TI's MT protocol. Can only scan for networks: other tools
  widen the channel list by rewriting it, and energy scans need a running network, and we do neither.

A link is anything with write(bytes), read(timeout_seconds) -> bytes and set_pins(dtr, rts).
"""
import binascii
import struct
import time

ALL_CHANNELS = list(range(11, 27))
ALL_CHANNELS_MASK = 0x07FFF800
ACTIVE_EXPONENT = 4  # about 0.26 s per channel, 4.2 s in total
ENERGY_EXPONENT = 3  # about 0.14 s per channel, 2.2 s in total
SCAN_TIMEOUT = 30.0
COMMAND_TIMEOUT = 3.0


class ZigbeeError(Exception):
    pass


class NoCaptureMode(ZigbeeError):
    """The firmware has no mfglib, so it can scan but not sniff."""


def eui64(data):
    """Zigbee sends EUI-64s least significant byte first but displays them most significant first."""
    return ":".join(f"{b:02x}" for b in reversed(data))


# ------------------------------------------------------------------------------------- Z-Stack (MT)
ZNP_SOF = 0xFE
BEACON_SIZE = 21


def znp_encode(cmd0, cmd1, data=b""):
    body = bytes([len(data), cmd0, cmd1]) + data
    fcs = 0
    for b in body:
        fcs ^= b
    return bytes([ZNP_SOF]) + body + bytes([fcs])


class ZnpParser:
    """Reassembles frames from arbitrary chunks, resynchronising on the next SOF after bad data."""

    def __init__(self):
        self.buf = bytearray()

    def _skip(self):
        i = self.buf.find(ZNP_SOF, 1)
        if i < 0:
            self.buf.clear()
        else:
            del self.buf[:i]

    def feed(self, data):
        self.buf += data
        out = []
        while self.buf:
            if self.buf[0] != ZNP_SOF:
                self._skip()
                continue
            if len(self.buf) < 2:
                break
            n = self.buf[1]
            if n > 250:
                self._skip()
                continue
            if len(self.buf) < n + 5:
                break
            fcs = 0
            for b in self.buf[1:n + 4]:
                fcs ^= b
            if fcs != self.buf[n + 4]:
                self._skip()
                continue
            out.append((self.buf[2], self.buf[3], bytes(self.buf[4:n + 4])))
            del self.buf[:n + 5]
        return out


def parse_beacons(data):
    """ZDO_BEACON_NOTIFY_IND: a count, then fixed-size beacon records."""
    if not data:
        return []
    nets = []
    for n in range(min(data[0], (len(data) - 1) // BEACON_SIZE)):
        b = data[1 + n * BEACON_SIZE:1 + (n + 1) * BEACON_SIZE]
        nets.append({
            "ext_pan": eui64(b[13:21]), "pan": struct.unpack_from("<H", b, 2)[0], "channel": b[4],
            "permit_join": bool(b[5]), "router_capacity": bool(b[6]), "device_capacity": bool(b[7]),
            "protocol": b[8], "stack_profile": b[9], "lqi": b[10], "update_id": b[12],
            "routers": [struct.unpack_from("<H", b, 0)[0]],
        })
    return nets


class ZnpDriver:
    family = "zstack"
    can_capture = False
    SREQ_SYS, SRSP_SYS, SREQ_ZDO, SRSP_ERROR, AREQ_ZDO = 0x21, 0x61, 0x25, 0x60, 0x45
    PING, VERSION, NV_READ, NWK_DISCOVERY, BEACON_NOTIFY, NWK_DISCOVERY_CNF = 0x01, 0x02, 0x08, 0x26, 0xC5, 0xC7
    NV_CHANLIST = 0x0084

    def __init__(self, link, parser, firmware, notes):
        self.link, self.parser, self.firmware, self.notes = link, parser, firmware, notes

    @staticmethod
    def _request(link, parser, cmd0, cmd1, data, timeout, pending=None):
        link.write(znp_encode(cmd0, cmd1, data))
        expected = (cmd0 & 0x1F) | 0x60
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for frame in parser.feed(link.read(0.1)):
                if frame[0] == expected and frame[1] == cmd1:
                    return frame
                if frame[0] == ZnpDriver.SRSP_ERROR:  # MT answers commands it doesn't know with an RPC error
                    return None
                if pending is not None:
                    pending.append(frame)
        return None

    @classmethod
    def connect(cls, link, timeout):
        parser = ZnpParser()
        if cls._request(link, parser, cls.SREQ_SYS, cls.PING, b"", timeout) is None:
            return None
        firmware = "Z-Stack (version unknown)"
        version = cls._request(link, parser, cls.SREQ_SYS, cls.VERSION, b"", COMMAND_TIMEOUT)
        if version and len(version[2]) >= 5:
            v = version[2]
            build = struct.unpack_from("<I", v, 5)[0] if len(v) >= 9 else 0
            firmware = f"Z-Stack {v[2]}.{v[3]}.{v[4]}" + (f" (build {build})" if build else "")
        notes = ["Z-Stack can only measure channel energy with its network running, so this stays read-only and skips it."]
        # Reading is safe; other tools widen this list by rewriting it, which we refuse to do.
        nv = cls._request(link, parser, cls.SREQ_SYS, cls.NV_READ, struct.pack("<HB", cls.NV_CHANLIST, 0), COMMAND_TIMEOUT)
        if nv and len(nv[2]) >= 6 and nv[2][0] == 0:
            mask = struct.unpack_from("<I", nv[2], 2)[0]
            if mask & ALL_CHANNELS_MASK != ALL_CHANNELS_MASK:
                found = [c for c in ALL_CHANNELS if mask >> c & 1]
                if found:
                    notes.append(f"This stick is configured for channel{'s' if len(found) > 1 else ''} "
                                 f"{', '.join(map(str, found))}, so networks on other channels may be missed.")
                # a mask with no channel 11-26 in it (unset or not a channel list): nothing useful to say
        return cls(link, parser, firmware, notes)

    def scan(self, on_network, on_energy, stop=None):
        pending = []
        response = self._request(self.link, self.parser, self.SREQ_ZDO, self.NWK_DISCOVERY,
                                 struct.pack("<IB", ALL_CHANNELS_MASK, ACTIVE_EXPONENT), COMMAND_TIMEOUT, pending)
        if response is None:
            raise ZigbeeError("The stick did not answer the scan request")
        if not response[2] or response[2][0] != 0:
            raise ZigbeeError("The stick refused to scan; unplug it and plug it back in if its network is running")
        deadline = time.monotonic() + SCAN_TIMEOUT
        while True:
            for cmd0, cmd1, data in pending:
                if cmd0 != self.AREQ_ZDO:
                    continue
                if cmd1 == self.BEACON_NOTIFY:
                    for network in parse_beacons(data):
                        on_network(network)
                elif cmd1 == self.NWK_DISCOVERY_CNF:
                    return
            pending.clear()
            if time.monotonic() > deadline or (stop is not None and stop.is_set()):
                raise ZigbeeError("The scan did not finish in time")
            pending.extend(self.parser.feed(self.link.read(0.1)))


# ------------------------------------------------------------------------------------- ASH
ASH_FLAG, ASH_ESCAPE, ASH_XON, ASH_XOFF, ASH_SUBSTITUTE, ASH_CANCEL = 0x7E, 0x7D, 0x11, 0x13, 0x18, 0x1A
ASH_RESERVED = frozenset((ASH_FLAG, ASH_ESCAPE, ASH_XON, ASH_XOFF, ASH_SUBSTITUTE, ASH_CANCEL))


def _pseudo_random():
    out, r = bytearray(), 0x42
    for _ in range(256):
        out.append(r)
        r = r >> 1 if r & 1 == 0 else (r >> 1) ^ 0xB8
    return bytes(out)


PSEUDO_RANDOM = _pseudo_random()


def ash_randomize(data):
    return bytes(a ^ b for a, b in zip(data, PSEUDO_RANDOM))


def ash_wire(frame):
    body = frame + binascii.crc_hqx(frame, 0xFFFF).to_bytes(2, "big")
    out = bytearray()
    for b in body:
        if b in ASH_RESERVED:
            out += bytes((ASH_ESCAPE, b ^ 0x20))
        else:
            out.append(b)
    out.append(ASH_FLAG)
    return bytes(out)


def ash_reset():
    """The cancel bytes abort anything half-received; the stick reboots and answers with RSTACK."""
    return bytes([ASH_CANCEL]) * 32 + ash_wire(b"\xC0")


def ash_ack(n):
    return ash_wire(bytes([0x80 | n]))


def ash_nak(n):
    return ash_wire(bytes([0xA0 | n]))


def ash_data(number, retransmit, ack, payload):
    return ash_wire(bytes([(number << 4) | (0x08 if retransmit else 0) | ack]) + ash_randomize(payload))


def ash_decode(data):
    """Returns (kind, ...) for unstuffed bytes, or None if corrupt or not a frame a host expects."""
    if len(data) < 3 or binascii.crc_hqx(data[:-2], 0xFFFF).to_bytes(2, "big") != data[-2:]:
        return None
    control, body = data[0], data[1:-2]
    if control & 0x80 == 0:
        return "data", (control >> 4) & 7, bool(control & 0x08), control & 7, ash_randomize(body)
    if control & 0xE0 == 0x80:
        return "ack", control & 7
    if control & 0xE0 == 0xA0:
        return "nak", control & 7
    if control == 0xC1 and len(body) == 2:
        return "rstack", body[0], body[1]
    if control == 0xC2 and len(body) == 2:
        return "error", body[0], body[1]
    return None


class AshParser:
    MAX_FRAME = 1024

    def __init__(self):
        self.current = bytearray()
        self.discarding = False

    def feed(self, data):
        """Returns (frames, damaged data frames)."""
        frames, damaged = [], 0
        for b in data:
            if b in (ASH_XON, ASH_XOFF):  # flow control, not frame content
                continue
            if b == ASH_CANCEL:
                self.current.clear()
            elif b == ASH_SUBSTITUTE:
                self.current.clear()
                self.discarding = True
            elif b == ASH_FLAG:
                if not self.discarding and self.current:
                    raw = self._unstuff(self.current)
                    frame = ash_decode(raw) if raw is not None else None
                    if frame:
                        frames.append(frame)
                    elif raw and raw[0] & 0x80 == 0:
                        damaged += 1
                self.current.clear()
                self.discarding = False
            elif not self.discarding and len(self.current) < self.MAX_FRAME:
                self.current.append(b)
        return frames, damaged

    @staticmethod
    def _unstuff(data):
        out, escaped = bytearray(), False
        for b in data:
            if escaped:
                b ^= 0x20
                if b not in ASH_RESERVED:
                    return None
                out.append(b)
                escaped = False
            elif b == ASH_ESCAPE:
                escaped = True
            else:
                out.append(b)
        return bytes(out)


class AshSession:
    """Sequencing, acknowledgement and retransmission. One DATA frame is in flight at a time."""
    ATTEMPTS, ACK_TIMEOUT = 5, 1.6

    def __init__(self, link):
        self.link = link
        self.parser = AshParser()
        self.received = []
        self.tx = self.rx = 0
        self.last_ack = None
        self.got_nak = self.got_rstack = False

    def _pump(self):
        frames, damaged = self.parser.feed(self.link.read(0.05))
        if damaged:
            self.link.write(ash_nak(self.rx))
        for f in frames:
            if f[0] == "data":
                _, number, retransmit, ack, payload = f
                self.last_ack = ack
                if number == self.rx:
                    self.rx = (self.rx + 1) % 8
                    self.link.write(ash_ack(self.rx))
                    self.received.append(payload)
                elif retransmit:
                    self.link.write(ash_ack(self.rx))
                else:
                    self.link.write(ash_nak(self.rx))
            elif f[0] == "ack":
                self.last_ack = f[1]
            elif f[0] == "nak":
                self.got_nak = True
            elif f[0] == "rstack":
                self.got_rstack = True
            elif f[0] == "error":
                raise ZigbeeError(f"The stick reported a firmware error (code 0x{f[2]:02x})")

    def reset(self, timeout):
        """Reboots the stick's firmware (stored network data is untouched) and waits for it to answer."""
        self.got_rstack = False
        self.link.write(ash_reset())
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._pump()
            if self.got_rstack:
                self.got_rstack = False
                self.tx = self.rx = 0
                self.received.clear()
                return True
        return False

    def send(self, payload):
        number = self.tx
        self.tx = (self.tx + 1) % 8
        expected = (number + 1) % 8
        for attempt in range(self.ATTEMPTS):
            self.last_ack, self.got_nak = None, False
            self.link.write(ash_data(number, attempt > 0, self.rx, payload))
            deadline = time.monotonic() + self.ACK_TIMEOUT
            while time.monotonic() < deadline:
                self._pump()
                if self.last_ack == expected:
                    return
                if self.got_nak:
                    break
        raise ZigbeeError("The stick stopped acknowledging commands")

    def receive(self, deadline):
        while not self.received and time.monotonic() < deadline:
            self._pump()
        return self.received.pop(0) if self.received else None


# ------------------------------------------------------------------------------------- EZSP
def ezsp_encode(version, seq, frame_id, params=b""):
    """EZSP headers changed shape twice, so they depend on the negotiated protocol version."""
    if version >= 8:
        return bytes((seq, 0, 1)) + struct.pack("<H", frame_id) + params
    if version >= 5:
        return bytes((seq, 0, 0xFF, 0, frame_id)) + params
    return bytes((seq, 0, frame_id)) + params


def ezsp_decode(version, data):
    """Returns (sequence, frame id, parameters), or None if too short."""
    if version >= 8 and len(data) >= 5:
        return data[0], struct.unpack_from("<H", data, 3)[0], data[5:]
    if 5 <= version <= 7 and len(data) >= 5:
        return data[0], data[4], data[5:]
    if version < 5 and len(data) >= 3:
        return data[0], data[2], data[3:]
    return None


def parse_network_found(p):
    """networkFoundHandler: EmberZigbeeNetwork, last hop LQI, last hop RSSI."""
    if len(p) < 16:
        return None
    return {"ext_pan": eui64(p[3:11]), "pan": struct.unpack_from("<H", p, 1)[0], "channel": p[0],
            "permit_join": bool(p[11]), "stack_profile": p[12], "update_id": p[13], "lqi": p[14],
            "rssi": struct.unpack_from("<b", p, 15)[0], "routers": []}


def parse_captured(channel, p):
    """mfglibRxHandler: lqi, rssi, length, packet. The last two packet bytes aren't a real checksum: drop them."""
    if len(p) < 3:
        return None
    n = min(p[2], len(p) - 3)
    if n < 2:
        return None
    return {"channel": channel, "lqi": p[0], "rssi": struct.unpack_from("<b", p, 1)[0], "data": p[3:3 + n - 2]}


class EzspDriver:
    family = "ezsp"
    can_capture = True
    notes = ()
    VERSION, START_SCAN, NETWORK_FOUND, SCAN_COMPLETE, ENERGY_RESULT, INVALID = 0x00, 0x1A, 0x1B, 0x1C, 0x48, 0x58
    MFG_START, MFG_END, MFG_CHANNEL, MFG_RX = 0x83, 0x84, 0x8A, 0x8E
    SCAN_ENERGY, SCAN_ACTIVE = 0, 1
    RESTART_TIMEOUT = 2.0

    def __init__(self, ash, version, seq, firmware):
        self.ash, self.version, self.seq, self.firmware = ash, version, seq, firmware
        self.callbacks = []

    @classmethod
    def connect(cls, link, timeout):
        ash = AshSession(link)
        if not ash.reset(timeout):
            return None
        seq = [0]

        def version_cmd(fmt, desired):
            s = seq[0]
            seq[0] += 1
            ash.send(ezsp_encode(fmt, s, cls.VERSION, bytes([desired])))
            deadline = time.monotonic() + COMMAND_TIMEOUT
            while True:
                data = ash.receive(deadline)
                if data is None:
                    raise ZigbeeError("The stick did not report its EZSP version")
                f = ezsp_decode(fmt, data)
                if f and f[0] == s and f[1] == cls.VERSION and len(f[2]) >= 4:
                    return f[2]

        # Always opens in the legacy format; the reply says which version to switch to.
        reply = version_cmd(4, 4)
        negotiated = reply[0]
        if negotiated != 4:
            reply = version_cmd(negotiated, negotiated)
        s = struct.unpack_from("<H", reply, 2)[0]
        firmware = f"EmberZNet {s >> 12 & 15}.{s >> 8 & 15}.{s >> 4 & 15}.{s & 15} (EZSP v{negotiated})"
        return cls(ash, negotiated, seq[0], firmware)

    def _next(self, deadline):
        data = self.ash.receive(deadline)
        if data is None:
            return None
        frame = ezsp_decode(self.version, data)
        if frame is None:
            raise ZigbeeError("The stick sent a malformed frame")
        return frame

    def _command(self, frame_id, params=b""):
        seq = self.seq
        self.seq = (self.seq + 1) & 0xFF
        self.ash.send(ezsp_encode(self.version, seq, frame_id, params))
        deadline = time.monotonic() + COMMAND_TIMEOUT
        while True:
            frame = self._next(deadline)
            if frame is None:
                raise ZigbeeError("The stick did not answer a command")
            if frame[0] == seq and frame[1] == frame_id:
                return frame[2]
            if frame[0] == seq and frame[1] == self.INVALID:
                raise ZigbeeError("The stick rejected a command as invalid")
            self.callbacks.append(frame)

    def _run_scan(self, kind, exponent, on_network, on_energy):
        status = self._command(self.START_SCAN, struct.pack("<BIB", kind, ALL_CHANNELS_MASK, exponent))
        # Status is one byte up to EZSP 13 and four after that; zero means success in both.
        if any(status):
            raise ZigbeeError(f"The stick refused to scan (status 0x{status.hex()})")
        deadline = time.monotonic() + SCAN_TIMEOUT
        while True:
            frame = self.callbacks.pop(0) if self.callbacks else self._next(deadline)
            if frame is None:
                raise ZigbeeError("The scan did not finish in time")
            _, frame_id, p = frame
            if frame_id == self.NETWORK_FOUND:
                network = parse_network_found(p)
                if network:
                    on_network(network)
            elif frame_id == self.ENERGY_RESULT and len(p) >= 2:
                on_energy(p[0], struct.unpack_from("<b", p, 1)[0])
            elif frame_id == self.SCAN_COMPLETE:
                return

    def scan(self, on_network, on_energy, stop=None):
        self._run_scan(self.SCAN_ENERGY, ENERGY_EXPONENT, on_network, on_energy)
        self._run_scan(self.SCAN_ACTIVE, ACTIVE_EXPONENT, on_network, on_energy)

    def capture(self, channels, dwell, until, on_channel, on_frame):
        """Listens with mfglib until until() is true, then restarts the stick. Receive-only: nothing is transmitted
        (mfglibSendPacket, tones and streams are never used) and nothing is stored on the stick."""
        message = "This stick's firmware has no capture mode (mfglib), so it can scan but not sniff"
        try:
            started = self._command(self.MFG_START, b"\x01")
        except ZigbeeError as e:
            raise NoCaptureMode(message) from e
        if any(started):
            raise NoCaptureMode(message)

        def deliver(frame, channel):
            if frame[1] == self.MFG_RX and channel is not None:
                captured = parse_captured(channel, frame[2])
                if captured:
                    on_frame(captured)

        try:
            current, index = None, 0
            while not until():
                channel = channels[index % len(channels)]
                index += 1
                if channel != current:
                    if any(self._command(self.MFG_CHANNEL, bytes([channel]))):
                        raise ZigbeeError(f"The stick couldn't switch to channel {channel}")
                    # Anything queued while switching was heard on the old channel.
                    while self.callbacks:
                        deliver(self.callbacks.pop(0), current)
                    current = channel
                    on_channel(channel)
                end = time.monotonic() + dwell
                while time.monotonic() < end and not until():
                    frame = self.callbacks.pop(0) if self.callbacks else self._next(min(end, time.monotonic() + 0.25))
                    if frame:
                        deliver(frame, current)
        finally:
            # Also runs when stopping, and may fail if the stick was just unplugged.
            try:
                self._command(self.MFG_END)
                self.ash.reset(self.RESTART_TIMEOUT)
            except (ZigbeeError, OSError):
                pass


# ------------------------------------------------------------------------------------- detection
def detect(link, family=None, stop=None):
    """Works out what firmware a stick runs by asking: the same USB chip sits on both kinds of stick. Each probe is
    harmless to the other firmware, which ignores bytes outside its own framing.

    EZSP goes first and leaves DTR and RTS alone, because on the ZBDongle-E those lines drive the chip's reset and
    boot pins. `family` skips straight to a firmware found earlier."""
    if family == "zstack":
        driver = ZnpDriver.connect(link, 1.0)
        if driver:
            return driver
    for _ in range(2):
        driver = EzspDriver.connect(link, 3.0)
        if driver:
            return driver
        if stop is not None and stop.is_set():
            return None
    # This pin sequence leaves CC2652 sticks running: other patterns start their bootloader.
    for rts in (False, True, False):
        link.set_pins(False, rts)
        time.sleep(0.15)
    for _ in range(3):
        driver = ZnpDriver.connect(link, 0.5)
        if driver:
            return driver
    # CC253x sticks wait in their bootloader until they receive this byte.
    link.write(b"\xEF" * 256)
    time.sleep(2.5)
    for _ in range(3):
        driver = ZnpDriver.connect(link, 1.0)
        if driver:
            return driver
    return None


# ------------------------------------------------------------------------------------- IEEE 802.15.4
TYPE_NAMES = ("beacon", "data", "ack", "command", "other")
# What a frame's unencrypted parts suggest, from least to most telling. Never proof: encrypted content is not read,
# and there are deliberately no product labels, because no verified signatures for specific products are built in.
HINTS = ("unknown", "encrypted", "thread", "zigbee")
HINT_UNKNOWN, HINT_ENCRYPTED, HINT_THREAD, HINT_ZIGBEE = range(4)


class MacFrame:
    __slots__ = ("type", "secured", "sequence", "dst_pan", "dst", "src_pan", "src", "payload", "sec_level", "key_mode")

    def __init__(self, type_, secured, sequence, dst_pan, dst, src_pan, src, payload, sec_level=None, key_mode=None):
        self.type, self.secured, self.sequence = type_, secured, sequence
        self.dst_pan, self.dst, self.src_pan, self.src, self.payload = dst_pan, dst, src_pan, src, payload
        self.sec_level, self.key_mode = sec_level, key_mode  # from the auxiliary security header (None: not secured / not read)

    @property
    def hint(self):
        p = self.payload
        if self.type == "beacon":
            return _beacon_hint(p)
        if self.secured:  # Zigbee encrypts above this layer, not here
            # Thread secures every frame at the MAC layer with security level 5 (encryption + 32-bit MIC) and key mode 1 (data) or 2 (MLE):
            # OpenThread accepts nothing else (mac.cpp). Zigbee does not use MAC security, so this combination is a good sign, not proof.
            if self.type in ("data", "command") and self.sec_level == 5 and self.key_mode in (1, 2):
                return HINT_THREAD
            return HINT_ENCRYPTED
        if self.type == "data" and len(p) >= 8 and p[0] & 3 <= 1 and (p[0] >> 2) & 15 == 2:
            return HINT_ZIGBEE
        if self.type == "data" and self.dst == "0xffff" and parse_gp(p):  # Zigbee Green Power: battery-less switches and sensors of a Zigbee network
            return HINT_ZIGBEE
        if self.type == "data" and p and p[0] & 0xE0 == 0x60:  # 6LoWPAN IPHC dispatch
            return HINT_THREAD
        return HINT_UNKNOWN


def _beacon_body(p):
    """Offset of the beacon payload after the superframe specification, GTS fields and pending addresses, or None."""
    if len(p) < 4:
        return None
    gts = p[2] & 7
    at = 3 + (1 if gts else 0) + gts * 3
    if at >= len(p):
        return None
    pending = p[at]
    body = at + 1 + (pending & 7) * 2 + ((pending >> 4) & 7) * 8
    return body if body < len(p) else None


def _beacon_hint(p):
    body = _beacon_body(p)
    if body is None:
        return HINT_UNKNOWN
    return {0: HINT_ZIGBEE, 3: HINT_THREAD}.get(p[body], HINT_UNKNOWN)


THREAD_PROTOCOL_ID = 3
THREAD_BEACON_SIZE = 26   # protocol id, flags, 16-byte network name, 8-byte extended PAN ID (OpenThread: src/core/mac/mac_beacon.hpp)


def parse_thread_beacon(p):
    """A Thread beacon's payload: {"version", "native", "joining", "name", "ext_pan"}, or None if `p` is not one. Layout (OpenThread,
    mac_beacon.hpp): protocol ID 3; flags (version in the high four bits, bit 3 = native commissioner, bit 0 = joining permitted);
    the network name in 16 bytes padded with zeros; the extended PAN ID in 8 bytes."""
    body = _beacon_body(p)
    if body is None or p[body] != THREAD_PROTOCOL_ID or len(p) - body < THREAD_BEACON_SIZE:
        return None
    flags = p[body + 1]
    name = bytes(p[body + 2:body + 18]).split(b"\x00")[0].decode("utf-8", "replace")
    name = "".join(ch for ch in name if ch.isprintable()).strip()
    return {"version": flags >> 4, "native": bool(flags & 0x08), "joining": bool(flags & 0x01), "name": name[:16],
            "ext_pan": ":".join(f"{b:02x}" for b in p[body + 18:body + 26])}  # as OpenThread prints it: the bytes in the order sent, not reversed like an address


def _pans_present(version, dst_mode, src_mode, compressed):
    has_dst, has_src = dst_mode != 0, src_mode != 0
    if version < 2:
        return has_dst, has_src and not compressed
    # The 2015 revision's table: compression means something different for each combination.
    if not has_dst and not has_src:
        return compressed, False
    if has_dst and not has_src:
        return not compressed, False
    if not has_dst:
        return False, not compressed
    if dst_mode == 3 and src_mode == 3:
        return not compressed, False
    return True, not compressed


def parse_mac(data):
    """Decodes the unencrypted 802.15.4 MAC header (2006 and 2015 revisions). None for frames too short or malformed
    to trust. Addresses come back as '0x1a2b' (short) or a colon-separated EUI-64 (long)."""
    if len(data) < 2:
        return None
    control = data[0] | data[1] << 8
    type_ = TYPE_NAMES[min(control & 7, 4)]
    secured, compressed = bool(control & 0x08), bool(control & 0x40)
    version, dst_mode, src_mode = (control >> 12) & 3, (control >> 10) & 3, (control >> 14) & 3
    if dst_mode == 1 or src_mode == 1 or version == 3:
        return None
    at = 2
    sequence = None
    if not (control & 0x0100 and version == 2):
        if at >= len(data):
            return None
        sequence = data[at]
        at += 1
    if type_ == "other":  # multipurpose and other frame types have a different layout
        return MacFrame(type_, secured, sequence, None, None, None, None, b"")

    try:
        def pan():
            nonlocal at
            if at + 2 > len(data):
                raise IndexError
            v = data[at] | data[at + 1] << 8
            at += 2
            return v

        def address(mode):
            nonlocal at
            if mode == 2:
                if at + 2 > len(data):
                    raise IndexError
                v = f"0x{data[at] | data[at + 1] << 8:04x}"
                at += 2
                return v
            if at + 8 > len(data):
                raise IndexError
            v = eui64(data[at:at + 8])
            at += 8
            return v

        dst_present, src_present = _pans_present(version, dst_mode, src_mode, compressed)
        dst_pan = pan() if dst_present else None
        dst = address(dst_mode) if dst_mode else None
        # A compressed source shares the destination's PAN.
        src_pan = pan() if src_present else (dst_pan if src_mode and compressed else None)
        src = address(src_mode) if src_mode else None
    except IndexError:
        return None
    sec_level = key_mode = None
    if secured and at < len(data):  # auxiliary security header: control (level, key mode), frame counter, key identifier
        control_byte = data[at]
        sec_level, key_mode = control_byte & 7, (control_byte >> 3) & 3
        suppressed = version == 2 and control_byte & 0x20          # 2015 revision: the frame counter may be left out
        aux = 1 + (0 if suppressed else 4) + (0, 1, 5, 9)[key_mode]
        if at + aux <= len(data):
            at += aux
    return MacFrame(type_, secured, sequence, dst_pan, dst, src_pan, src, bytes(data[at:]), sec_level, key_mode)


ROLE_POLLS, ROLE_PARENT, ROLE_RELAYS, ROLE_BEACONS, ROLE_ROUTER_BROADCAST = 1, 2, 4, 8, 16
# Seen since release 32; sent apart from the five above (in "more"), so a server that only knows those still takes them.
ROLE_MLE_ROUTER, ROLE_GREEN_POWER, ROLE_GP_SWITCH = 32, 64, 128
ROLE_WIRE_MASK = 31
ROUTER_MASK = ROLE_PARENT | ROLE_RELAYS | ROLE_BEACONS | ROLE_ROUTER_BROADCAST | ROLE_MLE_ROUTER
ROLE_LABELS = ((ROLE_POLLS, "polls a parent"), (ROLE_PARENT, "serves end devices (answers their polls or join requests)"), (ROLE_RELAYS, "relays frames of others"),
               (ROLE_BEACONS, "sends beacons"), (ROLE_ROUTER_BROADCAST, "broadcasts to all routers"),
               (ROLE_MLE_ROUTER, "advertises itself to its neighbours (Thread routers do)"),
               (ROLE_GREEN_POWER, "sends Zigbee Green Power frames"), (ROLE_GP_SWITCH, "sends switch commands (on, off, scenes, dimming)"))


def role_of(roles):
    """What the observed behaviour says a radio is: "green power" (a battery-less Zigbee Green Power device), "router" (relays, beacons,
    answers polls, broadcasts to routers or advertises as a Thread router), "end device" (only polls a parent: a sleepy device), or
    None. A router does not poll, so any router behaviour wins."""
    if not roles:
        return None
    if roles & ROLE_GREEN_POWER:
        return "green power"
    if roles & ROUTER_MASK:
        return "router"
    return "end device" if roles & ROLE_POLLS else None


# The join request (MAC command 1, "association request") is not encrypted in Zigbee and carries one byte about the device.
CAP_FFD, CAP_MAINS, CAP_RX_IDLE = 0x02, 0x04, 0x08


def parse_assoc(mac):
    """The capability byte of an association request, or None: bit 1 full-function device (can route), bit 2 mains powered,
    bit 3 receiver on while idle (not sleepy). IEEE 802.15.4-2006, 7.3.1.2."""
    if mac.type == "command" and not mac.secured and len(mac.payload) == 2 and mac.payload[0] == 1:
        return mac.payload[1]
    return None


def capability_labels(caps):
    """What a join request said, in words: ["mains powered", "always listening", "can route"] or ["battery powered", "sleeps between messages"]."""
    if caps is None:
        return []
    return ["mains powered" if caps & CAP_MAINS else "battery powered",
            "always listening" if caps & CAP_RX_IDLE else "sleeps between messages",
            "full-function device (can route)" if caps & CAP_FFD else "reduced-function device (cannot route)"]


# Thread routers announce themselves with MLE advertisements: UDP port 19788 to the link-local all-nodes address, hop limit 255.
# The MLE message is secured inside its UDP payload, not at the MAC layer, so the compressed IPv6 and UDP headers are readable:
# IPHC 7f 3b (traffic class and flow elided, next header compressed, hop limit 255, source from the MAC address, multicast
# ff02::00xx in one byte), that byte (01 = all nodes), then the UDP header f0 with both ports (4d4c = 19788) inline.
MLE_ALL_NODES = bytes.fromhex("7f3b01f04d4c4d4c")


def is_mle_advertisement(mac):
    return mac.type == "data" and not mac.secured and mac.payload[:8] == MLE_ALL_NODES


GP_SWITCH_COMMANDS = range(0x10, 0x70)   # scenes 0x10-0x1f, off/on/toggle 0x20-0x22, level 0x30-0x38, colour 0x40-0x4b, press/release 0x60-0x6a


def parse_gp(p):
    """A Zigbee Green Power frame (the stub that battery-less switches and sensors send): {"src": 32-bit source ID or None,
    "to_device": bool, "command": the command byte when it is readable, else None}, or None if `p` is not one.
    Layout (Zigbee PRO Green Power, A.1.4.1): frame control (type in bits 0-1, protocol version 3 in bits 2-5, bit 7 = an extended
    frame control follows: application ID in bits 0-2, security level in bits 3-4, bit 7 = direction), the source ID (application
    ID 0), a 4-byte frame counter from security level 2, then the command (in the clear up to level 2; level 3 encrypts it)."""
    if len(p) < 2 or (p[0] >> 2) & 15 != 3 or p[0] & 3 > 1:
        return None
    at, app, level, to_device = 1, 0, 0, False
    if p[0] & 0x80:
        app, level, to_device, at = p[1] & 7, (p[1] >> 3) & 3, bool(p[1] & 0x80), 2
    if app not in (0, 2):
        return None
    src = None
    if app == 0 and (p[0] & 3 == 0 or p[0] & 0x80):
        if at + 4 > len(p):
            return None
        src, at = int.from_bytes(p[at:at + 4], "little"), at + 4
    elif app == 2:
        at += 1   # endpoint; the device is the MAC source address
    if level >= 2:
        at += 4
    command = p[at] if level < 3 and at < len(p) else None
    return {"src": src, "to_device": to_device, "command": command}


def parse_nwk(p):
    """The Zigbee network header (it is not encrypted; the payload after it is): {"type", "dst", "src", "radius", "eui", "dst_eui", "src_eui"}
    or None. eui is the sender's 64-bit address when the security header (which carries it in the clear) is present."""
    if len(p) < 8 or p[0] & 3 > 1 or (p[0] >> 2) & 15 != 2:
        return None
    fc = p[0] | p[1] << 8
    dst, src, radius = p[2] | p[3] << 8, p[4] | p[5] << 8, p[6]
    at = 8   # frame control, destination, source, radius, sequence
    dst_eui = src_eui = eui = None
    if fc & 0x0800:   # destination IEEE address present
        if at + 8 > len(p):
            return None
        dst_eui, at = eui64(p[at:at + 8]), at + 8
    if fc & 0x1000:   # source IEEE address present
        if at + 8 > len(p):
            return None
        src_eui, at = eui64(p[at:at + 8]), at + 8
    if fc & 0x0100:   # multicast control
        at += 1
    if fc & 0x0400:   # source route subframe: relay count, relay index, relay list
        if at + 2 > len(p):
            return None
        at += 2 + 2 * p[at]
    if fc & 0x0200 and at + 14 <= len(p):   # auxiliary security header: control, frame counter, extended source, key sequence
        if p[at] & 0x20:
            eui = eui64(p[at + 5:at + 13])
    return {"type": "command" if p[0] & 3 else "data", "dst": dst, "src": src, "radius": radius, "eui": eui or src_eui, "dst_eui": dst_eui}


def is_broadcast(address):
    return address is not None and address.startswith("0x") and int(address, 16) >= 0xFFFC


class FrameBatch:
    """Sums captured frames into per-channel counts and per-radio records, so a busy channel sends one compact
    observation every few seconds rather than one per frame."""
    MAX_RADIOS = 2000

    def __init__(self):
        self.clear()

    MAX_NETWORKS = 64

    def clear(self):
        self.channels = {}
        self.radios = {}
        self.threads = {}   # (pan, extended PAN ID, channel) -> a Thread network announced in a beacon
        self.detail = {}    # (pan, address) -> {"roles": bit mask, "eui": 64-bit address learned from the network header, "caps": join request byte}
        self.frames = self.undecoded = 0

    def add(self, captured):
        self.frames += 1
        ch = captured["channel"]
        self.channels[ch] = self.channels.get(ch, 0) + 1
        mac = parse_mac(captured["data"])
        if mac is None:
            self.undecoded += 1
            return
        if mac.type == "beacon":
            tb = parse_thread_beacon(mac.payload)
            pan = mac.src_pan if mac.src_pan is not None else mac.dst_pan
            if tb and pan is not None and len(self.threads) < self.MAX_NETWORKS:
                self.threads[(pan, tb["ext_pan"], captured["channel"])] = {**tb, "pan": pan, "channel": captured["channel"],
                                                                         "rssi": captured["rssi"], "lqi": captured["lqi"]}
        self._behaviour(mac)
        gp = parse_gp(mac.payload) if mac.type == "data" and not mac.secured else None
        if gp and not gp["to_device"]:
            self._green_power(mac, gp, captured)
        if mac.src:
            self._record(mac.src_pan if mac.src_pan is not None else mac.dst_pan, mac.src, mac, captured, True)
        if mac.dst and not is_broadcast(mac.dst):
            self._record(mac.dst_pan if mac.dst_pan is not None else mac.src_pan, mac.dst, mac, captured, False)

    def _detail(self, pan, address):
        k = (pan if pan is not None else -1, address)
        d = self.detail.get(k)
        if d is None and len(self.detail) < self.MAX_RADIOS:
            d = self.detail[k] = {"roles": 0, "eui": None, "caps": None}
        return d

    def _green_power(self, mac, gp, captured):
        """A Green Power device usually sends without a MAC source address: it is known by its 32-bit source ID, shown as gpd:xxxxxxxx."""
        pan = mac.dst_pan if mac.dst_pan not in (None, 0xFFFF) else mac.src_pan if mac.src_pan not in (None, 0xFFFF) else None
        if mac.dst != "0xffff":   # these devices cannot listen first, so they broadcast
            return
        if gp["src"] and mac.src is None:
            address = f"gpd:{gp['src']:08x}"
            self._record(pan, address, mac, captured, True)
        elif gp["src"] is None and mac.src and not mac.src.startswith("0x"):   # application ID 2: known by its 64-bit address
            address = mac.src
        else:
            return
        d = self._detail(pan, address)
        if d:
            d["roles"] |= ROLE_GREEN_POWER | (ROLE_GP_SWITCH if gp["command"] in GP_SWITCH_COMMANDS else 0)

    def _behaviour(self, mac):
        """What a radio's frames say about its role: who polls (end devices ask their parent for waiting data), who relays others' frames,
        who sends beacons, and (Zigbee) each sender's 64-bit address from the network header. Payloads stay encrypted; this reads headers."""
        pan = mac.src_pan if mac.src_pan is not None else mac.dst_pan
        if mac.src is None:
            return
        if mac.type == "beacon":
            d = self._detail(pan, mac.src)
            if d:
                d["roles"] |= ROLE_BEACONS
        elif parse_assoc(mac) is not None:
            d = self._detail(pan, mac.src)
            if d:
                d["caps"] = parse_assoc(mac)
            if mac.dst and not is_broadcast(mac.dst):   # the radio a device asks to join through is a router (or the coordinator)
                d = self._detail(pan, mac.dst)
                if d:
                    d["roles"] |= ROLE_PARENT
        elif is_mle_advertisement(mac):
            d = self._detail(pan, mac.src)
            if d:
                d["roles"] |= ROLE_MLE_ROUTER
        elif mac.type == "command" and mac.payload:
            # the data request is command 4; with Thread's encryption the identifier is hidden, but such a frame is then 5 bytes (1 + 4 byte MIC)
            poll = (not mac.secured and mac.payload[0] == 4) or (mac.secured and mac.sec_level == 5 and len(mac.payload) == 5 and mac.hint == HINT_THREAD)
            if poll:
                d = self._detail(pan, mac.src)
                if d:
                    d["roles"] |= ROLE_POLLS
                if mac.dst and not is_broadcast(mac.dst):
                    d = self._detail(pan, mac.dst)
                    if d:
                        d["roles"] |= ROLE_PARENT
        elif mac.type == "data" and mac.hint == HINT_ZIGBEE:
            n = parse_nwk(mac.payload)
            if not n:
                return
            origin = f"0x{n['src']:04x}"
            if mac.src != origin and mac.src.startswith("0x"):   # the last hop is not the originator: it forwards, so it is a router
                d = self._detail(pan, mac.src)
                if d:
                    d["roles"] |= ROLE_RELAYS
            if n["dst"] == 0xFFFC:
                d = self._detail(pan, origin)
                if d:
                    d["roles"] |= ROLE_ROUTER_BROADCAST
            if n["eui"] and not int(n["eui"][:2], 16) & 1:
                d = self._detail(pan, origin)
                if d:
                    d["eui"] = n["eui"]

    def _record(self, pan, address, mac, captured, sent):
        key = (pan if pan is not None else -1, address)
        r = self.radios.get(key)
        if r is None:
            if len(self.radios) >= self.MAX_RADIOS:
                return
            r = self.radios[key] = {"channels": 0, "sent": 0, "received": 0, "encrypted": 0, "hint": 0, "types": 0,
                                    "rssi": None, "lqi": None}
        r["channels"] |= 1 << captured["channel"]
        r["types"] |= 1 << TYPE_NAMES.index(mac.type)
        r["hint"] = max(r["hint"], mac.hint)
        if sent:
            r["sent"] += 1
            r["encrypted"] += 1 if mac.secured else 0
            # Signal readings only mean something for the radio that transmitted.
            r["rssi"], r["lqi"] = captured["rssi"], captured["lqi"]
        else:
            r["received"] += 1

    def drain(self, ts):
        """The observation for everything since the last drain, or None if nothing was heard."""
        if not self.frames:
            return None
        o = {"t": "zb_frames", "ts": ts, "mac": "-", "undecoded": self.undecoded,
             "channels": {str(c): n for c, n in self.channels.items()},
             "radios": [[pan, addr, r["channels"], r["sent"], r["received"], r["encrypted"], r["hint"], r["types"],
                         r["rssi"], r["lqi"]] for (pan, addr), r in self.radios.items()]}
        if self.threads:
            o["networks"] = list(self.threads.values())
        detail = [[pan, addr, d["roles"] & ROLE_WIRE_MASK, d["eui"]] for (pan, addr), d in self.detail.items() if d["roles"] & ROLE_WIRE_MASK or d["eui"]]
        if detail:
            o["detail"] = detail
        more = [[pan, addr, d["roles"] & ~ROLE_WIRE_MASK, d["caps"]] for (pan, addr), d in self.detail.items()
                if d["roles"] & ~ROLE_WIRE_MASK or d["caps"] is not None]
        if more:   # roles and join capabilities known since release 32
            o["more"] = more
        self.clear()
        return o
