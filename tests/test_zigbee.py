"""Zigbee / 802.15.4. Expected wire bytes were computed separately, following zigpy-znp and bellows."""
import queue
import threading
import time

import pytest

from sniffowireless import sanitize, status
from sniffowireless.config import Config, zigbee_channels
from sniffowireless.main import build
from sniffowireless.zigbee import ZigbeeSensor
from sniffowireless.zigbee_radio import (ALL_CHANNELS_MASK, HINT_ENCRYPTED, HINT_THREAD, HINT_UNKNOWN, HINT_ZIGBEE, AshParser,
                                         EzspDriver, FrameBatch, NoCaptureMode, ZigbeeError, ZnpDriver, ZnpParser, ash_ack,
                                         ash_data, ash_decode, ash_nak, ash_reset, ash_wire, detect, ezsp_decode, ezsp_encode,
                                         parse_beacons, parse_captured, parse_mac, parse_network_found, znp_encode)


def h(text):
    return bytes.fromhex(text)


BEACON_COORDINATOR = h("0000 3412 0F 00 01 01 02 02 96 00 05 8877665544332211")
BEACON_ROUTER = h("CDAB 3412 0F 01 01 01 02 02 DC 01 05 8877665544332211")
BEACON_NEIGHBOUR = h("0000 CDAB 14 00 00 00 02 02 28 00 00 01EFCDAB90785634")
NETWORK_HOME = h("0F 3412 8877665544332211 01 02 05 C8 C4")
NETWORK_NEIGHBOUR = h("14 CDAB 01EFCDAB90785634 00 02 00 28 A6")
FRAME_ZIGBEE_DATA = h("4188 2A 3412 FFFF 0000 0802 FDFF 0000 1E7B")
FRAME_ZIGBEE_BEACON = h("0080 2B 3412 0000 FFCF 00 00 00 2284 1122334455667788")
FRAME_ENCRYPTED = h("69D8 11 CDAB 0100 0807060504030201 0500000000 AABBCCDD")
FRAME_ACK = h("0200 2A")
CAPTURES = {15: [FRAME_ZIGBEE_BEACON, FRAME_ZIGBEE_DATA, FRAME_ACK], 20: [FRAME_ENCRYPTED, FRAME_ENCRYPTED, h("FF")]}


class SimLink:
    """Delivers replies in small chunks, like a real serial port splits them up."""

    def __init__(self):
        self.out = queue.Queue()
        self.pin_changes = 0

    def send(self, data):
        for b in data:
            self.out.put(b)

    def read(self, timeout):
        try:
            data = bytearray([self.out.get(timeout=timeout)])
        except queue.Empty:
            return b""
        while len(data) < 7:
            try:
                data.append(self.out.get_nowait())
            except queue.Empty:
                break
        return bytes(data)

    def set_pins(self, dtr, rts):
        self.pin_changes += 1

    def write(self, data):
        pass

    def close(self):
        pass


class SimZnp(SimLink):
    def __init__(self, channels=ALL_CHANNELS_MASK, scan_status=0):
        super().__init__()
        self.parser, self.channels, self.scan_status, self.received = ZnpParser(), channels, scan_status, []

    def write(self, data):
        for cmd0, cmd1, _ in self.parser.feed(data):
            self.received.append((cmd0, cmd1))
            if (cmd0, cmd1) == (0x21, 1):
                self.send(znp_encode(0x61, 1, h("D907")))
            elif (cmd0, cmd1) == (0x21, 2):
                self.send(znp_encode(0x61, 2, h("0201020701 9B953401 00")))
            elif (cmd0, cmd1) == (0x21, 8):
                self.send(znp_encode(0x61, 8, bytes([0, 4]) + self.channels.to_bytes(4, "little")))
            elif (cmd0, cmd1) == (0x25, 0x26):
                self.send(znp_encode(0x65, 0x26, bytes([self.scan_status])))
                if self.scan_status == 0:
                    self.send(znp_encode(0x45, 0xC5, b"\x02" + BEACON_COORDINATOR + BEACON_ROUTER))
                    self.send(znp_encode(0x45, 0xC5, b"\x01" + BEACON_NEIGHBOUR))
                    self.send(znp_encode(0x45, 0xC7, b"\x00"))


class SimEzsp(SimLink):
    def __init__(self, version=13, drop=0, capture=True, scan_status=0):
        super().__init__()
        self.version, self.drop, self.capture, self.scan_status = version, drop, capture, scan_status
        self.status_bytes = 4 if version >= 14 else 1
        self.parser = AshParser()
        self.tx = self.rx = self.resets = self.retransmissions = 0
        self.received = []

    def write(self, data):
        if data[:1] == b"\x1a":  # the cancel bytes are only sent with a reset
            self.tx = self.rx = 0
            self.resets += 1
            self.send(ash_wire(h("C1 02 0B")))
            return
        for f in self.parser.feed(data)[0]:
            if f[0] != "data":
                continue
            if self.drop:
                self.drop -= 1
                continue
            self.retransmissions += 1 if f[2] else 0
            self.rx = (f[1] + 1) % 8
            self.send(ash_ack(self.rx))
            self._command(f[4])

    def _command(self, payload):
        fmt = 8 if len(payload) >= 5 and payload[2] == 1 else 5 if len(payload) >= 5 and payload[2] == 0xFF else 4
        seq, frame_id, p = ezsp_decode(fmt, payload)
        self.received.append(frame_id)

        def reply(i, params):
            self.send(ash_data(self.tx, False, self.rx, ezsp_encode(fmt, seq, i, params)))
            self.tx = (self.tx + 1) % 8

        ok = bytes(self.status_bytes)
        if frame_id == 0x00:
            reply(0, bytes([self.version, 2]) + h("3074"))
        elif frame_id == 0x1A:
            reply(0x1A, bytes([self.scan_status]) + bytes(self.status_bytes - 1))
            if self.scan_status:
                return
            if p[0] == 0:
                for ch in range(11, 27):
                    reply(0x48, bytes([ch, (-90 + ch) & 0xFF]))
            else:
                reply(0x1B, NETWORK_HOME)
                reply(0x1B, NETWORK_NEIGHBOUR)
            reply(0x1C, b"\0\0")
        elif frame_id in (0x83, 0x84) and self.capture:
            reply(frame_id, ok)
        elif frame_id == 0x8A:
            reply(0x8A, ok)
            for frame in CAPTURES.get(p[0], []):  # lqi, rssi, length, frame, then the filler real firmware appends
                reply(0x8E, bytes([0xC8, -58 & 0xFF, len(frame) + 2]) + frame + b"\x7f\x00")
        else:
            reply(0x58, b"\x31")


# ---------------------------------------------------------------------------- wire formats
def test_znp_frames_match_reference():
    assert znp_encode(0x21, 1) == h("FE 00 21 01 20")
    assert znp_encode(0x21, 2) == h("FE 00 21 02 23")
    assert znp_encode(0x21, 8, h("840000")) == h("FE 03 21 08 84 00 00 AE")
    assert znp_encode(0x25, 0x26, h("00F8FF0704")) == h("FE 05 25 26 00 F8 FF 07 04 02")


def test_znp_parser_reassembles_and_skips_garbage():
    good = znp_encode(0x61, 1, h("D907"))
    corrupt = bytearray(znp_encode(0x61, 2, h("0102")))
    corrupt[-1] = 0
    p = ZnpParser()
    frames = [f for b in h("007E11") + bytes(corrupt) + good for f in p.feed(bytes([b]))]
    assert frames == [(0x61, 1, h("D907"))]


def test_beacon_fields():
    n = parse_beacons(b"\x01" + BEACON_ROUTER)[0]
    assert n["ext_pan"] == "11:22:33:44:55:66:77:88" and n["pan"] == 0x1234 and n["channel"] == 15
    assert n["permit_join"] and n["lqi"] == 220 and n["update_id"] == 5 and n["routers"] == [0xABCD]
    assert parse_beacons(h("03 0000 34")) == [] and parse_beacons(b"") == []


def test_ash_frames_match_reference():
    assert ash_reset() == b"\x1a" * 32 + h("C0 38 BC 7E")
    assert ash_wire(h("C1 02 0B")) == h("C1 02 0B 0A 52 7E")
    assert ash_ack(3) == h("83 40 1B 7E") and ash_nak(1) == h("A1 44 3B 7E")
    assert ash_data(0, False, 0, h("00000004")) == h("00 42 21 A8 50 ED 2C 7E")
    assert ash_data(2, False, 1, h("0500011A000100F8FF0704")) == h("21 47 21 A9 4E 2A 14 B2 A1 6B 4D 21 33 F4 7E")
    assert ash_data(5, True, 4, h("7E117D13181AFF00")) == h("5C 3C 30 D5 47 32 0F 4D 59 63 56 7E")


def test_ash_round_trips_every_byte_value():
    p = AshParser()
    payload = bytes(range(200))
    wire = ash_data(3, False, 6, payload) + ash_data(4, True, 7, bytes(255 - i for i in range(200)))
    frames = [f for b in wire for f in p.feed(bytes([b]))[0]]
    assert frames[0] == ("data", 3, False, 6, payload) and frames[1][2] is True


def test_ash_parser_reports_damage_and_honours_cancel_and_substitute():
    p = AshParser()
    damaged = bytearray(ash_data(0, False, 0, h("010203")))
    damaged[1] = (damaged[1] + 1) & 0xFF
    assert p.feed(bytes(damaged))[1] == 1
    assert p.feed(h("0506 1A") + ash_ack(1))[1] == 0
    assert p.feed(h("05 18 06") + ash_ack(2))[0] == []
    assert p.feed(ash_ack(3))[0] == [("ack", 3)]
    assert ash_decode(h("80")) is None


def test_ezsp_headers_follow_version():
    assert ezsp_encode(4, 7, 0x1A, h("09")) == h("07 00 1A 09")
    assert ezsp_encode(7, 7, 0x1A, h("09")) == h("07 00 FF 00 1A 09")
    assert ezsp_encode(13, 7, 0x1A, h("09")) == h("07 00 01 1A 00 09")
    assert ezsp_decode(4, h("07 80 1A 09"))[1] == 0x1A
    assert ezsp_decode(7, h("07 80 FF 00 1A 09"))[1] == 0x1A
    assert ezsp_decode(13, h("07 80 01 1A 00 09"))[1] == 0x1A
    assert ezsp_decode(13, h("07 80")) is None


def test_network_found_and_captured_frame_fields():
    n = parse_network_found(NETWORK_HOME)
    assert (n["ext_pan"], n["pan"], n["channel"], n["permit_join"], n["lqi"], n["rssi"]) == \
        ("11:22:33:44:55:66:77:88", 0x1234, 15, True, 200, -60)
    assert parse_network_found(bytes(15)) is None
    c = parse_captured(15, bytes([200, -58 & 0xFF, 5]) + h("020001") + h("7F00"))
    assert c == {"channel": 15, "lqi": 200, "rssi": -58, "data": h("020001")}


# ---------------------------------------------------------------------------- 802.15.4
def test_mac_zigbee_data_shares_one_pan():
    f = parse_mac(FRAME_ZIGBEE_DATA)
    assert (f.type, f.secured, f.sequence, f.dst_pan, f.src_pan, f.dst, f.src) == \
        ("data", False, 0x2A, 0x1234, 0x1234, "0xffff", "0x0000")
    assert f.hint == HINT_ZIGBEE


def test_mac_beacon_payload_reveals_protocol():
    assert parse_mac(FRAME_ZIGBEE_BEACON).hint == HINT_ZIGBEE
    assert parse_mac(h("0080 2B 3412 0000 FFCF 00 00 03 21")).hint == HINT_THREAD
    assert parse_mac(h("0080 2B 3412 0000 FFCF 00 00 7A 21")).hint == HINT_UNKNOWN


def test_mac_encryption_and_long_addresses():
    f = parse_mac(FRAME_ENCRYPTED)
    assert f.secured and f.src_pan == 0xABCD and f.dst == "0x0001" and f.src == "01:02:03:04:05:06:07:08"
    assert f.hint == HINT_ENCRYPTED


def test_mac_ack_and_beacon_request():
    ack = parse_mac(FRAME_ACK)
    assert ack.type == "ack" and ack.src is None and ack.dst is None
    req = parse_mac(h("0308 05 FFFF FFFF 07"))
    assert req.type == "command" and req.dst_pan == 0xFFFF and req.src is None and req.payload == h("07")


def test_mac_2015_revision_can_omit_sequence_and_pan():
    f = parse_mac(h("41ED 0102030405060708 1112131415161718 AA"))
    assert f.sequence is None and f.dst_pan is None and f.src_pan is None
    assert f.dst == "08:07:06:05:04:03:02:01" and f.src == "18:17:16:15:14:13:12:11" and f.payload == h("AA")


def test_mac_rejects_truncated_and_reserved_frames():
    for bad in ("41", "4188", "4188 2A 34", "4188 2A 3412 FFFF 00", "4184 2A 3412 FFFF 0000"):
        assert parse_mac(h(bad)) is None
    import random
    rng = random.Random(42)
    for _ in range(20000):  # never raises on junk
        f = parse_mac(rng.randbytes(rng.randrange(40)))
        if f:
            f.hint


def captured(data, channel=15, rssi=-60, lqi=200):
    return {"channel": channel, "lqi": lqi, "rssi": rssi, "data": data}


def test_batch_groups_radios():
    b = FrameBatch()
    for c in (captured(FRAME_ZIGBEE_BEACON), captured(FRAME_ZIGBEE_DATA, rssi=-70), captured(FRAME_ACK),
              captured(FRAME_ENCRYPTED, channel=20, rssi=-80), captured(h("FF"), channel=20)):
        b.add(c)
    o = b.drain(1000.0)
    assert o["channels"] == {"15": 3, "20": 2} and o["undecoded"] == 1
    r = {(x[0], x[1]): x for x in o["radios"]}
    assert not any(a == "0xffff" for _, a in r)  # the broadcast address isn't a device
    coord = r[(0x1234, "0x0000")]
    assert coord[3] == 2 and coord[6] == HINT_ZIGBEE and coord[8] == -70
    assert r[(0xABCD, "01:02:03:04:05:06:07:08")][5] == 1
    receiver = r[(0xABCD, "0x0001")]
    assert receiver[3] == 0 and receiver[4] == 1 and receiver[8] is None  # signal readings aren't its own
    assert b.drain(1001.0) is None


def test_batch_stops_growing_at_limit():
    b = FrameBatch()
    b.MAX_RADIOS = 2
    for i in range(1, 6):
        b.add(captured(h(f"4188 01 3412 FFFF 0{i}00")))
    o = b.drain(1.0)
    assert len(o["radios"]) == 2 and o["channels"] == {"15": 5}


# ---------------------------------------------------------------------------- drivers
def test_detects_zstack_and_only_reads():
    link = SimZnp()
    d = detect(link)
    assert isinstance(d, ZnpDriver) and d.firmware == "Z-Stack 2.7.1 (build 20223387)" and not d.can_capture
    nets = []
    d.scan(nets.append, lambda *a: pytest.fail("Z-Stack has no energy scan"))
    assert len(nets) == 3
    assert set(link.received) == {(0x21, 1), (0x21, 2), (0x21, 8), (0x25, 0x26)}  # no NV write (0x09) or reset


def test_zstack_warns_about_limited_channels_and_reports_refusal():
    assert any("channel 15" in n for n in ZnpDriver.connect(SimZnp(channels=1 << 15), 1).notes)
    with pytest.raises(ZigbeeError):
        ZnpDriver.connect(SimZnp(scan_status=1), 1).scan(print, print)


def test_detects_ezsp_without_touching_reset_lines():
    link = SimEzsp()
    d = detect(link)
    assert isinstance(d, EzspDriver) and d.firmware == "EmberZNet 7.4.3.0 (EZSP v13)"
    assert link.pin_changes == 0  # DTR and RTS drive the ZBDongle-E's reset and boot pins


def test_unrecognised_stick_is_reported():
    assert detect(SimLink()) is None


@pytest.mark.parametrize("version", [4, 7, 8, 13, 14, 19])
def test_ezsp_scan_across_versions(version):
    d = EzspDriver.connect(SimEzsp(version=version), 1)
    nets, energy = [], []
    d.scan(nets.append, lambda c, r: energy.append((c, r)))
    assert f"EZSP v{version}" in d.firmware
    assert len(nets) == 2 and nets[0]["rssi"] == -60
    assert [c for c, _ in energy] == list(range(11, 27)) and energy[0][1] == -79


def test_ezsp_retransmits_lost_frame():
    link = SimEzsp(drop=1)
    d = EzspDriver.connect(link, 1)
    assert d is not None and link.retransmissions == 1


def test_ezsp_scan_refusal():
    with pytest.raises(ZigbeeError, match="35"):
        EzspDriver.connect(SimEzsp(scan_status=0x35), 1).scan(print, print)


def run_capture(link, channels, seconds):
    d = EzspDriver.connect(link, 1)
    heard, tuned = [], []
    end = time.monotonic() + seconds
    d.capture(channels, 0.1, lambda: time.monotonic() >= end, tuned.append, heard.append)
    return heard, tuned


def test_capture_labels_channels_and_strips_filler():
    heard, tuned = run_capture(SimEzsp(), [15, 20], 0.6)
    first = next(f for f in heard if f["channel"] == 15)
    assert first["data"] == FRAME_ZIGBEE_BEACON and first["lqi"] == 200 and first["rssi"] == -58
    assert any(f["channel"] == 20 and f["data"] == FRAME_ENCRYPTED for f in heard)
    assert tuned[:2] == [15, 20]


def test_capture_never_transmits_and_restarts_stick():
    link = SimEzsp()
    run_capture(link, [15, 20], 0.4)
    # Version, mfglib start, set channel and end. In particular no send packet (0x89), tone or stream.
    assert set(link.received) == {0x00, 0x83, 0x8A, 0x84}
    assert link.resets == 2


def test_capture_stays_on_one_channel_without_retuning():
    link = SimEzsp()
    run_capture(link, [15], 0.4)
    assert link.received.count(0x8A) == 1


def test_firmware_without_capture_mode():
    with pytest.raises(NoCaptureMode):
        run_capture(SimEzsp(capture=False), [15], 0.2)


# ---------------------------------------------------------------------------- sensor -> store -> API
@pytest.fixture
def ctx(tmp_path):
    return build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))


def api(ctx, path="/api/zigbee"):
    from fastapi.testclient import TestClient
    from sniffowireless.web import create_app
    ctx.auth.disabled = True
    return TestClient(create_app(ctx), base_url="http://sniffowireless.test").get(path)


def feed(ctx, *obs):
    for o in obs:
        ctx.store.process(o)
    ctx.store.flush()


def network_obs(raw, ts):
    return {"t": "zb_network", "ts": ts, "mac": "-", **raw}


def test_store_merges_networks_and_radios(ctx):
    now = time.time()
    beacons = parse_beacons(b"\x02" + BEACON_COORDINATOR + BEACON_ROUTER)
    feed(ctx, *(network_obs(b, now) for b in beacons))
    feed(ctx, network_obs(parse_beacons(b"\x01" + BEACON_COORDINATOR)[0], now + 1))
    feed(ctx, {"t": "zb_energy", "ts": now, "mac": "-", "readings": [[15, -75], [20, -60]]})
    batch = FrameBatch()
    for c in (captured(FRAME_ZIGBEE_DATA), captured(FRAME_ENCRYPTED, channel=20)):
        batch.add(c)
    feed(ctx, batch.drain(now))
    batch.add(captured(FRAME_ZIGBEE_DATA, rssi=-50))
    feed(ctx, batch.drain(now + 2))

    d = api(ctx).json()
    assert d["total_frames"] == 3
    n = d["networks"][0]
    assert n["pan"] == 0x1234 and n["routers"] == [0, 0xABCD] and n["sightings"] == 3
    # Routers add up across scans, but joining and signal describe the latest scan: only the coordinator answered it.
    assert not n["permit_join"] and n["lqi"] == 150
    r = {x["addr"]: x for x in d["radios"]}
    assert r["0x0000"]["sent"] == 2 and r["0x0000"]["rssi"] == -50 and r["0x0000"]["hint"] == "zigbee"
    enc = r["01:02:03:04:05:06:07:08"]
    assert enc["encrypted"] == 1 and enc["channels"] == [20] and enc["hint_label"].startswith("Encrypted")
    ch = {c["channel"]: c for c in d["channels"]}
    assert ch[15]["frames"] == 2 and ch[15]["rssi"] == -75 and ch[20]["rssi"] == -60 and ch[11]["frames"] == 0


def test_prune_removes_old_records(ctx):
    old = time.time() - 40 * 86400
    batch = FrameBatch()
    batch.add(captured(FRAME_ZIGBEE_DATA))
    feed(ctx, batch.drain(old), network_obs(parse_network_found(NETWORK_HOME), old))
    ctx.store.prune(time.time())
    for table in ("zigbee_radios", "zigbee_networks", "zigbee_channels"):
        assert ctx.one(f"SELECT COUNT(*) n FROM {table}")["n"] == 0


def test_api_handles_no_data(ctx):
    d = api(ctx).json()
    assert d["networks"] == [] and d["radios"] == [] and len(d["channels"]) == 16 and d["configured"] is False


def test_remote_observations_are_validated():
    now = time.time()
    clean = sanitize.remote_observation
    good = {"t": "zb_network", "ts": now, "mac": "-", "ext_pan": "11:22:33:44:55:66:77:88", "pan": 0x1234, "channel": 15,
            "permit_join": True, "stack_profile": 2, "update_id": 5, "lqi": 200, "rssi": -60, "routers": [1, 2]}
    assert clean(good, now)["ext_pan"] == good["ext_pan"]
    assert clean({**good, "ext_pan": "<script>"}, now) is None
    assert clean({**good, "channel": 99}, now) is None
    assert clean({"t": "zb_energy", "ts": now, "readings": [[15, -70], [99, -70], "x", [11, "y"]]}, now)["readings"] == [[15, -70]]
    f = clean({"t": "zb_frames", "ts": now, "channels": {"15": 3, "x": 1, "99": 1},
               "radios": [[0x1234, "0x0001", 1 << 15, 1, 0, 0, 3, 2, -60, 200],
                          [0x1234, "<b>", 1 << 15, 1, 0, 0, 3, 2, -60, 200],
                          [0x1234, "01:02:03:04:05:06:07:08", 1 << 15, 1, 0, 0, 9, 2, None, None], "bad"]}, now)
    assert f["channels"] == {"15": 3}
    assert [r[1] for r in f["radios"]] == ["0x0001"]  # the unsafe address and the out-of-range hint are dropped


def test_sensor_sends_scan_and_capture_results_then_stops(ctx):
    cfg = Config(zigbee_channels=[15, 20], zigbee_hop_interval=0.1, zigbee_scan_interval=60)
    sink = []

    class Sink:
        put = staticmethod(sink.append)

    stop = threading.Event()
    link = SimEzsp()
    sensor = ZigbeeSensor("/dev/ttyTEST", cfg, Sink, link_factory=lambda _: link)
    sensor.stop = stop
    thread = threading.Thread(target=sensor.run, args=(link,))
    thread.start()
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and not any(o["t"] == "zb_network" for o in sink):
        time.sleep(0.05)
    time.sleep(1.0)  # long enough to tune to channel 15, where the simulated stick hears frames
    stop.set()
    thread.join(5)
    assert not thread.is_alive()
    kinds = {o["t"] for o in sink}
    assert {"zb_network", "zb_energy", "zb_frames"} <= kinds  # the last batch is reported on the way out
    assert 0x89 not in link.received
    assert any(s["name"] == "zigbee:ttyTEST" and s.get("firmware") for s in status.snapshot())


def test_channel_setting():
    assert zigbee_channels("") == list(range(11, 27))
    assert zigbee_channels("15,20-21,99") == [15, 20, 21]


def test_a_network_gets_no_vendor_guessed_from_its_extended_pan_id(ctx, monkeypatch):
    """The coordinator picks the extended PAN ID, often at random: whatever the vendor database says about its prefix must not name a maker."""
    from sniffowireless.zigbee import ZigbeeMonitor
    monkeypatch.setattr(ctx.store.vendors, "lookup", lambda address: "Texas Instruments")      # a database that knows every prefix
    now = time.time()
    feed(ctx, {"t": "zb_network", "ts": now, "mac": "-", "ext_pan": "00:12:4b:aa:bb:cc:dd:ee", "pan": 0x1234, "channel": 15, "permit_join": False,
               "stack_profile": 2, "update_id": 0, "lqi": 200, "rssi": -50, "routers": []})
    ctx.store.flush()
    assert ctx.one("SELECT vendor FROM zigbee_networks WHERE pan=?", (0x1234,))["vendor"] is None
    mon = ZigbeeMonitor(ctx)                                                                      # what a radio's own addresses still give
    assert mon._vendor(ctx.store, "00:12:4b:aa:bb:cc:dd:ee") == "Texas Instruments"              # a 64-bit IEEE address names the maker
    assert mon._vendor(ctx.store, "0x1234") is None and mon._vendor(ctx.store, "02:12:4b:aa:bb:cc:dd:ee") is None   # short / locally administered: no


def test_a_vendor_stored_by_an_older_version_is_cleared_at_start(ctx):
    from sniffowireless.zigbee import ZigbeeMonitor
    ctx.store.conn.execute("INSERT INTO zigbee_networks(ext_pan, pan, channel, vendor, first_seen, last_seen, sightings) VALUES('00:80:c0:60:b0:e9:71:bd', 1, 25, 'Penril Datacomm', 1, 1, 1)")
    ZigbeeMonitor(ctx)
    assert ctx.one("SELECT vendor FROM zigbee_networks WHERE pan=1")["vendor"] is None
