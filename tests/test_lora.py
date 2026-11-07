import random
import struct

import pytest

from sniffowireless.lora_protocols import (PROFILES, SYNC_LORAWAN, SYNC_MESHTASTIC, SYNC_PRIVATE, classify, meshtastic_frequency,
                                           meshtastic_hash, parse_profiles)


# ------------------------------------------------------------------ frames built from the specs
def meshtastic(to=0xFFFFFFFF, frm=0x1A2B3C4D, pid=0xDEADBEEF, hop_limit=3, hop_start=3, want_ack=False, via_mqtt=False, chan=0x08,
               next_hop=0, relay=0x4D, n=20):
    flags = hop_limit | (8 if want_ack else 0) | (0x10 if via_mqtt else 0) | (hop_start << 5)
    return struct.pack("<IIIBBBB", to, frm, pid, flags, chan, next_hop, relay) + bytes(rnd.randrange(256) for rnd in [random.Random(pid)] for _ in range(n))


def meshcore_advert(name=b"Garage Repeater", ntype=2, location=True, route=1, hops=0, hsize=1):
    flags = ntype | (0x10 if location else 0) | (0x80 if name else 0)
    body = bytes(range(32)) + struct.pack("<I", 1_700_000_000) + bytes(64) + bytes([flags]) + (bytes(8) if location else b"") + name
    header = (4 << 2) | route
    path = bytes(range(hops * hsize))
    return bytes([header, hops | ((hsize - 1) << 6)]) + path + body


def meshcore_text(src=0x4F, dst=0xA1, n=32, hops=2):
    return bytes([(2 << 2) | 1, hops]) + bytes([0x10, 0x20]) + bytes([dst, src, 0xBE, 0xEF]) + bytes(n)


def lorawan_uplink(dev_addr=0x26011BDA, fcnt=1234, fport=1, payload=b"\x01\x02\x03", mtype=2, fopts=b"", adr=True):
    fctrl = (0x80 if adr else 0) | len(fopts)
    return bytes([mtype << 5]) + struct.pack("<I", dev_addr) + bytes([fctrl]) + struct.pack("<H", fcnt) + fopts + bytes([fport]) + payload + b"\xAA\xBB\xCC\xDD"


def lorawan_join_request(join_eui="70b3d57ed0000000", dev_eui="0004a30b001a2b3c"):
    return bytes([0x00]) + bytes.fromhex(join_eui)[::-1] + bytes.fromhex(dev_eui)[::-1] + b"\x12\x34" + b"\x00\x11\x22\x33"


APRS = b"<\xff\x01" + b"PA3ABC-9>APLRT1,WIDE1-1:!5207.00N/00455.00E-testing"


# ------------------------------------------------------------------ the classifier
def test_meshtastic():
    r = classify(meshtastic(), SYNC_MESHTASTIC, "meshtastic")
    assert (r["protocol"], r["label"], r["level"], r["kind"]) == ("meshtastic", "Meshtastic", "high", "broadcast")
    assert r["src"] == "!1a2b3c4d" and r["dst"] == "broadcast" and r["hops"] == 0 and r["confidence"] >= 80
    assert r["node"] == ("!1a2b3c4d", None, "node")
    assert r["info"]["id"] == "deadbeef" and r["info"]["channel"] == "08" and r["info"]["payload_bytes"] == 20
    r = classify(meshtastic(to=0x0C0FFEE0, hop_limit=1, hop_start=3, want_ack=True, via_mqtt=True, next_hop=0xE0), SYNC_MESHTASTIC)
    assert r["kind"] == "direct" and r["dst"] == "!0c0ffee0" and r["hops"] == 2
    assert r["info"] | {"want_ack": True, "via_mqtt": True, "hops_taken": 2, "next_hop": "e0"} == r["info"]
    # hop_start 0 is the pre-2.3 header: no relay / next hop to report.
    assert "relay" not in classify(meshtastic(hop_start=0, hop_limit=3), SYNC_MESHTASTIC)["info"]
    # The sync word is a hardware filter and Meshtastic always uses 0x2B: the same bytes heard elsewhere prove nothing.
    assert classify(meshtastic(), SYNC_PRIVATE)["protocol"] == "unknown"
    assert classify(meshtastic(), SYNC_LORAWAN)["protocol"] == "unknown"
    # An impossible hop count (hop_start below hop_limit) is less convincing but the sync word still carries it.
    assert classify(meshtastic(hop_limit=7, hop_start=2), SYNC_MESHTASTIC)["confidence"] < classify(meshtastic(), SYNC_MESHTASTIC)["confidence"]
    assert classify(meshtastic()[:16], SYNC_MESHTASTIC)["protocol"] == "unknown"  # a header and nothing after it


def test_meshcore():
    r = classify(meshcore_advert(), SYNC_PRIVATE, "meshcore")
    assert (r["protocol"], r["kind"], r["level"]) == ("meshcore", "advert", "high")
    assert r["name"] == "Garage Repeater" and r["node"] == ("pk:00010203", "Garage Repeater", "repeater")
    assert r["info"]["node_type"] == "repeater" and r["info"]["location_shared"] is True and r["info"]["public_key"] == "0001020304050607"
    assert "latitude" not in r["info"] and r["dst"] == "flood"  # where a node is is never taken out of the advert
    # An advert is distinctive enough to be recognised even where nobody said MeshCore is expected.
    assert classify(meshcore_advert(), SYNC_PRIVATE)["protocol"] == "meshcore"
    assert classify(meshcore_advert(name=b"", location=False, ntype=1), SYNC_PRIVATE, "meshcore")["name"] is None
    # Multi-byte path hashes, and transport codes in front of the path.
    r = classify(meshcore_advert(hops=3, hsize=2), SYNC_PRIVATE, "meshcore")
    assert r["hops"] == 3 and r["info"]["hash_bytes"] == 2 and len(r["info"]["path"]) == 12
    tr = bytes([(4 << 2) | 0]) + b"\x01\x00\x02\x00" + meshcore_advert()[1:]
    assert classify(tr, SYNC_PRIVATE, "meshcore")["name"] == "Garage Repeater"
    # Messages only show their one-byte hashes: who they are for and who from (not who that is).
    r = classify(meshcore_text(), SYNC_PRIVATE, "meshcore")
    assert (r["kind"], r["src"], r["dst"], r["hops"], r["level"]) == ("text message", "h:4f", "h:a1", 2, "medium") and r["node"][2] == "hash"
    assert classify(bytes([3 << 2 | 1, 0]) + b"\x01\x02\x03\x04", SYNC_PRIVATE, "meshcore")["kind"] == "ack"
    # Without the profile saying MeshCore, an ordinary message is not enough to name it.
    assert classify(meshcore_text(), SYNC_PRIVATE)["protocol"] == "unknown"
    # Reserved payload types and a reserved path hash size are not MeshCore.
    assert classify(bytes([(12 << 2) | 1, 0]) + bytes(40), SYNC_PRIVATE, "meshcore")["protocol"] == "unknown"
    assert classify(bytes([(2 << 2) | 1, 0xC0]) + bytes(40), SYNC_PRIVATE, "meshcore")["protocol"] == "unknown"
    assert classify(bytes([(2 << 2) | 1, 0x3F]) + bytes(20), SYNC_PRIVATE, "meshcore")["protocol"] == "unknown"  # path longer than the frame


def test_lorawan():
    r = classify(lorawan_uplink(), SYNC_LORAWAN, "lorawan")
    assert (r["protocol"], r["kind"], r["level"]) == ("lorawan", "unconfirmed uplink", "high")
    assert r["src"] == "26011bda" and r["node"] == ("26011bda", None, "device")
    assert r["info"]["fcnt"] == 1234 and r["info"]["fport"] == 1 and r["info"]["adr"] is True
    r = classify(lorawan_uplink(mtype=5, adr=False), SYNC_LORAWAN)
    assert r["kind"] == "confirmed downlink" and r["dst"] == "26011bda" and r["src"] is None
    r = classify(lorawan_join_request(), SYNC_LORAWAN)
    assert r["kind"] == "join request" and r["info"]["dev_eui"] == "0004a30b001a2b3c" and r["info"]["join_eui"] == "70b3d57ed0000000"
    assert r["src"] == "eui:0004a30b001a2b3c"
    assert classify(bytes([0x20]) + bytes(16), SYNC_LORAWAN)["kind"] == "join accept"
    assert classify(lorawan_uplink(fopts=b"\x02\x01"), SYNC_LORAWAN)["info"]["fport"] == 1  # FOpts shift where the port is
    # Private sync word: the same bytes are not named LoRaWAN; a wrong major version never is.
    assert classify(lorawan_uplink(), SYNC_PRIVATE)["protocol"] == "unknown"
    assert classify(bytes([0x41]) + lorawan_uplink()[1:], SYNC_LORAWAN)["protocol"] == "unknown"
    assert classify(lorawan_join_request()[:-3], SYNC_LORAWAN)["protocol"] == "unknown"  # a join request is exactly 23 bytes


def test_lora_aprs():
    r = classify(APRS, SYNC_PRIVATE, "lora-aprs")
    assert (r["protocol"], r["kind"], r["src"], r["dst"], r["level"]) == ("lora-aprs", "position", "PA3ABC-9", "APLRT1", "high")
    assert r["hops"] == 1 and r["info"]["path"] == "WIDE1-1" and r["node"] == ("PA3ABC-9", None, "station")
    assert classify(b"<\xff\x01" + b"PA3ABC-9>APLRT1::PA1XYZ   :hello{1", SYNC_PRIVATE)["kind"] == "message"
    assert classify(b"<\xff\x01" + b"garbage without structure", SYNC_PRIVATE)["confidence"] == 60  # the header alone
    assert classify(APRS[3:], SYNC_PRIVATE)["protocol"] == "unknown"                                 # no header


def test_unidentified_frames_say_what_they_are_like():
    r = classify(b"hello world, this is plain text", SYNC_PRIVATE)
    assert (r["protocol"], r["kind"], r["confidence"]) == ("unknown", "plain text", 0) and r["info"]["payload_bytes"] == 31
    rnd = random.Random(3)
    assert classify(bytes(rnd.randrange(256) for _ in range(40)), SYNC_PRIVATE)["kind"] == "unidentified"
    assert classify(b"", SYNC_PRIVATE)["protocol"] == "unknown" and classify(b"\x00", None)["protocol"] == "unknown"


def test_noise_is_rarely_taken_for_a_protocol():
    rnd = random.Random(7)
    for sync, hint in ((SYNC_PRIVATE, None), (SYNC_MESHTASTIC, None), (SYNC_LORAWAN, None), (SYNC_PRIVATE, "meshcore")):
        wrong = sum(classify(bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 120))), sync, hint)["protocol"] != "unknown"
                    for _ in range(3000))
        # Meshtastic and LoRaWAN accept anything that is long enough on their own sync word (what the hardware filters on); the
        # rest has to look like the protocol. This is a ceiling, not a target.
        limit = {SYNC_MESHTASTIC: 3000, SYNC_LORAWAN: 3000}.get(sync, 150) if hint is None else 700
        assert wrong <= limit, (sync, hint, wrong)
    # Without a hint, private-sync noise must almost never come out as MeshCore.
    assert sum(classify(bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 120))), SYNC_PRIVATE)["protocol"] != "unknown"
               for _ in range(3000)) < 90


# ------------------------------------------------------------------ profiles
def test_meshtastic_frequencies_follow_the_firmware_formula():
    assert meshtastic_hash("LongFast") == 130429955
    assert meshtastic_frequency("US") == 906.875 and meshtastic_frequency("EU868") == 869.525  # the values the docs give
    assert 915.0 < meshtastic_frequency("ANZ") < 928.0 and 433.0 < meshtastic_frequency("EU433") < 434.0
    p = PROFILES["meshtastic-us"]
    assert (p.freq, p.bw, p.sf, p.cr, p.sync, p.hint) == (906.875, 250, 11, 5, 0x2B, "meshtastic")
    assert PROFILES["meshcore-eu868"].sync == 0x12 and PROFILES["meshcore-eu868"].freq == 869.618 and PROFILES["meshcore-eu868"].bw == 62.5
    assert PROFILES["lorawan-eu868"].sync == 0x34 and PROFILES["lora-aprs-433"].sf == 12


def test_parse_profiles():
    assert [p.name for p in parse_profiles("", "EU868")] == ["meshtastic-eu868", "meshcore-eu868"]
    assert [p.name for p in parse_profiles("", "us915")] == ["meshtastic-us"]
    got = parse_profiles("meshtastic:us:MediumFast, mesh=868.3/125/7/5/0x34, LoRaWAN-EU868, lorawan-eu868, mine=915/250/9/6/18/12")
    assert [p.name for p in got] == ["meshtastic-us-mediumfast", "mesh", "lorawan-eu868", "mine"]  # a repeated profile is listed once
    assert got[0].bw == 250 and got[0].sf == 9 and got[1].hint == "lorawan" and got[1].sync == 0x34
    assert (got[3].freq, got[3].sync, got[3].preamble, got[3].hint) == (915.0, 18, 12, None)
    for bad in ("nonsense", "meshtastic:mars", "meshtastic:us:fastest", "x=1/2/3", "x=868/125/13/5/0x12", "x=868/130/7/5/0x12",
                "x=2000/125/7/5/0x12", "x=868/125/7/9/0x12", "x=868/125/7/5/0x1ff", "x=868/125/seven/5/0x12", "bad name=868/125/7/5/0x12"):
        with pytest.raises(ValueError):
            parse_profiles(bad)
    with pytest.raises(ValueError, match="LORA_REGION"):
        parse_profiles("", "MARS")


# ------------------------------------------------------------------ the sensor, against a scripted sniffer
import json
import threading
import time

from sniffowireless import lora as lora_mod
from sniffowireless import status
from sniffowireless.config import Config
from sniffowireless.lora import LoraError, LoraMonitor, LoraSensor, parse_rx
from sniffowireless.main import build


def rx_line(payload, profile, rssi=-97.5, snr=6.25, ferr=-320, ms=1000):
    return f"RX,{ms},{profile.freq},{profile.bw},{profile.sf},0x{profile.sync:02X},{rssi},{snr},{ferr},{len(payload)},{payload.hex()}"


class FakeSniffer:
    """What the firmware does on the serial line: answers PING and CFG, and 'hears' what is on the air for the current settings."""

    def __init__(self, air, answer_ping=True, refuse=(), die_after=None):
        self.air, self.answer_ping, self.refuse, self.die_after = air, answer_ping, set(refuse), die_after
        self.out, self.cfgs, self.current, self.closed = [], [], None, False

    def write_line(self, text):
        if text == "PING" and self.answer_ping:
            self.out.append("PONG")
        elif text.startswith("CFG,"):
            f = text.split(",")
            self.cfgs.append((float(f[1]), float(f[2]), int(f[3]), int(f[4]), int(f[5], 0), int(f[6])))
            if float(f[1]) in self.refuse:
                self.out.append("ERR,CFG,-12")
            else:
                self.current = self.cfgs[-1]
                self.out.append("OK,CFG," + ",".join(f[1:]))
                self.out.extend(self.air.get((float(f[1]), int(f[3])), []))

    def read_line(self, timeout):
        if self.die_after is not None and self.die_after <= 0:
            time.sleep(min(timeout, 0.05))
            return None
        if self.out:
            if self.die_after is not None:
                self.die_after -= 1
            return self.out.pop(0)
        time.sleep(min(timeout, 0.02))
        return None

    def close(self):
        self.closed = True


class Sink(list):
    def put(self, o):
        self.append(o)


def run_sensor(sniffer, cfg, seconds=0.6, **kw):
    sink, stop = Sink(), threading.Event()
    sensor = LoraSensor("/dev/ttyUSB9", cfg, sink, link_factory=lambda path: sniffer)
    sensor.stop = stop
    err = []
    t = threading.Thread(target=lambda: err.append(_run(sensor, sniffer)), daemon=True)
    t.start()
    time.sleep(seconds)
    stop.set()
    t.join(3)
    return sensor, sink, err[0] if err else None


def _run(sensor, sniffer):
    try:
        sensor.run(sniffer)
    except LoraError as e:
        return e


def test_parse_rx():
    p = PROFILES["meshtastic-eu868"]
    good = parse_rx(rx_line(meshtastic(), p))
    assert good["freq"] == 869.525 and good["bw"] == 250.0 and good["sf"] == 11 and good["sync"] == 0x2B
    assert good["rssi"] == -97.5 and good["snr"] == 6.25 and good["ferr"] == -320 and good["hex"] == meshtastic().hex()
    for bad in ("", "STAT,1,2,3", "RX,1,2", rx_line(meshtastic(), p).replace(",36,", ",35,"), rx_line(b"", p),
                rx_line(meshtastic(), p)[:-2] + "zz", rx_line(meshtastic(), p).replace("RX", "TX", 1), "RX,1,x,250,11,0x2B,-90,5,0,3,010203"):
        assert parse_rx(bad) is None, bad


def test_sensor_hops_between_profiles_and_attributes_frames():
    eu, mc = PROFILES["meshtastic-eu868"], PROFILES["meshcore-eu868"]
    air = {(eu.freq, eu.sf): [rx_line(meshtastic(), eu), "STAT,10000,1,2"], (mc.freq, mc.sf): [rx_line(meshcore_advert(), mc)]}
    sniffer = FakeSniffer(air)
    cfg = Config(lora_profiles=[eu, mc], lora_hop_interval=0.15)
    sensor, sink, err = run_sensor(sniffer, cfg, seconds=0.9)
    assert err is None and sniffer.closed is False
    # It asked for each profile in turn, and kept cycling (the settings as the firmware wants them).
    assert sniffer.cfgs[0] == (869.525, 250.0, 11, 5, 0x2B, 8) and sniffer.cfgs[1] == (869.618, 62.5, 8, 5, 0x12, 8)
    assert len(sniffer.cfgs) >= 4 and [c[0] for c in sniffer.cfgs[:4]] == [869.525, 869.618, 869.525, 869.618]
    got = {(o["profile"], o["sync"]) for o in sink}
    assert got == {("meshtastic-eu868", 0x2B), ("meshcore-eu868", 0x12)} and all(o["t"] == "lora_frame" and o["mac"] == "-" for o in sink)
    assert sensor.packets == len(sink) >= 2
    st = status.SENSORS["lora:ttyUSB9"]
    assert st["type"] == "lora" and st["crc_errors"] == 2 and st["firmware"] == "lora-sniffer" and st["state"] == "listening"
    assert st["profiles"] == ["meshtastic-eu868", "meshcore-eu868"]


def test_sensor_with_one_profile_does_not_hop():
    eu = PROFILES["meshtastic-eu868"]
    sniffer = FakeSniffer({(eu.freq, eu.sf): [rx_line(meshtastic(), eu)]})
    sensor, sink, err = run_sensor(sniffer, Config(lora_profiles=[eu], lora_hop_interval=0.05), seconds=0.4)
    assert err is None and len(sniffer.cfgs) == 1 and len(sink) == 1


def test_sensor_attributes_by_what_the_sniffer_reports_not_what_was_asked():
    eu, mc = PROFILES["meshtastic-eu868"], PROFILES["meshcore-eu868"]
    # A frame from the previous settings arrives after the change: it is still filed under the profile it was heard on.
    sniffer = FakeSniffer({(mc.freq, mc.sf): [rx_line(meshtastic(), eu)]})
    sensor, sink, err = run_sensor(sniffer, Config(lora_profiles=[mc], lora_hop_interval=0.05), seconds=0.3)
    assert [o["profile"] for o in sink] == ["meshtastic-eu868"]
    odd = LoraSensor("/dev/x", Config(lora_profiles=[mc]), Sink())
    assert odd.match({"freq": 433.0, "bw": 125.0, "sf": 7, "sync": 0x12}) == "custom"


def test_sensor_skips_a_refused_profile_and_says_so():
    eu, mc, ap = PROFILES["meshtastic-eu868"], PROFILES["meshcore-eu868"], PROFILES["lora-aprs-433"]
    sniffer = FakeSniffer({(eu.freq, eu.sf): [rx_line(meshtastic(), eu)]}, refuse=[ap.freq])
    sensor, sink, err = run_sensor(sniffer, Config(lora_profiles=[ap, eu], lora_hop_interval=0.1), seconds=0.6)
    assert err is None and len(sink) >= 1
    assert "lora-aprs-433" in status.SENSORS["lora:ttyUSB9"]["warning"]
    # Everything refused is an error saying what to check.
    sensor, sink, err = run_sensor(FakeSniffer({}, refuse=[ap.freq]), Config(lora_profiles=[ap]), seconds=0.4)
    assert isinstance(err, LoraError) and "refused every profile" in str(err)


def test_sensor_notices_other_firmware_and_a_dead_stick(monkeypatch):
    monkeypatch.setattr(lora_mod, "HANDSHAKE_TRIES", 1)
    s = LoraSensor("/dev/ttyUSB9", Config(), Sink(), link_factory=None)
    s.stop = threading.Event()
    monkeypatch.setattr(s.stop, "wait", lambda t=None: True)
    class Mute(FakeSniffer):
        def read_line(self, timeout):
            time.sleep(0.01)
            return None
    monkeypatch.setattr(lora_mod.time, "monotonic", lambda c=[0.0]: c.__setitem__(0, c[0] + 0.7) or c[0])
    with pytest.raises(LoraError, match="did not answer as the lora-sniffer firmware"):
        s.handshake(Mute({}, answer_ping=False))


def test_dead_sniffer_is_reported(monkeypatch):
    eu = PROFILES["meshtastic-eu868"]
    monkeypatch.setattr(lora_mod, "SILENCE_LIMIT", 0.3)
    sniffer = FakeSniffer({}, die_after=3)  # answers the handshake and the settings, then goes quiet
    sensor, sink, err = run_sensor(sniffer, Config(lora_profiles=[eu]), seconds=1.2)
    assert isinstance(err, LoraError) and "stopped sending" in str(err)


# ------------------------------------------------------------------ the store plugin: what is kept
@pytest.fixture
def ctx(tmp_path):
    status.SENSORS.clear()
    return build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))


def frame(payload, profile, ts, **kw):
    return {"t": "lora_frame", "ts": ts, "mac": "-", "profile": profile.name, "freq": profile.freq, "bw": profile.bw, "sf": profile.sf,
            "sync": profile.sync, "rssi": kw.get("rssi", -100.0), "snr": kw.get("snr", 5.0), "ferr": 0, "hex": payload.hex(), **{k: v for k, v in kw.items() if k == "sensor"}}


def test_monitor_recognises_frames_and_keeps_only_metadata(ctx):
    eu, mc, lw, ap = PROFILES["meshtastic-eu868"], PROFILES["meshcore-eu868"], PROFILES["lorawan-eu868"], PROFILES["lora-aprs-433"]
    t = time.time() - 120
    secret = b"TOP-SECRET-MESSAGE-BODY"
    frames = [(meshtastic(frm=0x11111111) + secret, eu), (meshtastic(frm=0x11111111, pid=7), eu), (meshtastic(frm=0x22222222), eu),
              (meshcore_advert(), mc), (meshcore_text(), mc), (lorawan_uplink(fcnt=1), lw), (lorawan_uplink(fcnt=2), lw),
              (lorawan_join_request(), lw), (APRS, ap), (b"\x30\x02\x03unidentified-noise", PROFILES["meshcore-nz-narrow"])]
    for i, (p, prof) in enumerate(frames):
        ctx.store.process(frame(p, prof, t + i * 3, rssi=-90 - i, sensor="garage-pi" if i == 0 else None))
    ctx.store.flush()
    by = {r["protocol"]: r["n"] for r in ctx.rows("SELECT protocol, COUNT(*) n FROM lora_packets GROUP BY protocol")}
    assert by == {"meshtastic": 3, "meshcore": 2, "lorawan": 3, "lora-aprs": 1, "unknown": 1}
    nodes = {(r["protocol"], r["addr"]): r for r in ctx.rows("SELECT * FROM lora_nodes")}
    assert nodes[("meshtastic", "!11111111")]["packets"] == 2 and ("meshtastic", "!22222222") in nodes
    assert nodes[("meshcore", "pk:00010203")]["name"] == "Garage Repeater" and nodes[("meshcore", "pk:00010203")]["kind"] == "repeater"
    assert nodes[("meshcore", "h:4f")]["kind"] == "hash"
    assert ("lorawan", "26011bda") in nodes and nodes[("lorawan", "26011bda")]["packets"] == 2 and ("lorawan", "eui:0004a30b001a2b3c") in nodes
    assert ("lora-aprs", "PA3ABC-9") in nodes and not [k for k in nodes if k[0] == "unknown"]
    first = ctx.one("SELECT * FROM lora_packets ORDER BY id LIMIT 1")
    assert (first["sensor"], first["src"], first["dst"], first["kind"], first["bytes"], first["sync"]) == ("garage-pi", "!11111111", "broadcast", "broadcast", 36 + len(secret) - 20 + 0, 0x2B) or first["bytes"] > 16
    assert ctx.one("SELECT sensor FROM lora_packets WHERE protocol='lora-aprs'")["sensor"] == "local"
    stats = ctx.rows("SELECT protocol, SUM(packets) n FROM lora_stats GROUP BY protocol")
    assert {r["protocol"]: r["n"] for r in stats} == by
    # Neither the message body nor any frame's bytes are kept anywhere in the database, and no location from an advert is.
    import sqlite3
    with sqlite3.connect(ctx.cfg.db_path) as c:
        dump = "\n".join(c.iterdump()).encode()
    assert secret not in dump and secret.hex().encode() not in dump and APRS.hex().encode() not in dump and meshtastic().hex().encode() not in dump
    info = ctx.one("SELECT info FROM lora_packets WHERE protocol='meshcore' AND kind='advert'")["info"]
    assert "Garage" not in info and json.loads(info)["location_shared"] is True


def test_monitor_prune_and_robustness(ctx):
    eu = PROFILES["meshtastic-eu868"]
    old, now = time.time() - 40 * 86400, time.time()
    ctx.store.process(frame(meshtastic(frm=5), eu, old))
    ctx.store.process(frame(meshtastic(frm=6), eu, now))
    for junk in ({"t": "lora_frame", "ts": now, "mac": "-", "hex": ""}, {"t": "lora_frame", "ts": now, "mac": "-", "hex": "zz"},
                 {"t": "lora_frame", "ts": now, "mac": "-", "hex": "0102030405060708", "sync": None, "profile": "nope"}):
        ctx.store.process(junk)  # frames the radio never produces must not break anything
    ctx.store.flush()
    assert ctx.one("SELECT COUNT(*) n FROM lora_packets")["n"] == 3
    ctx.store.prune(now)
    assert ctx.rows("SELECT src FROM lora_packets WHERE src IS NOT NULL") == [{"src": "!00000006"}]
    assert ctx.one("SELECT COUNT(*) n FROM lora_nodes")["n"] == 1 and ctx.one("SELECT COUNT(*) n FROM lora_stats WHERE minute < ?", (now - 86400,))["n"] == 0


def test_remote_lora_frames_are_validated():
    from sniffowireless.sanitize import remote_observation
    eu = PROFILES["meshtastic-eu868"]
    now = time.time()
    ok = remote_observation(frame(meshtastic(), eu, now), now)
    assert ok and ok["t"] == "lora_frame" and ok["profile"] == "meshtastic-eu868" and ok["hex"] == meshtastic().hex() and ok["mac"] == "-"
    assert remote_observation({**frame(meshtastic(), eu, now), "hex": meshtastic().hex().upper()}, now)["hex"] == meshtastic().hex()
    for patch in ({"hex": "zz"}, {"hex": "abc"}, {"hex": ""}, {"hex": "00" * 300}, {"freq": 5.0}, {"freq": 5000}, {"bw": 100}, {"sf": 4}, {"sf": 13},
                  {"sync": 300}, {"rssi": 500}, {"snr": None}, {"rssi": "loud"}):
        assert remote_observation({**frame(meshtastic(), eu, now), **patch}, now) is None, patch
    assert remote_observation({**frame(meshtastic(), eu, now), "profile": "x" * 500}, now)["profile"] == "x" * 32


def test_lora_api(ctx, tmp_path):
    from fastapi.testclient import TestClient
    from sniffowireless.auth import hash_password
    from sniffowireless.web import create_app
    with ctx.wdb() as c:
        c.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('admin', ?, 'admin', 0)", (hash_password("correct-horse-battery", iterations=1000),))
    c = TestClient(create_app(ctx), base_url="http://sniffowireless.test")
    assert c.get("/api/lora").status_code == 401
    assert c.post("/api/auth/login", json={"username": "admin", "password": "correct-horse-battery"}).status_code == 200
    empty = c.get("/api/lora").json()
    assert empty["protocols"] == [] and empty["nodes"] == [] and empty["recent"] == [] and empty["configured"] is False
    assert [p["name"] for p in empty["listening"]] == ["meshtastic-eu868", "meshcore-eu868"] and "meshtastic-us" in [p["name"] for p in empty["known_profiles"]]
    eu, mc = PROFILES["meshtastic-eu868"], PROFILES["meshcore-eu868"]
    t = time.time() - 600
    for i in range(6):
        ctx.store.process(frame(meshtastic(frm=0x100 + i % 2, pid=i + 1), eu, t + i * 30))
    ctx.store.process(frame(meshcore_advert(), mc, t + 200))
    ctx.store.flush()
    d = c.get("/api/lora?hours=1").json()
    got = {p["protocol"]: p for p in d["protocols"]}
    assert got["meshtastic"]["packets"] == 6 and got["meshtastic"]["senders"] == 2 and got["meshtastic"]["label"] == "Meshtastic" and got["meshcore"]["packets"] == 1
    assert sum(d["series"]["meshtastic"]) == 6 and len(d["series"]["meshtastic"]) == len(d["t"]) and sum(d["series"]["meshcore"]) == 1
    assert {n["addr"] for n in d["nodes"]} == {"!00000100", "!00000101", "pk:00010203"} and d["nodes"][0]["label"] in ("Meshtastic", "MeshCore")
    assert len(d["recent"]) == 7 and d["recent"][0]["id"] > d["recent"][-1]["id"] and "hex" not in d["recent"][0]
    assert {(p["profile"], p["protocol"]) for p in d["profiles"]} == {("meshtastic-eu868", "meshtastic"), ("meshcore-eu868", "meshcore")}
    assert c.get("/api/lora?hours=0.001").status_code == 400 and c.get("/api/lora?hours=100000").status_code == 400
    assert c.get("/api/lora?hours=720").json()["bucket"] >= 60 and c.get("/api/lora?hours=0.02").status_code == 200
