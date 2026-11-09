"""Choosing the LoRa profiles from the web UI (this server and remote sensors), LoRaWAN coverage, and reading the public Meshtastic channel."""
import json
import struct
import time

import pytest

from sniffowireless import meshtastic as mt
from sniffowireless import status
from sniffowireless.config import Config
from sniffowireless.lora import LoraControl, LoraSensor, clean_override
from sniffowireless.lora_protocols import (LORAWAN_PLANS, PROFILES, SYNC_LORAWAN, SYNC_MESHTASTIC, SYNC_PRIVATE, classify, parse_profiles)

from tests.test_lora import FakeSniffer, ctx, frame, lorawan_join_request, lorawan_uplink, meshtastic  # noqa: F401


# ------------------------------------------------------------------ AES and protobuf
def test_aes_matches_the_standard():
    # FIPS-197 appendix C.1
    assert mt.aes128_encrypt_block(bytes(range(16)), bytes.fromhex("00112233445566778899aabbccddeeff")).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
    # NIST SP 800-38A F.5.1 (CTR-AES128): two blocks
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
    assert mt.aes_ctr(key, iv, pt).hex() == "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
    assert mt.aes_ctr(key, iv, mt.aes_ctr(key, iv, b"any length of data, 37 bytes long!!!")) == b"any length of data, 37 bytes long!!!"


def varint(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def pb(num, value):
    if isinstance(value, int):
        return varint(num << 3) + varint(value)
    if isinstance(value, bytes):
        return varint(num << 3 | 2) + varint(len(value)) + value
    return varint(num << 3 | 5) + struct.pack("<f", value)


def fixed32(num, v):
    return varint(num << 3 | 5) + struct.pack("<i", v)


def data(port, payload):
    return pb(1, port) + pb(2, payload)


def packet(plain, frm=0x1A2B3C4D, pid=0xCAFEF00D, to=0xFFFFFFFF, key=mt.DEFAULT_KEY, chan=0x08):
    body = mt.aes_ctr(key, struct.pack("<QI", pid, frm) + bytes(4), plain) if key else plain
    return struct.pack("<IIIBBBB", to, frm, pid, 3 | (3 << 5), chan, 0, 0x4D) + body


POSITION = fixed32(1, 521234567) + fixed32(2, 49876543) + pb(3, 12) + pb(19, 7) + pb(23, 16)


def test_public_channel_text_position_nodeinfo_telemetry():
    d = mt.decode(packet(data(1, "Hello mesh, test 1 2 3 ✓".encode())))
    assert d["port_name"] == "text message" and d["text"] == "Hello mesh, test 1 2 3 ✓" and d["encrypted"] is True
    d = mt.decode(packet(data(3, POSITION)))
    assert d["position"] == {"lat": 52.123457, "lon": 4.987654, "alt": 12, "sats": 7, "precision_bits": 16}
    d = mt.decode(packet(data(4, pb(1, b"!1a2b3c4d") + pb(2, b"Garage node") + pb(3, b"GRG") + pb(5, 43) + pb(7, 2))))
    assert d["user"] == {"id": "!1a2b3c4d", "long_name": "Garage node", "short_name": "GRG", "hardware": "Heltec V3", "role": "router"}
    metrics = pb(1, 87) + pb(2, 4.05) + pb(3, 12.5) + pb(5, 3600)
    d = mt.decode(packet(data(67, pb(1, 1700000000) + pb(2, metrics))))
    assert d["telemetry"]["battery"] == 87 and d["telemetry"]["voltage"] == 4.05 and d["telemetry"]["uptime"] == 3600
    d = mt.decode(packet(data(67, pb(3, pb(1, 21.5) + pb(2, 45.0)))))
    assert d["telemetry"] == {"temperature": 21.5, "humidity": 45.0}


def test_unencrypted_channel_is_read_as_it_is():
    d = mt.decode(packet(data(1, b"no key at all"), key=None))
    assert d["text"] == "no key at all" and d["encrypted"] is False


def test_private_channels_and_noise_stay_unread():
    other = bytes(range(16))
    assert mt.decode(packet(data(1, b"secret plans"), key=other)) is None
    assert mt.decode(packet(data(3, POSITION), key=other)) is None
    assert mt.decode(meshtastic()) is None                       # the test generator's random bytes
    assert mt.decode(meshtastic(n=0)) is None and mt.decode(b"") is None
    # a Data message that names no known port, or has no payload, is not accepted either
    assert mt.decode(packet(pb(1, 99) + pb(2, b"x"))) is None and mt.decode(packet(pb(1, 1))) is None
    assert mt.decode(packet(data(1, b"\x00\x01\x02\xff\xfe"))) is None   # not text


def test_other_ports_are_named_but_their_contents_are_not_read():
    d = mt.decode(packet(data(6, b"admin payload with secrets")))
    assert d["port_name"] == "admin" and set(d) == {"port", "port_name", "encrypted"}


def test_decoder_survives_garbage():
    import random
    rnd = random.Random(7)
    for _ in range(3000):
        n = rnd.randrange(0, 80)
        mt.decode(bytes(rnd.randrange(256) for _ in range(n)))
        mt.decode_data(bytes(rnd.randrange(256) for _ in range(n)))
    for plain in (data(3, b"\x0d\x01"), data(4, b"\x12\xff\xff\x03"), data(1, b"\xc3\x28"), data(67, b"\x12\x05\x08"), data(8, b"\x10")):
        mt.decode(packet(plain))


# ------------------------------------------------------------------ the store reads it (and can be told not to)
def test_store_keeps_public_messages_positions_and_names(ctx):
    eu = PROFILES["meshtastic-eu868"]
    t = time.time()
    ctx.store.process(frame(packet(data(1, b"anyone out there?"), pid=11), eu, t))
    ctx.store.process(frame(packet(data(3, POSITION), pid=12), eu, t + 1))
    ctx.store.process(frame(packet(data(4, pb(2, b"Garage node") + pb(3, b"GRG")), pid=13), eu, t + 2))
    ctx.store.process(frame(packet(data(1, b"private words"), pid=14, key=bytes(range(16))), eu, t + 3))
    ctx.store.flush()
    rows = ctx.rows("SELECT kind, src, info FROM lora_packets ORDER BY id")
    assert [r["kind"] for r in rows][:3] == ["text message", "position", "node info"]
    assert json.loads(rows[0]["info"])["text"] == "anyone out there?" and json.loads(rows[1]["info"])["position"]["lat"] == 52.123457
    assert rows[3]["kind"] == "broadcast" and "private" not in (rows[3]["info"] or "")      # the private channel stays what it was
    node = ctx.one("SELECT * FROM lora_nodes WHERE addr='!1a2b3c4d'")
    assert node["name"] == "Garage node" and (node["lat"], node["lon"]) == (52.123457, 4.987654) and node["packets"] == 4


def test_reading_the_public_channel_can_be_switched_off(ctx):
    s = ctx.settings.get("lora")
    s["decode_public"] = False
    ctx.settings.set("lora", s)
    ctx.lora._dec_at = -10.0
    ctx.store.process(frame(packet(data(1, b"should not be kept"), pid=21), PROFILES["meshtastic-eu868"], time.time()))
    ctx.store.flush()
    row = ctx.one("SELECT kind, info FROM lora_packets")
    assert row["kind"] == "broadcast" and "should not" not in (row["info"] or "")


# ------------------------------------------------------------------ LoRaWAN
def test_lorawan_regions_cover_the_default_channels():
    assert LORAWAN_PLANS["EU868"][0] == [868.1, 868.3, 868.5]
    assert LORAWAN_PLANS["US915"][0][0] == 903.9 and LORAWAN_PLANS["US915"][0][-1] == 905.3 and len(LORAWAN_PLANS["AU915"][0]) == 8
    got = parse_profiles("lorawan:eu868:7-12")
    assert len(got) == 18 and {p.sync for p in got} == {SYNC_LORAWAN} and {p.bw for p in got} == {125} and {p.hint for p in got} == {"lorawan"}
    assert {p.sf for p in parse_profiles("lorawan:us915:7-12")} == {7, 8, 9, 10}      # US915 devices never use SF11/12 on these channels
    assert [p.freq for p in parse_profiles("lorawan:as923")] == [923.2, 923.4]
    assert [p.name for p in parse_profiles("lorawan:eu868:9")][0] == "lorawan-eu868-868.1-sf9"
    for bad in ("lorawan:mars", "lorawan:eu868:x", "lorawan:us915:11-12", "lorawan:eu868:7:1", "lorawan:eu868:6"):
        with pytest.raises(ValueError):
            parse_profiles(bad)


def test_lorawan_is_listened_for_by_default_in_every_region():
    for region in ("EU868", "US915", "ANZ"):
        assert any(p.hint == "lorawan" for p in parse_profiles("", region)), region


def test_lorawan_frames_in_all_message_types():
    up = classify(lorawan_uplink(mtype=2, fport=10, payload=bytes(range(20))), SYNC_LORAWAN, "lorawan")
    assert up["protocol"] == "lorawan" and up["kind"] == "unconfirmed uplink" and up["level"] == "high" and up["info"]["fport"] == 10
    cu = classify(lorawan_uplink(mtype=4), SYNC_LORAWAN)
    assert cu["kind"] == "confirmed uplink" and cu["src"] == "26011bda"
    # an uplink without any application payload (MAC commands only / empty ack): header + FCnt + MIC = 12 bytes
    empty = lorawan_uplink(payload=b"")
    empty = empty[:8] + empty[-4:] if len(empty) > 12 else empty
    assert classify(empty, SYNC_LORAWAN)["protocol"] == "lorawan" and "fport" not in classify(empty, SYNC_LORAWAN)["info"]
    j = classify(lorawan_join_request(), SYNC_LORAWAN)
    assert j["kind"] == "join request" and j["info"]["join_eui"] == "70b3d57ed0000000"
    # every message type nibble parses (rejoin, proprietary) and a different sync word is never called LoRaWAN
    assert classify(bytes([6 << 5]) + bytes(18), SYNC_LORAWAN)["kind"] == "rejoin request"
    assert classify(bytes([7 << 5]) + bytes(18), SYNC_LORAWAN)["kind"] == "proprietary"
    assert classify(lorawan_uplink(), SYNC_MESHTASTIC)["protocol"] != "lorawan" and classify(lorawan_uplink(), SYNC_PRIVATE)["protocol"] == "unknown"


def test_lorawan_heard_end_to_end_on_a_region_profile(ctx):
    p = parse_profiles("lorawan:eu868:7-9")[4]               # 868.3 MHz SF8
    assert p.name == "lorawan-eu868-868.3-sf8"
    ctx.store.process(frame(lorawan_uplink(dev_addr=0x26011BDA), p, time.time()))
    ctx.store.flush()
    row = ctx.one("SELECT protocol, kind, profile, sf, sync FROM lora_packets")
    assert (row["protocol"], row["kind"], row["profile"], row["sf"], row["sync"]) == ("lorawan", "unconfirmed uplink", p.name, 8, 0x34)
    assert ctx.one("SELECT addr FROM lora_nodes WHERE protocol='lorawan'")["addr"] == "26011bda"


# ------------------------------------------------------------------ choosing profiles
def test_clean_override_checks_everything():
    assert clean_override({"profiles": " lorawan:eu868 ", "hop_interval": "3"}) == {"profiles": "lorawan:eu868", "hop_interval": 3.0}
    assert clean_override({}) == {"profiles": None, "hop_interval": None} and clean_override(None)["profiles"] is None
    for bad in ({"profiles": "nonsense"}, {"profiles": "x" * 2000}, {"profiles": "lorawan:eu868:7-12,lorawan:us915:7-12,lorawan:au915:7-12"},
                {"hop_interval": 0.1}, {"hop_interval": 9999}, {"hop_interval": "fast"}, {"profiles": 5}):
        with pytest.raises(ValueError):
            clean_override(bad)


def test_control_overrides_the_environment_and_returns_to_it():
    cfg = Config()
    c = LoraControl(cfg)
    assert [p.name for p in c.effective()[0]] == [p.name for p in cfg.lora_profiles] and c.effective()[1] == cfg.lora_hop_interval
    c.apply({"profiles": "lorawan:eu868:7-8,meshtastic-eu868", "hop_interval": 2}, 1)
    names = [p.name for p in c.effective()[0]]
    assert len(names) == 7 and names[-1] == "meshtastic-eu868" and c.effective()[1] == 2.0 and c.rev == 1
    c.apply({}, 2)
    assert [p.name for p in c.effective()[0]] == [p.name for p in cfg.lora_profiles] and c.rev == 2
    with pytest.raises(ValueError):
        c.apply({"profiles": "bogus"}, 3)
    assert c.rev == 2                                                  # an invalid change leaves everything as it was


def test_remote_control_applies_a_new_revision_once_and_ignores_bad_ones():
    c = LoraControl(Config())
    c.apply_remote({"rev": 4, "profiles": "lorawan:eu868", "hop_interval": None})
    assert c.rev == 4 and len(c.effective()[0]) == 3
    c.apply_remote({"rev": 5, "profiles": "garbage", "hop_interval": None})
    assert c.rev == 4 and c._rejected_rev == 5
    for junk in (None, "x", {"rev": "1"}, {"profiles": "lorawan:eu868"}, {"rev": 4}):
        c.apply_remote(junk)
    assert c.rev == 4


def test_running_board_switches_profiles_when_the_setting_changes():
    import threading
    eu, mc = PROFILES["meshtastic-eu868"], PROFILES["meshcore-eu868"]
    lw = parse_profiles("lorawan:eu868")
    sniffer = FakeSniffer({})
    control = LoraControl(Config(lora_profiles=[eu, mc], lora_hop_interval=0.05))
    sink, stop = [], threading.Event()
    sensor = LoraSensor("/dev/ttyLSEL1", control.cfg, type("S", (), {"put": lambda self, o: sink.append(o)})(), link_factory=lambda p: sniffer, control=control)
    sensor.stop = stop
    t = threading.Thread(target=lambda: sensor.run(sniffer), daemon=True)
    t.start()
    time.sleep(0.4)
    before = len(sniffer.cfgs)
    assert {c[0] for c in sniffer.cfgs} == {eu.freq, mc.freq}
    control.apply({"profiles": "lorawan:eu868"}, 1)
    time.sleep(0.5)
    stop.set()
    t.join(3)
    late = {c[0] for c in sniffer.cfgs[before + 1:]}
    assert late == {p.freq for p in lw}
    st = next(x for x in status.snapshot() if x["name"] == "lora:ttyLSEL1")
    assert st["lora_rev"] == 1 and st["profiles"] == [p.name for p in lw]
    status.SENSORS.pop("lora:ttyLSEL1", None)


# ------------------------------------------------------------------ the API
def admin_client(ctx):
    from fastapi.testclient import TestClient
    from sniffowireless.auth import hash_password
    from sniffowireless.web import create_app
    with ctx.wdb() as c:
        c.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('admin', ?, 'admin', 0)", (hash_password("correct-horse-battery", iterations=1000),))
        c.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('view', ?, 'viewer', 0)", (hash_password("correct-horse-battery", iterations=1000),))
    c = TestClient(create_app(ctx), base_url="http://sniffowireless.test")
    assert c.post("/api/auth/login", json={"username": "admin", "password": "correct-horse-battery"}).status_code == 200
    c.headers["x-sniffowireless"] = "1"
    return c


def test_lora_settings_api(ctx):
    import time as _t
    from fastapi.testclient import TestClient
    from sniffowireless.lora import attach
    from sniffowireless.web import create_app
    attach(ctx)
    c = admin_client(ctx)
    ctx.execute("INSERT INTO sensors(id, name, created, last_seen) VALUES('garden', 'Garden', ?, ?)", (_t.time(), _t.time()))
    d = c.get("/api/lora-settings").json()
    assert [t["id"] for t in d["targets"]] == ["local", "garden"] and d["targets"][0]["own"] and d["decode_public"] is True
    tokens = {k["token"] for k in d["known"]}
    assert {"meshtastic-eu868", "lorawan:eu868", "lorawan:eu868:7-12", "lorawan:us915:7-10"} <= tokens
    r = c.put("/api/lora-settings/garden", json={"profiles": "lorawan:eu868:7-9", "hop_interval": 4}).json()
    assert r["config"]["rev"] == 1 and r["profiles"] == 9 and r["cycle_seconds"] == 36
    assert c.get("/api/lora-settings").json()["targets"][1]["config"]["profiles"] == "lorawan:eu868:7-9"
    assert c.put("/api/lora-settings/garden", json={"profiles": "lorawan:eu868:7-9"}).json()["config"]["rev"] == 2
    assert c.put("/api/lora-settings/garden", json={"profiles": "nope"}).status_code == 400
    assert c.put("/api/lora-settings/ghost", json={"profiles": "lorawan:eu868"}).status_code == 404
    # this server: saving applies at once
    c.put("/api/lora-settings/local", json={"profiles": "meshtastic-us", "hop_interval": None})
    assert [p.name for p in ctx.lora_control.effective()[0]] == ["meshtastic-us"] and ctx.lora_control.rev == 1
    assert c.delete("/api/lora-settings/local").status_code == 200
    assert [p.name for p in ctx.lora_control.effective()[0]] == [p.name for p in ctx.cfg.lora_profiles]
    # reading the public channel
    assert c.put("/api/lora-settings", json={"decode_public": False}).json()["decode_public"] is False
    assert c.get("/api/lora").json()["decode_public"] is False
    assert c.put("/api/lora-settings", json={"decode_public": None}).json()["decode_public"] is True
    # admin only
    v = TestClient(create_app(ctx), base_url="http://sniffowireless.test")
    assert v.get("/api/lora-settings").status_code == 401
    assert v.post("/api/auth/login", json={"username": "view", "password": "correct-horse-battery"}).status_code == 200
    assert v.get("/api/lora-settings").status_code == 403 and v.put("/api/lora-settings/local", headers={"x-sniffowireless": "1"}, json={}).status_code == 403


def test_ingest_reply_carries_the_sensors_lora_profiles(ctx):
    c = admin_client(ctx)
    tok = c.post("/api/sensors", json={"name": "Shed", "room": None}).json()
    c.put(f"/api/lora-settings/{tok['id']}", json={"profiles": "lorawan:eu868", "hop_interval": 3})
    from fastapi.testclient import TestClient
    from sniffowireless.web import create_app
    s = TestClient(create_app(ctx), base_url="http://sniffowireless.test")
    reply = s.post("/api/ingest", headers={"Authorization": f"Bearer {tok['token']}", "x-sniffowireless": "1"}, json={"observations": [], "status": []}).json()
    assert reply["lora_config"] == {"rev": 1, "profiles": "lorawan:eu868", "hop_interval": 3.0}
    assert c.delete(f"/api/sensors/{tok['id']}").status_code == 200
    assert tok["id"] not in ctx.settings.get("lora")["sensors"]
