"""Frame inspector (release 33.1): decoding recorded frames into summaries and field trees with byte ranges, display filters,
and the API behind the Frames page."""
import gzip
import json
import os
import random

import pytest
from fastapi.testclient import TestClient
from test_hardening import PW, client, ctx  # noqa: F401  (ctx is a fixture)

from sniffowireless import capture, sample_frames as sf
from sniffowireless.dissect import MALFORMED, dissect
from sniffowireless.framefilter import FilterError, compile_filter
from sniffowireless.web import create_app


def run(radio, raw, **meta):
    return dissect({"radio": radio, "src": "test", "raw": raw, "ts": 100.0, **meta})


def nodes(tree):
    for n in tree:
        yield n
        yield from nodes(n.get("c", []))


def find(tree, name):
    """The first field called `name`, else the first whose name starts with it."""
    return next((n for n in nodes(tree) if n["n"] == name), None) or next((n for n in nodes(tree) if n["n"].startswith(name)), None)


@pytest.mark.parametrize("radio,src,raw,meta", sf.samples())
def test_every_sample_decodes_with_byte_ranges_inside_the_frame(radio, src, raw, meta):
    s, tree, shown = run(radio, raw, **meta)
    assert s["proto"] and s["info"] and "Could not be decoded" not in s["info"]
    for n in nodes(tree):
        assert n["n"] != MALFORMED and n.get("v") != MALFORMED, n
        if "o" in n:
            assert 0 <= n["o"] and n["o"] + n["l"] <= len(shown), n


def test_wifi_beacon_fields():
    s, tree, shown = run("wifi", sf.beacon())
    assert s["src"] == "02:a0:c5:11:22:33" and s["dst"] == "Broadcast" and s["rssi"] == -48 and s["channel"] == 6
    assert s["info"] == 'Beacon frame, SN=100, BI=100, SSID="HomeNet"' and s["ssid"] == "HomeNet" and s["color"] == "beacon"
    assert find(tree, "Tag: RSN Information")["v"] == "PSK, SAE (WPA3-Personal)"
    ssid = find(tree, "Tag: SSID")
    assert bytes(shown[ssid["o"] + 2:ssid["o"] + ssid["l"]]) == b"HomeNet"
    name = find(tree, "Device Name")
    assert name["v"] == "Living Room AP" and shown[name["o"] + 4:name["o"] + name["l"]] == b"Living Room AP"
    assert find(tree, "BSS color")["v"] == "5"
    assert find(tree, "Beacon Interval")["v"] == "0.102400 seconds (100 TU)"


def test_wifi_deauth_with_fcs_and_a_broken_one():
    s, tree, _ = run("wifi", sf.with_fcs(sf.deauth()))
    assert "Class 3 frame received from nonassociated STA (7)" in s["info"] and s["color"] == "deauth"
    assert find(tree, "Frame check sequence")["v"].endswith("[correct]")
    bad = bytearray(sf.with_fcs(sf.deauth()))
    bad[-1] ^= 0xFF
    s, tree, _ = run("wifi", bytes(bad))
    assert find(tree, "Frame check sequence")["v"].endswith("[incorrect]") and s["color"] == "bad"


def test_wifi_data_header_addresses_follow_the_ds_bits():
    s, tree, _ = run("wifi", sf.qos_data())
    assert s["src"] == "da:12:f3:a4:b5:c6" and s["dst"] == "02:a0:c5:11:22:33" and "protected" in s["info"]
    assert find(tree, "Receiver address (BSS Id)") and find(tree, "QoS Control")["v"] == "TID 0"
    assert find(tree, "Data")["v"].startswith("not recorded")


def test_bluetooth_reports():
    s, tree, _ = run("bt", sf.le_adv())
    assert (s["proto"], s["src"], s["rssi"], s["name"]) == ("LE ADV", "3c:2e:f9:01:02:03", -71, "Pixel 8")
    assert "Google Fast Pair (0xfe2c)" in find(tree, "Advertising Data: Complete List of 16-bit Service UUIDs")["v"]
    assert find(tree, "BD_ADDR")["v"] == "3c:2e:f9:01:02:03 (random, non-resolvable private)"
    s, tree, _ = run("bt", sf.le_findmy())
    assert "Apple Find My" in s["info"] and find(tree, "Apple: Find My")
    s, tree, _ = run("bt", sf.ibeacon())
    assert find(tree, "Major")["v"] == "1" and find(tree, "Minor")["v"] == "42" and find(tree, "Measured power")["v"] == "-59 dBm"
    s, tree, _ = run("bt", sf.le_ext_adv())
    assert s["proto"] == "LE EXT ADV" and '"Kitchen speaker"' in s["info"] and find(tree, "Secondary PHY")["v"] == "LE 2M"
    s, tree, _ = run("bt", sf.inquiry_eir())
    assert s["proto"] == "BR/EDR" and s["rssi"] == -74 and '"Car Audio"' in s["info"] and "Audio/Video" in s["info"]
    s, _, _ = run("bt", sf.command_complete())
    assert s["info"] == "Command Complete (LE Set Scan Enable)"


def test_zigbee_and_thread():
    s, tree, _ = run("zigbee", sf.zb_beacon(), channel=15)
    assert s["proto"] == "ZigBee" and "EPID: dd:dd:dd:dd:dd:dd:dd:dd" in s["info"] and s["channel"] == 15
    assert "ZigBee PRO" in find(tree, "Beacon").get("v", "") or find(tree, ".... .... .... 0010 = Stack Profile: ZigBee PRO")
    s, tree, _ = run("zigbee", sf.thread_beacon())
    assert s["proto"] == "Thread" and s["network"] == "OpenThreadDemo"
    s, tree, _ = run("zigbee", sf.zb_data())
    assert (s["src"], s["dst"]) == ("0x4f21", "0x0000") and s["info"].endswith("encrypted")
    assert find(tree, "Extended Source")["v"] == "00:12:4b:00:01:02:03:04" and find(tree, "Message Integrity Code")["v"] == "aabbccdd"
    assert run("zigbee", sf.beacon_request())[0]["info"] == "Beacon Request"
    assert run("zigbee", sf.zb_ack())[0]["info"] == "Ack, seq 40"
    assert run("zigbee", sf.thread_data())[0]["proto"] == "6LoWPAN"


def test_lora_frames_show_the_payload_bytes():
    s, tree, shown = run("lora", sf.lora_line(sf.meshtastic_packet()))
    assert s["proto"] == "Meshtastic" and s["src"] == "!deadbeef" and s["rssi"] == -104 and shown == sf.meshtastic_packet()
    assert find(tree, "Hop limit") is None and find(tree, ".... .011 = Hop limit: 3")
    s, tree, _ = run("lora", sf.lora_line(sf.lorawan_uplink(), sync=0x34))
    assert s["proto"] == "LoRaWAN" and find(tree, "DevAddr")["v"] == "260b1a2c" and find(tree, "FCnt")["v"] == "513"
    s, tree, shown = run("lora", b"BOOT sniffer v7")
    assert s["info"] == "BOOT sniffer v7" and shown == b"BOOT sniffer v7"


def test_cut_short_and_random_frames_never_raise():
    rnd = random.Random(33)
    for radio, _, raw, meta in sf.samples():
        for n in range(len(raw)):
            s, tree, _ = run(radio, raw[:n], **meta)
            assert "Could not be decoded" not in s.get("info", ""), (radio, n, s)
    for radio in ("wifi", "bt", "zigbee", "lora"):
        for _ in range(1500):
            raw = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 80)))
            if radio == "wifi" and rnd.random() < 0.7:
                raw = sf.radiotap() + raw
            if radio == "bt" and rnd.random() < 0.7:
                raw = bytes([4, rnd.choice([0x3E, 0x2F, 0x22, 0x02, 0x0E]), len(raw)]) + bytes([rnd.choice([2, 13])]) + raw
            s, _, _ = run(radio, raw)
            assert "Could not be decoded" not in s.get("info", ""), (radio, raw.hex())


SUMMARIES = [{"no": 1, "radio": "wifi", "proto": "802.11", "type": "Beacon frame", "src": "02:a0:c5:11:22:33", "dst": "Broadcast",
              "info": 'Beacon frame, SSID="HomeNet"', "rssi": -48, "channel": 6, "ssid": "HomeNet", "len": 268},
             {"no": 2, "radio": "bt", "proto": "LE ADV", "type": "ADV_IND", "src": "3c:2e:f9:01:02:03", "dst": "Broadcast", "info": "ADV_IND, Pixel 8",
              "rssi": -71, "len": 36, "name": "Pixel 8"},
             {"no": 3, "radio": "zigbee", "proto": "ZigBee", "src": "0x4f21", "dst": "0x0000", "info": "Data", "rssi": -64, "channel": 15, "len": 47}]


@pytest.mark.parametrize("text,want", [
    ("", [1, 2, 3]), ("wifi", [1]), ("ble", [2]), ("zigbee || lora", [3]), ("beacon", [1]), ("!wifi", [2, 3]),
    ("rssi > -65", [1, 3]), ("rssi >= -71 && rssi < -60", [2, 3]), ("addr == 3C:2E:F9:01:02:03", [2]), ("src == 0x4f21", [3]),
    ('ssid contains "home"', [1]), ("name == \"Pixel 8\"", [2]), ("channel == 6", [1]), ("(wifi or bt) and not beacon", [2]),
    ("len > 100", [1]), ("channel > 10", [3]), ("ssid != HomeNet", [2, 3]), ('"pixel"', [2]), ("proto == \"LE ADV\"", [2])])
def test_filters(text, want):
    pred = compile_filter(text)
    got = [s["no"] for s in SUMMARIES if pred is None or pred(s)]
    assert got == want


@pytest.mark.parametrize("text", ["rssi >", "(wifi", "wifi)", "colour == red", "rssi > strong", "a == b ==", "&& wifi", "x" * 600])
def test_bad_filters_say_why(text):
    with pytest.raises(FilterError):
        compile_filter(text)


def _recording(ctx, frames=None, name="capture-20261116-120000.jsonl.gz", cut=False):
    folder = capture.directory(ctx.cfg)
    path = os.path.join(folder, name)
    if frames is None:
        sf.write_recording(path, count=300, start=1000.0)
    else:
        os.makedirs(folder, exist_ok=True)
        with gzip.open(path, "wt", encoding="ascii") as f:
            for i, (radio, src, raw, meta) in enumerate(frames):
                f.write(json.dumps({"ts": 1000 + i, "radio": radio, "src": src, "raw": raw.hex(), **meta}) + "\n")
    if cut:
        with open(path, "rb") as f:
            data = f.read()
        with open(path, "wb") as f:
            f.write(data[:len(data) * 2 // 3])
    return name


def test_frames_api(ctx):
    name = _recording(ctx)
    app = create_app(ctx)
    admin = client(app, "admin")
    d = admin.get(f"/api/captures/{name}/frames?limit=50").json()
    assert d["total"] == 300 and d["matched"] == 300 and len(d["items"]) == 50 and d["items"][0]["no"] == 1 and d["items"][0]["time"] == 0
    assert sum(d["counts"].values()) == 300 and not d["incomplete"]
    page = admin.get(f"/api/captures/{name}/frames?offset=50&limit=50").json()["items"]
    assert page[0]["no"] == 51
    beacons = admin.get(f"/api/captures/{name}/frames?filter=beacon&limit=1000").json()
    assert beacons["matched"] and all("beacon" in x["info"].lower() for x in beacons["items"])
    bad = admin.get(f"/api/captures/{name}/frames?filter=rssi%20%3E")
    assert bad.status_code == 400 and "missing" in bad.json()["detail"]
    one = admin.get(f"/api/captures/{name}/frames/1").json()
    assert one["summary"]["no"] == 1 and one["tree"][0]["n"] == "Frame 1" and bytes.fromhex(one["hex"])
    for no in range(1, 301):  # every frame of the demo recording opens
        assert admin.get(f"/api/captures/{name}/frames/{no}").status_code == 200
    assert admin.get(f"/api/captures/{name}/frames/301").status_code == 404
    assert admin.get("/api/captures/../etc/passwd/frames").status_code == 404
    assert client(app, "view").get(f"/api/captures/{name}/frames").status_code == 403
    assert TestClient(app, base_url="http://sniffowireless.test").get(f"/api/captures/{name}/frames").status_code == 401
    assert admin.delete(f"/api/captures/{name}").status_code == 200 and capture.VIEWS.current is None


def test_a_recording_cut_short_shows_what_is_there(ctx):
    name = _recording(ctx, sf.samples() * 40, cut=True)
    d = client(create_app(ctx), "admin").get(f"/api/captures/{name}/frames?limit=1").json()
    assert d["incomplete"] and 0 < d["total"] < 920


def test_no_inspecting_while_addresses_are_private(ctx):
    name = _recording(ctx, sf.samples())
    p = ctx.settings.get("privacy")
    ctx.settings.set("privacy", {**p, "macs": True})
    r = client(create_app(ctx), "admin").get(f"/api/captures/{name}/frames")
    assert r.status_code == 409 and "privacy" in r.json()["detail"]


def test_the_demo_writes_one_sample_recording(tmp_path):
    from sniffowireless.config import Config
    from sniffowireless.demo import sample_recording
    cfg = Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path))
    path = sample_recording(cfg)
    assert path and len(list(capture.read(path))) == 800
    assert sample_recording(cfg) is None   # not again once there is one


def test_a_big_recording_is_read_in_the_background(ctx, monkeypatch):
    import threading
    name = _recording(ctx, sf.samples())
    gate, real = threading.Event(), capture.dis.summarize
    monkeypatch.setattr(capture.dis, "summarize", lambda rec, vendor=None: (gate.wait(5), real(rec, vendor))[1])
    capture.VIEWS.current = capture.VIEWS.job = None
    admin = client(create_app(ctx), "admin")
    d = admin.get(f"/api/captures/{name}/frames").json()
    assert d["loading"] and d["read"] == 0
    assert admin.get(f"/api/captures/{name}/frames/1").status_code in (200, 409)
    gate.set()
    path = os.path.join(capture.directory(ctx.cfg), name)
    assert capture.VIEWS.load(path).summaries and admin.get(f"/api/captures/{name}/frames").json()["total"] == len(sf.samples())
