"""pcapng export of recordings and live captures, and pcap / pcapng import (release 34)."""
import gzip
import os
import shutil
import struct
import subprocess

import pytest
from test_hardening import client, ctx  # noqa: F401  (ctx is a fixture)

from sniffowireless import capture, pcap, sample_frames as sf
from sniffowireless.web import create_app


def records():
    t = 1_790_000_000.0
    return [{"ts": t + i / 100, "radio": radio, "src": src, "raw": raw, **meta} for i, (radio, src, raw, meta) in enumerate(sf.samples())]


def exported(recs):
    return b"".join(pcap.export(recs))


def test_export_round_trip():
    recs = records()
    data = exported(recs)
    back = [pcap.to_record(*p) for p in pcap.packets(data)]
    assert len(back) == len(recs)
    for rec, (got, why) in zip(recs, back):
        assert why is None and got["radio"] == rec["radio"] and got["src"] == rec["src"] and abs(got["ts"] - rec["ts"]) < 1e-5
        if rec["radio"] == "lora":   # LoRaTap has no frequency error and no board time stamp: the rest comes back
            assert got["raw"].split(b",")[2:8] == rec["raw"].split(b",")[2:8] and got["raw"].split(b",")[9:] == rec["raw"].split(b",")[9:]
        else:
            assert got["raw"] == rec["raw"]
        for key in ("channel", "rssi", "lqi"):
            if key in rec:
                assert got[key] == rec[key]


def test_one_interface_per_radio_and_source():
    recs = records()
    recs.append({**recs[0], "src": "wifi:wlan1mon"})
    data = exported(recs)
    blocks, at = [], 0
    while at < len(data):
        btype, n = struct.unpack("<II", data[at:at + 8])
        blocks.append(btype)
        at += n
    assert blocks[0] == 0x0A0D0D0A and blocks.count(1) == 5 and blocks.count(6) == len(recs)


@pytest.mark.skipif(not shutil.which("tshark"), reason="tshark is not installed")
def test_wireshark_decodes_it(tmp_path):
    f = tmp_path / "x.pcapng"
    f.write_bytes(exported(records()))
    out = subprocess.run(["tshark", "-r", str(f), "-T", "fields", "-e", "frame.protocols"], capture_output=True, text=True, timeout=60).stdout
    protos = out.split()
    assert sum(p.startswith("radiotap:wlan_radio:wlan") for p in protos) == 8
    assert sum("bthci_evt" in p for p in protos) == 6
    assert sum(p.startswith("wpan-tap") for p in protos) == 7
    assert "loratap:lorawan" in protos


def legacy(linktype, pkts, big=False, nano=False):
    e = ">" if big else "<"
    out = struct.pack(e + "IHHiIII", 0xA1B23C4D if nano else 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for ts, p in pkts:
        out += struct.pack(e + "IIII", int(ts), int(round(ts % 1 * (1e9 if nano else 1e6))), len(p), len(p)) + p
    return out


@pytest.mark.parametrize("big,nano", [(False, False), (True, False), (False, True), (True, True)])
def test_legacy_pcap(big, nano):
    got = [pcap.to_record(*p)[0] for p in pcap.packets(legacy(127, [(1_790_000_000.25, sf.beacon()), (1_790_000_001.5, sf.probe_request())], big, nano))]
    assert [g["raw"] for g in got] == [sf.beacon(), sf.probe_request()] and got[0]["src"] == "pcap:wifi"
    assert abs(got[1]["ts"] - 1_790_000_001.5) < 1e-5


def test_other_link_types():
    hci = sf.le_adv()
    zb = sf.zb_ack()
    plain = sf.probe_request()[int.from_bytes(sf.probe_request()[2:4], "little"):]   # without its radiotap header
    cases = [(105, plain, "wifi"), (187, hci, "bt"), (201, b"\0\0\0\1" + hci, "bt"), (195, zb + b"\xaa\xbb", "zigbee"), (230, zb, "zigbee")]
    for lt, p, radio in cases:
        rec, why = pcap.to_record(lt, 1.0, p)
        assert why is None and rec["radio"] == radio
    assert pcap.to_record(195, 1, zb + b"\xaa\xbb")[0]["raw"] == zb
    assert pcap.to_record(105, 1, plain)[0]["raw"][8:] == plain   # an empty radiotap header in front
    assert pcap.to_record(1, 1, b"\0" * 60) == (None, "link type Ethernet")
    assert pcap.to_record(187, 1, b"\x02\x00")[1] == "Bluetooth: not an HCI event"   # ACL data


def test_data_frames_are_cut_on_import():
    raw = sf.qos_data() + b"secret payload" * 10
    rec = pcap.to_record(127, 1, raw)[0]
    assert b"secret" not in rec["raw"] and rec["raw"] == sf.qos_data()


def test_not_a_capture():
    for data in (b"hello world", b"\x1f\x8bnot really gzip"):
        with pytest.raises(pcap.NotCapture):
            list(pcap.packets(data))
    cut = exported(records())[:-7]   # cut short: what came before is read
    assert len(list(pcap.packets(cut))) == len(records()) - 1


@pytest.fixture
def setup(ctx):
    capture.LIVE.close()
    capture.LIVE_CAPTURES.clear()
    app = create_app(ctx)
    yield ctx, app, client(app, "admin")
    capture.LIVE.close()
    capture.LIVE_CAPTURES.clear()


def test_export_a_recording(setup):
    ctx, app, admin = setup
    folder = capture.directory(ctx.cfg)
    os.makedirs(folder, exist_ok=True)
    name = "capture-20261117-120000.jsonl.gz"
    sf.write_recording(os.path.join(folder, name))
    r = admin.get(f"/api/captures/{name}/pcap")
    assert r.status_code == 200 and 'filename="capture-20261117-120000.pcapng"' in r.headers["content-disposition"]
    assert len(list(pcap.packets(r.content))) == len(list(capture.read(os.path.join(folder, name))))
    r = admin.get(f"/api/captures/{name}/pcap?filter=ble")
    assert r.status_code == 200 and "-filtered.pcapng" in r.headers["content-disposition"]
    got = [pcap.to_record(*p)[0]["radio"] for p in pcap.packets(r.content)]
    assert got and set(got) == {"bt"}
    assert admin.get(f"/api/captures/{name}/pcap?filter=rssi%20%3E").status_code == 400
    assert client(app, "view").get(f"/api/captures/{name}/pcap").status_code == 403
    assert admin.get("/api/captures/nothing.jsonl.gz/pcap").status_code == 404


def test_import(setup):
    ctx, app, admin = setup
    data = exported(records())
    r = admin.post("/api/captures/import", content=gzip.compress(data), headers={"content-type": "application/octet-stream"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["frames"] == len(records()) and d["radios"] == ["bt", "lora", "wifi", "zigbee"] and d["name"].endswith("-import.jsonl.gz")
    listing = admin.get("/api/captures").json()["files"]
    assert next(f for f in listing if f["name"] == d["name"])["sensor_name"] == "Imported file"
    frames = admin.get(f"/api/captures/{d['name']}/frames").json()
    assert frames["total"] == len(records()) and frames["items"][0]["sensor"] == "wifi:wlan0mon"   # the interface names come back
    r2 = admin.post("/api/captures/import", content=data).json()
    assert r2["name"] != d["name"]   # in the same second: a name of its own


def test_import_tells_what_was_left_out(setup):
    ctx, app, admin = setup
    r = admin.post("/api/captures/import", content=legacy(1, [(1, b"\0" * 60)] * 3))
    assert r.status_code == 400 and "Ethernet: 3" in r.json()["detail"]
    assert admin.post("/api/captures/import", content=b"just text").status_code == 400
    assert not [n for n in os.listdir(capture.directory(ctx.cfg)) if n.endswith(".part")]
    mixed = legacy(127, [(1, sf.beacon()), (2, sf.beacon() + b"\1" * 5000)])
    d = admin.post("/api/captures/import", content=mixed).json()
    assert d["frames"] == 1 and d["skipped"] == {"longer than a recorded frame can be": 1}
    assert client(app, "view").post("/api/captures/import", content=mixed).status_code == 403


def test_import_respects_the_number_of_recordings(setup, monkeypatch):
    ctx, app, admin = setup
    monkeypatch.setattr(capture, "MAX_FILES", 1)
    assert admin.post("/api/captures/import", content=legacy(127, [(1, sf.beacon())])).status_code == 200
    assert admin.post("/api/captures/import", content=legacy(127, [(1, sf.beacon())])).status_code == 409


def test_live_capture_as_pcapng(setup):
    ctx, app, admin = setup
    admin.post("/api/frames/live", json={"radios": ["wifi", "bt"]})
    capture.RECORDER.record("wifi", "wifi:wlan0mon", sf.beacon(), tuned=2437)
    capture.RECORDER.record("bt", "bt:hci0", sf.le_adv())
    r = admin.get("/api/frames/live/pcap?source=local")
    assert r.status_code == 200 and r.headers["content-disposition"].endswith('.pcapng"')
    assert [p[0] for p in pcap.packets(r.content)] == [127, 201]
    assert [p[0] for p in pcap.packets(admin.get("/api/frames/live/pcap?filter=ble").content)] == [201]
    assert admin.get("/api/frames/live/pcap?source=attic").status_code == 404
