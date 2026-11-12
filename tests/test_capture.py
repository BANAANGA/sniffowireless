"""Raw-frame recording and replay: what is recorded is what the radios delivered, a replay gives the parsers exactly that again,
and the files stay private (admin only, no traffic contents, not while MAC privacy is on)."""
import gzip
import json
import struct
import time

import pytest
from fastapi.testclient import TestClient
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from test_identification32 import EUI, assoc_request, green_power
from test_lora import meshtastic, rx_line

from sniffowireless import capture, macprivacy, status
from sniffowireless.auth import hash_password
from sniffowireless.config import Config
from sniffowireless.lora_protocols import PROFILES
from sniffowireless.main import build
from sniffowireless.web import create_app

PW = "correct-horse-battery"
BSSID = "00:11:22:33:44:55"


@pytest.fixture
def ctx(tmp_path):
    status.SENSORS.clear()
    capture.RECORDER.stop()
    c = build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))
    with c.wdb() as w:
        for name, role in (("admin", "admin"), ("view", "viewer")):
            w.execute("INSERT INTO users(username, pw_hash, role, created) VALUES(?, ?, ?, 0)", (name, hash_password(PW, iterations=1000), role))
    yield c
    capture.RECORDER.stop()


def client(app, user=None):
    c = TestClient(app, base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    if user:
        assert c.post("/api/auth/login", json={"username": user, "password": PW}).status_code == 200
    return c


def beacon(ssid=b"HomeNet"):
    return bytes(RadioTap(present="Channel+dBm_AntSignal", ChannelFrequency=2437, dBm_AntSignal=-50)
                 / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=BSSID, addr3=BSSID) / Dot11Beacon(cap="ESS")
                 / Dot11Elt(ID="SSID", info=ssid) / Dot11Elt(ID="DSset", info=b"\x06"))


def data_frame(payload=b"SECRET-CONTENTS-OF-SOMEBODYS-TRAFFIC" * 4):
    return bytes(RadioTap(present="Channel+dBm_AntSignal", ChannelFrequency=2437, dBm_AntSignal=-50)
                 / Dot11(type=2, subtype=0, FCfield="to-DS", addr1=BSSID, addr2="00:aa:bb:cc:dd:01", addr3=BSSID)) + payload


def le_advert(mac="c4:11:22:33:44:01", name=b"Kitchen Scale"):
    ad = bytes([len(name) + 1, 0x09]) + name
    body = bytes([0x02, 1, 0x00, 0x00]) + bytes(reversed(bytes.fromhex(mac.replace(":", "")))) + bytes([len(ad)]) + ad + struct.pack("<b", -60)
    return bytes([0x04, 0x3E, len(body)]) + body


def record_everything(tmp_path, seconds=60):
    r = capture.RECORDER
    r.start(str(tmp_path / "captures"), seconds)
    r.record("wifi", "wifi:mon0", beacon(), tuned=2437)
    r.record("wifi", "wifi:mon0", data_frame(), tuned=2437)
    r.record("bt", "bt:hci0", le_advert())
    r.record("zigbee", "zigbee:ttyUSB0", assoc_request(0x8E), channel=15, rssi=-60, lqi=150)
    r.record("zigbee", "zigbee:ttyUSB0", green_power(0x01020304, 0x22), channel=15, rssi=-60, lqi=150)
    r.record("lora", "lora:ttyACM0", rx_line(meshtastic(), next(p for p in PROFILES.values() if p.name.startswith("meshtastic"))).encode())
    return r.stop()


def test_recording_keeps_frames_as_delivered_but_never_traffic_contents(tmp_path):
    path = record_everything(tmp_path)
    recs = list(capture.read(path))
    assert [r["radio"] for r in recs] == ["wifi", "wifi", "bt", "zigbee", "zigbee", "lora"]
    assert recs[0]["raw"] == beacon() and recs[0]["tuned"] == 2437 and recs[2]["raw"] == le_advert()
    assert recs[3]["raw"] == assoc_request(0x8E) and (recs[3]["channel"], recs[3]["rssi"], recs[3]["lqi"]) == (15, -60, 150)
    whole = data_frame()
    assert len(recs[1]["raw"]) < len(whole) and whole.startswith(recs[1]["raw"])
    assert b"SECRET" not in gzip.open(path).read() and "5345435245542d" not in gzip.open(path, "rt").read()  # nor as hex
    assert RadioTap(recs[1]["raw"])[Dot11].addr2 == "00:aa:bb:cc:dd:01"   # the header the parsers need is still there


def test_trim_cuts_exactly_at_the_end_of_the_header_whatever_its_length():
    rt = bytes(RadioTap(present="Channel+dBm_AntSignal", ChannelFrequency=2437, dBm_AntSignal=-50))
    body = b"PAYLOAD!" * 8
    for fc0, fc1, header in ((0x08, 0x01, 24), (0x08, 0x03, 30), (0x88, 0x01, 26), (0x88, 0x03, 32), (0x88, 0x81, 30), (0x88, 0x83, 36)):
        frame = rt + bytes([fc0, fc1]) + bytes(header - 2) + body
        assert capture.trim_wifi(frame) == frame[:len(rt) + header], (fc0, fc1)


def test_trim_leaves_management_frames_and_short_input_alone():
    assert capture.trim_wifi(beacon()) == beacon()
    assert capture.trim_wifi(b"\x00") == b"\x00" and capture.trim_wifi(b"") == b""


def test_replay_finds_what_was_recorded(ctx, tmp_path):
    path = record_everything(tmp_path)
    counts = capture.replay(path, ctx)
    assert counts["frames"] == {"wifi": 2, "bt": 1, "zigbee": 2, "lora": 1}
    assert all(counts["observations"][r] >= 1 for r in ("wifi", "bt", "zigbee", "lora"))
    found = capture.identified(ctx)
    by_mac = {d["mac"]: d for d in found["devices"]}
    assert by_mac[BSSID]["kind"] == "ap" and by_mac[BSSID]["ssid"] == "HomeNet"
    assert by_mac["00:aa:bb:cc:dd:01"]["kind"] == "wifi_client"            # from the trimmed data frame
    assert by_mac["c4:11:22:33:44:01"]["kind"] == "ble" and by_mac["c4:11:22:33:44:01"]["name"] == "Kitchen Scale"
    radios = {r["addr"]: r for r in found["zigbee"]}
    assert radios["gpd:01020304"]["role"] == "green power" and "Battery-less switch" in radios["gpd:01020304"]["device"]
    assert "Mains-powered" in radios[EUI]["device"]
    assert [n["protocol"] for n in found["lora"]] == ["meshtastic"]


def test_replay_survives_damaged_lines_and_frames(ctx, tmp_path):
    path = tmp_path / "capture-20260101-000000.jsonl.gz"
    with gzip.open(path, "wt") as f:
        f.write("not json\n")
        f.write(json.dumps({"ts": 1, "radio": "wifi", "src": "x", "raw": "zz"}) + "\n")
        f.write(json.dumps({"ts": 1, "radio": "radar", "src": "x", "raw": "00"}) + "\n")
        for radio in capture.RADIOS:
            f.write(json.dumps({"ts": 1, "radio": radio, "src": "x", "raw": "00ff00ff"}) + "\n")
        f.write(json.dumps({"ts": 2, "radio": "wifi", "src": "x", "raw": beacon().hex(), "tuned": 2437}) + "\n")
    counts = capture.replay(str(path), ctx)
    assert counts["frames"] == {r: 1 if r != "wifi" else 2 for r in capture.RADIOS}
    assert [d["mac"] for d in capture.identified(ctx)["devices"]] == [BSSID]


def test_recording_stops_by_itself(tmp_path, monkeypatch):
    r = capture.RECORDER
    r.start(str(tmp_path / "c"), 1)
    r.record("bt", "bt:hci0", le_advert())
    deadline = time.time() + 5
    while r.active and time.time() < deadline:   # no frame arrives: the clock stops it
        time.sleep(0.1)
    assert not r.active and len(list(capture.read(r.path))) == 1
    r.record("bt", "bt:hci0", le_advert())       # after the end: ignored
    assert len(list(capture.read(r.path))) == 1
    monkeypatch.setattr(capture, "MAX_BYTES", 400)
    r.start(str(tmp_path / "d"), 60)
    for _ in range(20):
        r.record("bt", "bt:hci0", le_advert())
    assert not r.active and 1 <= len(list(capture.read(r.path))) < 20   # the size limit stops it too


def test_only_chosen_radios_are_recorded_and_one_recording_at_a_time(tmp_path):
    r = capture.RECORDER
    r.start(str(tmp_path / "c"), 60, ["bt"])
    with pytest.raises(RuntimeError):
        r.start(str(tmp_path / "c"), 60)
    r.record("wifi", "wifi:mon0", beacon())
    r.record("bt", "bt:hci0", le_advert())
    assert r.state()["counts"] == {"bt": 1}
    assert [x["radio"] for x in capture.read(r.stop())] == ["bt"]


def test_api_is_admin_only_and_file_names_are_not_paths(ctx, tmp_path):
    app = create_app(ctx)
    admin, viewer, anon = client(app, "admin"), client(app, "view"), client(app)
    for c in (viewer, anon):
        assert c.get("/api/captures").status_code in (401, 403)
        assert c.post("/api/captures", json={"seconds": 10}).status_code in (401, 403)
        assert c.get("/api/captures/capture-20260101-000000.jsonl.gz").status_code in (401, 403)
    started = admin.post("/api/captures", json={"seconds": 30, "radios": ["bt", "nonsense"]}).json()
    assert started["radios"] == ["bt"]
    assert admin.post("/api/captures", json={"seconds": 30}).status_code == 409        # one at a time
    capture.RECORDER.record("bt", "bt:hci0", le_advert())
    assert admin.get("/api/captures").json()["active"]["frames"] == 1
    assert admin.post("/api/captures/stop").status_code == 200
    listing = admin.get("/api/captures").json()
    assert listing["active"] is None and [f["name"] for f in listing["files"]] == [started["name"]]
    got = admin.get(f"/api/captures/{started['name']}")
    assert got.status_code == 200 and b"bt:hci0" in gzip.decompress(got.content)
    secret = tmp_path / "secret.txt"
    secret.write_text("no")
    for evil in ("../secret.txt", "..%2Fsecret.txt", "secret.txt", "capture-20260101-000000.jsonl.gz/../../secret.txt"):
        assert admin.get(f"/api/captures/{evil}").status_code == 404
        assert admin.delete(f"/api/captures/{evil}").status_code in (404, 405)
    assert secret.exists()
    assert admin.delete(f"/api/captures/{started['name']}").status_code == 200
    assert admin.get("/api/captures").json()["files"] == []
    assert admin.post("/api/captures", json={"seconds": 2}).status_code == 422 and admin.post("/api/captures", json={"seconds": 10 ** 6}).status_code == 422
    assert admin.post("/api/captures", json={"seconds": 30, "radios": ["nonsense"]}).status_code == 400


def test_no_recording_while_mac_privacy_is_on(ctx, monkeypatch):
    monkeypatch.setattr(macprivacy, "is_active", lambda: True)
    admin = client(create_app(ctx), "admin")
    assert admin.post("/api/captures", json={"seconds": 30}).status_code == 409
    assert "privacy" in admin.get("/api/captures").json()["blocked"] and not capture.RECORDER.active


def test_recording_from_the_start_by_environment(tmp_path, monkeypatch):
    cfg = Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path))
    capture.start_from_env(cfg)
    assert not capture.RECORDER.active
    monkeypatch.setenv("CAPTURE_AT_START", "30")
    capture.start_from_env(cfg)
    assert capture.RECORDER.active and capture.RECORDER.path.startswith(str(tmp_path / "captures"))
    capture.RECORDER.stop()


def test_replay_command(tmp_path, capsys):
    path = record_everything(tmp_path)
    assert capture.replay_cli([path]) == 0
    out = capsys.readouterr().out
    assert "wifi 2" in out and "HomeNet" in out and "Kitchen Scale" in out and "gpd:01020304" in out and "meshtastic" in out
    assert capture.replay_cli([path, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["frames"]["zigbee"] == 2 and any(d.get("ssid") == "HomeNet" for d in data["devices"])
    assert capture.replay_cli([]) == 2
