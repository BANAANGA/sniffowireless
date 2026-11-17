"""Connection steps, attempts and roams (release 34): from the frames a client and its access point exchange, which step of a
connection failed and why, and how long a roam took."""
import struct
import time

import pytest
from test_hardening import client as http, ctx  # noqa: F401  (ctx is a fixture)

from sniffowireless import joins
from sniffowireless.sanitize import remote_observation
from sniffowireless.web import create_app

CL, AP1, AP2 = "aa:bb:cc:00:00:01", "24:a4:3c:10:00:01", "24:a4:3c:10:00:02"
RT = struct.pack("<BBHI", 0, 0, 9, 1 << 5) + struct.pack("b", -61)   # radiotap: antenna signal only


def m(s):
    return bytes.fromhex(s.replace(":", ""))


def mgmt(sub, body, from_ap, ap=AP1, protected=False):
    a1, a2 = (m(CL), m(ap)) if from_ap else (m(ap), m(CL))
    return RT + bytes([sub << 4, 0x40 if protected else 0, 0, 0]) + a1 + a2 + m(ap) + b"\0\0" + body


def auth(algo=0, seq=1, status=0, from_ap=False, ap=AP1):
    return mgmt(11, struct.pack("<HHH", algo, seq, status), from_ap, ap)


def assoc(ap=AP1):
    return mgmt(0, struct.pack("<HH", 0x0411, 10) + b"\x00\x04Home", False, ap)


def reassoc(ap=AP2, current=AP1):
    return mgmt(2, struct.pack("<HH", 0x0411, 10) + m(current) + b"\x00\x04Home", False, ap)


def assoc_resp(status=0, ap=AP1, sub=1):
    return mgmt(sub, struct.pack("<HHH", 0x0411, status, 0xC001), True, ap)


def deauth(reason, from_ap=True, ap=AP1):
    return mgmt(12, struct.pack("<H", reason), from_ap, ap)


def eapol(body, from_ap, ap=AP1, etype=3):
    fc1 = 0x02 if from_ap else 0x01
    a1, a2 = (m(CL), m(ap)) if from_ap else (m(ap), m(CL))
    payload = joins.SNAP_EAPOL + bytes([2, etype]) + struct.pack(">H", len(body)) + body
    return RT + bytes([0x88, fc1, 0, 0]) + a1 + a2 + m(ap) + b"\0\0" + b"\0\0" + payload


def key(n, ap=AP1):
    ki = {1: 0x008A, 2: 0x010A, 3: 0x13CA, 4: 0x030A}[n]
    return eapol(bytes([2]) + struct.pack(">H", ki) + bytes(92), n in (1, 3), ap)


def eap(code, t=None, from_ap=True):
    body = bytes([code, 1]) + struct.pack(">H", 5 if t else 4) + (bytes([t]) if t else b"")
    return eapol(body, from_ap, etype=0)


def btm_req(ap=AP1):
    return mgmt(13, bytes([10, 7, 1, 0x01, 0, 0, 0]), True, ap)


def test_steps_of_each_frame():
    assert joins.steps(auth())[0] == {"mac": CL, "bssid": AP1, "from_ap": False, "rssi": -61, "step": "auth", "algo": 0, "seq": 1, "code": 0}
    assert joins.steps(auth(3, 1, 0, True))[0]["from_ap"] is True and joins.steps(auth(3, 1, 0, True))[0]["rssi"] is None
    assert joins.steps(reassoc())[0] == {"mac": CL, "bssid": AP2, "from_ap": False, "rssi": -61, "step": "reassoc", "detail": AP1}
    assert joins.steps(assoc_resp(17))[0]["code"] == 17
    assert [joins.steps(key(n))[0]["step"] for n in (1, 2, 3, 4)] == ["m1", "m2", "m3", "m4"]
    assert joins.steps(eapol(bytes([2]) + struct.pack(">H", 0x1382) + bytes(92), True)) == []   # group key handshake
    assert joins.steps(eap(1, 25))[0] == {"mac": CL, "bssid": AP1, "from_ap": True, "rssi": None, "step": "eap", "code": 25, "detail": "PEAP"}
    assert joins.steps(eap(4))[0]["step"] == "eap_failure"
    assert joins.steps(deauth(15))[0]["code"] == 15
    assert joins.steps(btm_req())[0]["step"] == "btm_req"
    assert joins.steps(mgmt(12, b"\x0f\x00", True, protected=True)) == []    # a protected deauth: not readable
    assert joins.steps(mgmt(8, bytes(12), True)) == []                      # a beacon
    assert joins.steps(b"\x00\x00\x08") == []


def test_a_deauth_flood_is_capped():
    w = joins.JoinWatcher()
    got = sum(len(w.feed(deauth(7), 100.0 + i / 1000)) for i in range(500))
    assert got == joins.FLOOD


def run(frames, t0=1_000_000.0):
    """Frames (with the gap in seconds before each) as stored steps, then as attempts."""
    w, ev, t = joins.JoinWatcher(), [], t0
    for gap, f in frames:
        t += gap
        for o in w.feed(f, t):
            ev.append({**o, "code": o.get("code"), "algo": o.get("algo"), "seq": o.get("seq"), "detail": o.get("detail"), "sensor": "local"})
    tries, gone = joins.attempts(ev)
    return [a.as_dict({AP1: "Home", AP2: "Home"}) for a in tries], gone


OPEN = [(0, auth()), (0.002, auth(from_ap=True)), (0.003, assoc()), (0.004, assoc_resp())]


def test_a_good_wpa2_connection():
    tries, _ = run(OPEN + [(0.005, key(1)), (0.003, key(2)), (0.004, key(3)), (0.002, key(4))])
    a = tries[0]
    assert a["outcome"] == "connected" and a["method"] == "PSK" and a["duration_ms"] == pytest.approx(23, abs=0.5)
    assert [s["step"] for s in a["steps"]] == ["auth", "auth", "assoc", "assoc_resp", "m1", "m2", "m3", "m4"]


def test_wrong_password():
    tries, _ = run(OPEN + [(0.005, key(1)), (0.003, key(2)), (1, key(1)), (0.003, key(2)), (1, key(1)), (0.003, key(2)), (1, deauth(15))])
    a = tries[0]
    assert a["outcome"] == "failed" and a["why"].startswith("The access point ended it") and "Wrong password" in a["why"]
    assert a["cause"] == "Wrong password"


def test_the_client_never_answers():
    tries, _ = run(OPEN + [(0.005, key(1)), (1, key(1)), (1, key(1))], t0=time.time() - 3600)
    assert tries[0]["outcome"] == "failed" and "never answered message 1" in tries[0]["why"]


def test_refused_association():
    tries, _ = run([(0, auth()), (0.002, auth(from_ap=True)), (0.003, assoc()), (0.004, assoc_resp(17))])
    assert tries[0]["outcome"] == "failed" and "unable to handle additional" in tries[0]["why"] and "as many clients" in tries[0]["why"]
    assert tries[0]["cause"] == "Access point full"
    tries, _ = run([(0, auth(3)), (0.01, auth(3, 1, 77, True))])
    assert tries[0]["method"] == "SAE" and "password identifier" in tries[0]["why"]


def test_enterprise_login_rejected():
    tries, _ = run(OPEN + [(0.01, eap(1, 1)), (0.01, eap(2, 1, False)), (0.05, eap(1, 25)), (0.3, eap(4))])
    assert tries[0]["outcome"] == "failed" and tries[0]["method"] == "802.1X" and "EAP-Failure" in tries[0]["why"]


def test_sae_two_exchanges_are_one_attempt():
    tries, _ = run([(0, auth(3, 1)), (0.01, auth(3, 1, 0, True)), (0.01, auth(3, 2)), (0.01, auth(3, 2, 0, True)), (0.003, assoc()),
                    (0.004, assoc_resp()), (0.005, key(1)), (0.003, key(2)), (0.004, key(3)), (0.002, key(4))])
    assert len(tries) == 1 and tries[0]["outcome"] == "connected" and tries[0]["method"] == "SAE"


def test_only_part_heard():
    tries, _ = run([(0, auth())], t0=time.time() - 3600)
    assert tries[0]["outcome"] == "incomplete"


def test_roams_and_disconnects():
    first = OPEN + [(0.005, key(1)), (0.003, key(2)), (0.004, key(3)), (0.002, key(4))]
    ft = [(30, btm_req()), (2, auth(2, 1, 0, False, AP2)), (0.004, auth(2, 2, 0, True, AP2)), (0.003, reassoc()),
          (0.005, assoc_resp(0, AP2, 3))]
    slow = [(60, reassoc(AP1, AP2)), (0.004, assoc_resp(0, AP1, 3)), (0.02, eap(1, 1)), (0.3, eap(3)), (0.01, key(1)), (0.003, key(2)),
            (0.004, key(3)), (0.002, key(4)), (100, deauth(3))]
    tries, gone = run(first + ft + slow)
    assert [a["outcome"] for a in tries] == ["connected"] * 3
    r = joins.roams(tries)
    assert [(x["from"], x["to"]) for x in r] == [(AP1, AP2), (AP2, AP1)]
    assert r[0]["method"] == "FT" and r[0]["steered"] and r[0]["grade"] == "fast" and r[0]["ms"] == pytest.approx(12, abs=0.5)
    assert r[1]["grade"] == "slow" and r[1]["ms"] > 300
    assert len(gone) == 1 and gone[0]["code"] == 3


def test_remote_steps_are_checked():
    now = time.time()
    o = {"t": "join", "ts": now, "mac": CL, "bssid": AP1, "step": "reassoc", "detail": AP2.upper(), "code": 99999, "evil": 1, "from_ap": 0}
    r = remote_observation(o, now)
    assert r["detail"] == AP2 and "code" not in r and "evil" not in r
    assert remote_observation({**o, "step": "rm -rf"}, now) is None


def feed(ctx, frames, t0):
    w, t = joins.JoinWatcher(), t0
    for gap, f in frames:
        t += gap
        for o in w.feed(f, t):
            ctx.store.process(o)
            ctx.store.process(dict(o))   # a second sensor heard the same frame: kept once
    ctx.store.flush()


def test_site_summary_and_routes(ctx):
    t0 = time.time() - 600
    feed(ctx, OPEN + [(0.005, key(1)), (0.003, key(2)), (1, key(1)), (0.003, key(2)), (1, deauth(15))], t0)
    assert ctx.one("SELECT COUNT(*) n FROM join_events")["n"] == 9   # each step once, though two sensors heard it
    ctx.execute("INSERT INTO devices(mac, kind, ssid, last_seen) VALUES(?, 'ap', 'Home', ?)", (AP1, time.time()))
    ctx.settings.set("networks", {"ssids": ["Home"], "trusted_bssids": []})
    app = create_app(ctx)
    v = http(app, "view")
    one = v.get(f"/api/joins/{CL}").json()
    assert one["attempts"][0]["outcome"] == "failed" and one["attempts"][0]["ssid"] == "Home"
    s = v.get("/api/joins?hours=1").json()
    assert s["counts"]["failed"] == 1 and s["causes"][0]["count"] == 1 and s["causes"][0]["cause"] == "Wrong password"
    ctx.settings.set("networks", {"ssids": ["Other"], "trusted_bssids": []})
    assert v.get("/api/joins?hours=1").json()["counts"]["attempts"] == 0   # not on my networks


def test_old_steps_are_pruned(ctx):
    feed(ctx, OPEN, time.time() - 400 * 86400)
    ctx.store.prune(time.time())
    assert ctx.one("SELECT COUNT(*) n FROM join_events")["n"] == 0
