"""Link quality per client (release 34): rates, MCS and retries of its data frames, each way, counted by the sensor per minute and
added up per hour by the server, with what they point to."""
import json
import struct
import time

import pytest
from test_hardening import client, ctx  # noqa: F401  (ctx is a fixture)

from sniffowireless import linkstats as ls, sample_frames as sf
from sniffowireless.sanitize import remote_observation
from sniffowireless.web import create_app

CLIENT, AP = "aa:bb:cc:00:00:01", "24:a4:3c:10:00:01"


def rt_legacy(rate_mbps, rssi=-60):
    return sf.radiotap(2437, rssi, int(rate_mbps * 2))


def rt_ht(idx, forty=False, sgi=False, rssi=-55):
    flags = (1 if forty else 0) | (4 if sgi else 0)
    return struct.pack("<BBHI", 0, 0, 12, (1 << 5) | (1 << 19)) + struct.pack("<bBBB", rssi, 0x07, flags, idx)


def rt_vht(mcs, nss, bw_code, sgi=False):
    body = struct.pack("<HBB", 0x0044, 0x04 if sgi else 0, bw_code) + bytes([mcs << 4 | nss, 0, 0, 0]) + bytes(4)
    return struct.pack("<BBHI", 0, 0, 8 + len(body), 1 << 21) + body


def rt_he(mcs, nss, bw, gi=0):
    data = [0x0020 | 0x4000, 0x0002, mcs << 8, 0, bw | gi << 4, nss]
    return struct.pack("<BBHI", 0, 0, 20, 1 << 23) + struct.pack("<6H", *data)


def mac(s):
    return bytes.fromhex(s.replace(":", ""))


def data(rt, up=True, retry=False, subtype=8, dst=None):
    fc0 = 0x08 | subtype << 4
    fc1 = (0x01 if up else 0x02) | (0x08 if retry else 0)
    a1, a2 = (mac(AP), mac(CLIENT)) if up else (dst or mac(CLIENT), mac(AP))
    return rt + bytes([fc0, fc1, 0, 0]) + a1 + a2 + mac(AP) + b"\0\0" + (b"\0\0" if subtype & 8 else b"") + b"payload"


@pytest.mark.parametrize("rt,rate,label", [
    (rt_legacy(54), 54, None),
    (rt_ht(15, forty=True, sgi=True), 300.0, "HT MCS 7 2SS 40"),
    (rt_ht(7), 65.0, "HT MCS 7 1SS 20"),
    (rt_vht(9, 2, 4, sgi=True), 867.0, "VHT MCS 9 2SS 80"),
    (rt_he(11, 2, 2), 1201.2, "HE MCS 11 2SS 80"),
    (rt_he(0, 1, 0, gi=2), 7.3, "HE MCS 0 1SS 20"),
])
def test_rate_from_radiotap(rt, rate, label):
    p = ls.phy(rt + b"\0" * 30)
    assert p["rate"] == pytest.approx(rate, abs=0.5) and p["mcs"] == label


def test_the_sensor_counts_data_frames():
    c = ls.LinkCounter()
    for i in range(10):
        c.feed(data(rt_ht(7, rssi=-61), up=True, retry=i < 3))
    for _ in range(5):
        c.feed(data(rt_he(9, 2, 2), up=False))
    c.feed(data(rt_ht(7), subtype=12))                      # QoS null: no data in it
    c.feed(data(rt_ht(7), up=False, dst=mac("01:00:5e:00:00:01")))   # multicast
    c.feed(sf.beacon())
    c.feed(b"\x01\x02")
    assert not c.due(time.time())
    obs = {o["dir"]: o for o in c.drain()}
    up, down = obs["up"], obs["down"]
    assert up["mac"] == CLIENT and up["bssid"] == AP and up["frames"] == 10 and up["retries"] == 3
    assert up["mcs"] == {"HT MCS 7 1SS 20": 10} and up["rates"] == {"65": 10} and up["rssi_sum"] == -610 and up["rssi_n"] == 10
    assert down["frames"] == 5 and down["rssi_n"] == 0 and list(down["mcs"]) == ["HE MCS 9 2SS 80"]
    assert c.drain() == []


def test_remote_link_observations_are_checked():
    now = time.time()
    o = {"t": "link", "ts": now, "mac": CLIENT.upper(), "bssid": AP, "dir": "up", "frames": 10, "retries": 2, "rssi_sum": -600, "rssi_n": 10,
         "rates": {"65": 10, "<b>": 1, "x" * 40: 1, "7": -1}, "mcs": {"HT MCS 7 1SS 20": 10, "a\nb": 3}, "evil": 1}
    r = remote_observation(o, now)
    assert r["mac"] == CLIENT and r["rates"] == {"65": 10} and r["mcs"] == {"HT MCS 7 1SS 20": 10} and "evil" not in r
    assert remote_observation({**o, "dir": "sideways"}, now) is None
    assert remote_observation({**o, "mac": "nonsense"}, now) is None


def obs(way, frames, retries, mcs, rssi=None, mac_=CLIENT, ts=None):
    rates = {}
    for label, n in mcs.items():
        p = ls.parse_mcs(label)
        rates[f"{round(ls.HT_VHT_20[p[1]] * p[2], 1):g}"] = n
    return {"t": "link", "ts": ts or time.time(), "mac": mac_, "bssid": AP, "dir": way, "frames": frames, "retries": retries,
            "rates": rates, "mcs": mcs, "rssi_sum": (rssi or 0) * 10, "rssi_n": 10 if rssi else 0}


def test_hours_add_up_and_the_verdicts(ctx):
    s = ctx.store
    s.process(obs("up", 600, 210, {"HT MCS 7 1SS 20": 400, "HT MCS 6 1SS 20": 200}, rssi=-52))           # interference
    s.process(obs("up", 400, 140, {"HT MCS 7 1SS 20": 400}, rssi=-52))
    s.process(obs("down", 900, 20, {"HT MCS 7 1SS 20": 900}))
    s.process(obs("up", 500, 10, {"HT MCS 1 1SS 20": 400, "HT MCS 2 1SS 20": 100}, rssi=-79, mac_="aa:bb:cc:00:00:02"))   # weak
    s.process(obs("up", 20, 0, {"HT MCS 7 1SS 20": 20}, mac_="aa:bb:cc:00:00:03"))                       # too little
    s.flush()
    s.process(obs("up", 100, 0, {"HT MCS 7 1SS 20": 100}, rssi=-52))   # a second flush merges into the same hour
    s.flush()
    row = ctx.one("SELECT frames, retries, mcs FROM link_stats WHERE mac=? AND dir='up'", (CLIENT,))
    assert row["frames"] == 1100 and row["retries"] == 350 and json.loads(row["mcs"]) == {"HT MCS 7 1SS 20": 900, "HT MCS 6 1SS 20": 200}
    one = ls.client_link(ctx, CLIENT, time.time() - 3600)
    up = one["up"]
    assert up["verdict"]["level"] == "bad" and up["verdict"]["short"] == "interference" and up["mcs_median"] == 7 and up["rssi"] == -52
    assert up["phy"] == "HT" and up["nss"] == 1 and up["width"] == 20 and up["median_rate"] == 65
    assert one["down"]["verdict"]["level"] == "ok"
    weak = ls.client_link(ctx, "aa:bb:cc:00:00:02", time.time() - 3600)["up"]
    assert weak["verdict"]["short"] == "weak signal" and "-79 dBm" in weak["verdict"]["text"]
    listing = ls.clients(ctx, time.time() - 3600)
    assert [c["verdict"]["level"] for c in listing] == ["bad", "warn", "none"]


def test_legacy_only():
    s = ls.summarize([{"frames": 400, "retries": 4, "rssi_sum": 0, "rssi_n": 0, "rates": json.dumps({"1": 100, "2": 100, "11": 200}), "mcs": "{}", "bssid": AP}])
    assert s["phy"] == "legacy" and s["verdict"]["short"] == "legacy rates" and "802.11b" in s["verdict"]["text"]


def test_routes(ctx):
    ctx.store.process(obs("up", 600, 6, {"HT MCS 7 1SS 20": 600}, rssi=-50))
    ctx.store.flush()
    app = create_app(ctx)
    v = client(app, "view")
    assert v.get(f"/api/link/{CLIENT}").json()["up"]["verdict"]["level"] == "ok"
    assert v.get(f"/api/link?bssid={AP}").json()["clients"][0]["mac"] == CLIENT
    assert v.get("/api/link?bssid=00:00:00:00:00:01").json()["clients"] == []


def test_old_data_is_pruned(ctx):
    ctx.store.process(obs("up", 600, 6, {"HT MCS 7 1SS 20": 600}, ts=time.time() - 400 * 86400))
    ctx.store.flush()
    ctx.store.prune(time.time())
    assert ctx.one("SELECT COUNT(*) n FROM link_stats")["n"] == 0
