"""The logs of remote sensors on the Logs page: a sensor sends its new lines with each upload, the server keeps them per sensor."""
import logging
import time

from sniffowireless import logs, sanitize
from sniffowireless.logs import REMOTE, RemoteLogs

from tests.test_lora import ctx  # noqa: F401
from tests.test_lora_select import admin_client


def line(i, level="INFO", msg="hello", **kw):
    return {"id": i, "ts": time.time(), "level": level, "logger": "sniffowireless.bt", "msg": msg, "thread": "bt:hci0", **kw}


def test_a_remote_line_is_cleaned():
    now = time.time()
    ok = sanitize.remote_log_line(line(5, msg="a\x00b‮c\nTraceback\n  boom"), now, adjust=0)
    assert ok["msg"] == "abc\nTraceback\n  boom" and ok["level"] == "INFO" and ok["src_id"] == 5
    assert sanitize.remote_log_line(line(1, level="LOUD"), now) is None and sanitize.remote_log_line("x", now) is None
    assert sanitize.remote_log_line({"level": "INFO", "msg": 5}, now) is None
    assert len(sanitize.remote_log_line(line(1, msg="x" * 9000), now)["msg"]) == 2000
    far = sanitize.remote_log_line(line(1, ts=now + 10 ** 6), now)
    assert abs(far["ts"] - now) < 5                                   # an absurd time is replaced
    moved = sanitize.remote_log_line(line(1, ts=now - 100), now, adjust=60)
    assert abs(moved["ts"] - (now - 40)) < 1                          # the sensor's clock offset is applied


def lines(*ids, **kw):
    now = time.time()
    return [sanitize.remote_log_line(line(i, **kw), now) for i in ids]


def test_buffer_orders_dedupes_and_survives_a_restart():
    r = RemoteLogs()
    r.add("garden", "aaaa", lines(1, 2, 3))
    r.add("garden", "aaaa", lines(2, 3, 4))                           # an upload retried after a lost answer: no doubles
    assert [x["id"] for x in r.since("garden")] == [1, 2, 3, 4] and r.count("garden") == 4
    assert [x["id"] for x in r.since("garden", after=2)] == [3, 4]
    r.add("garden", "bbbb", lines(1, 2))                              # the sensor restarted and counts from 1 again
    assert [x["id"] for x in r.since("garden")] == [1, 2, 3, 4, 5, 6]
    assert r.since("shed") == [] and r.count("shed") == 0
    r.drop("garden")
    assert r.count("garden") == 0


def test_buffer_is_bounded_and_redacts_secrets():
    r = RemoteLogs()
    r.add("s", "e", lines(*range(1, logs.REMOTE_BATCH + 1)))
    for k in range(20):
        r.add("s", "e", lines(*range(1000 * (k + 1), 1000 * (k + 1) + logs.REMOTE_BATCH)))
    assert r.count("s") == logs.REMOTE_CAPACITY
    r.add("t", "e", lines(1, msg="token sniffowireless_" + "A" * 30 + " and setup code: 1234-ABCD"))
    m = r.since("t")[0]["msg"]
    assert "AAAA" not in m and "1234-ABCD" not in m and "••••" in m


def test_the_sensor_sends_its_new_lines_and_the_api_shows_them_per_sensor(ctx):  # noqa: F811
    from fastapi.testclient import TestClient
    from sniffowireless.web import create_app
    c = admin_client(ctx)
    tok = c.post("/api/sensors", json={"name": "Shed", "room": None}).json()
    s = TestClient(create_app(ctx), base_url="http://sniffowireless.test")
    h = {"Authorization": f"Bearer {tok['token']}", "x-sniffowireless": "1"}
    batch = {"obs": [], "status": [], "log_epoch": "ab12", "logs": [line(1, msg="Wi-Fi sensor on wlan1"), line(2, "ERROR", "capture stopped"),
                                                                       {"id": 3, "level": "NOPE", "msg": "dropped"}, "garbage"]}
    assert s.post("/api/ingest", headers=h, json=batch).status_code == 200
    assert s.post("/api/ingest", headers=h, json=batch).status_code == 200     # a retry adds nothing
    snap = c.get("/api/logs", params={"sensor": tok["id"]}).json()
    assert [x["msg"] for x in snap["items"]] == ["Wi-Fi sensor on wlan1", "capture stopped"] and snap["level"] is None
    assert snap["sensor"] == tok["id"] and snap["capacity"] == logs.REMOTE_CAPACITY
    assert snap["sensors"] == [{"id": tok["id"], "name": "Shed", "online": True, "lines": 2}]
    own = c.get("/api/logs").json()                                            # this server's own tab is unchanged
    assert own["sensor"] == "" and own["level"] and own["sensors"][0]["id"] == tok["id"]
    assert c.get("/api/logs", params={"sensor": "ghost"}).status_code == 404
    assert c.get("/api/logs", params={"sensor": tok["id"], "after": snap["items"][0]["id"]}).json()["items"][0]["msg"] == "capture stopped"
    # admin only, and the lines leave with the sensor
    v = TestClient(create_app(ctx), base_url="http://sniffowireless.test")
    assert v.post("/api/auth/login", json={"username": "view", "password": "correct-horse-battery"}).status_code == 200
    assert v.get("/api/logs", params={"sensor": tok["id"]}).status_code == 403
    assert c.delete(f"/api/sensors/{tok['id']}").status_code == 200
    assert REMOTE.count(tok["id"]) == 0


def test_the_forwarder_sends_each_line_once_and_only_after_a_good_post(monkeypatch):
    import gzip
    import json
    import threading
    from sniffowireless.config import Config
    from sniffowireless.sensors import Forwarder
    cfg = Config(server_url="http://x.test", sensor_token="sniffowireless_" + "a" * 30)
    f = Forwarder(cfg)
    sent, fail = [], [True]

    def post(body):
        sent.append(json.loads(gzip.decompress(body)))
        if fail[0]:
            raise OSError("down")
        return b"{}"
    monkeypatch.setattr(f, "_post", post)
    monkeypatch.setattr(logs.HANDLER, "buf", logs.HANDLER.buf.__class__(maxlen=50))
    log = logging.getLogger("sniffowireless.test")
    log.setLevel(logging.INFO)
    logs.install(logging.INFO)
    f.log_cursor = logs.HANDLER.seq
    log.info("first line")
    stop = threading.Event()
    real_wait = stop.wait
    calls = [0]

    def wait(t):
        calls[0] += 1
        if calls[0] == 3:
            fail[0] = False
        if calls[0] == 5:
            stop.set()
        return stop.is_set() and calls[0] > 5
    monkeypatch.setattr(stop, "wait", wait)
    f.run(stop)
    real_wait(0)
    got = [[x["msg"] for x in b["logs"] if x["logger"] == "sniffowireless.test"] for b in sent]
    assert got[0] == ["first line"] and got[1] == ["first line"]      # the failed post is retried with the same line
    assert got[2] == ["first line"]                                   # and the one that went through
    assert got[3:] and all(g == [] for g in got[3:])                  # then it is not sent again
    assert all(b["log_epoch"] == f.log_epoch for b in sent)
