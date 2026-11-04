"""MQTT presence publish: these tests start a real local mosquitto broker (skipped if it isn't installed,
e.g. in a minimal CI image) and check what actually comes out the other end, not just that nothing raises."""
import json
import shutil
import socket
import subprocess
import threading
import time

import pytest

pytest.importorskip("paho.mqtt.client")
import paho.mqtt.client as mqtt  # noqa: E402

from sniffowireless.auth import hash_password  # noqa: E402
from sniffowireless.config import Config  # noqa: E402
from sniffowireless.main import build  # noqa: E402
from sniffowireless.manage import apply_meta  # noqa: E402

MAC = "a4:83:e7:01:00:0b"
OTHER = "a4:83:e7:01:00:0c"  # never labelled/known: presence for it must never be published
H = {"X-Sniffowireless": "1"}
PW = "correct-horse-battery"


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def broker(tmp_path_factory):
    if not shutil.which("mosquitto"):
        pytest.skip("mosquitto not installed")
    port = _free_port()
    conf = tmp_path_factory.mktemp("mosquitto") / "mosquitto.conf"
    conf.write_text(f"listener {port}\nallow_anonymous true\n")
    p = subprocess.Popen(["mosquitto", "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    try:
        yield port
    finally:
        p.terminate()
        p.wait(timeout=5)


@pytest.fixture
def ctx(tmp_path):
    return build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))


@pytest.fixture
def env(tmp_path):
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from sniffowireless.web import create_app

    c = build(Config(db_path=str(tmp_path / "t2.db"), data_dir=str(tmp_path)))
    with c.wdb() as db:
        db.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('admin', ?, 'admin', 0)",
                   (hash_password(PW, iterations=1000),))
    client = TestClient(create_app(c), base_url="http://sniffowireless.test")
    assert client.post("/api/auth/login", json={"username": "admin", "password": PW}).status_code == 200
    return c, client


class Subscriber:
    """A plain MQTT client that records everything published under the topic prefix."""

    def __init__(self, port):
        self.received = []
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.client.on_message = lambda c, u, m: self.received.append((m.topic, m.payload.decode()))
        self.client.connect("127.0.0.1", port)
        self.client.subscribe("sniffowireless/#")
        self.client.loop_start()
        time.sleep(0.3)

    def wait_for(self, n, timeout=5):
        deadline = time.time() + timeout
        while len(self.received) < n and time.time() < deadline:
            time.sleep(0.05)
        return self.received

    def close(self):
        self.client.loop_stop()
        self.client.disconnect()


def _enable(ctx, port):
    ctx.settings.set("mqtt", {"enabled": True, "host": "127.0.0.1", "port": port, "username": "", "password": "",
                              "tls": False, "topic_prefix": "sniffowireless", "qos": 0, "retain": True})
    stop = threading.Event()
    ctx.mqtt.start(stop)
    deadline = time.time() + 5
    while not ctx.mqtt.connected and time.time() < deadline:
        time.sleep(0.1)
    assert ctx.mqtt.connected, ctx.mqtt.last_error
    return stop


def test_presence_published_for_labelled_devices_only(ctx, broker):
    sub = Subscriber(broker)
    try:
        with ctx.wdb() as c:
            c.execute("INSERT INTO device_meta(mac, label, known, updated) VALUES(?, 'Alex phone', 1, ?)", (MAC, time.time()))
        apply_meta(ctx)
        stop = _enable(ctx, broker)
        sub.wait_for(1)
        assert ("sniffowireless/status", "online") in sub.received
        sub.received.clear()

        s = ctx.store
        t0 = time.time() - 10000
        for mac in (MAC, OTHER):
            s.process({"t": "wifi_client", "ts": t0, "mac": mac, "frame": "data", "rssi": -50})
        s.flush()
        s.sweep(t0 + 1000)  # both presence sessions time out ("left")
        s.flush()
        sub.wait_for(1)

        topics = {t for t, _ in sub.received}
        assert f"sniffowireless/presence/{MAC.replace(':', '')}" in topics
        assert f"sniffowireless/presence/{OTHER.replace(':', '')}" not in topics  # not labelled/known
        payload = json.loads(next(p for t, p in sub.received if MAC.replace(":", "") in t))
        assert payload == {"state": "away", "mac": MAC, "label": "Alex phone", "name": None, "ts": t0}

        sub.received.clear()
        t1 = time.time()
        s.process({"t": "wifi_client", "ts": t1, "mac": MAC, "frame": "data", "rssi": -50})  # returns -> "arrived"
        s.flush()
        sub.wait_for(1)
        payload = json.loads(sub.received[0][1])
        assert payload["state"] == "home" and payload["mac"] == MAC
        stop.set()
    finally:
        sub.close()


def test_mqtt_settings_api(env):
    ctx, c = env
    r = c.get("/api/settings/mqtt").json()
    assert r["enabled"] is False and r["host"] == "" and "status" in r

    body = {"enabled": True, "host": "mqtt.example", "port": 1883, "username": "u", "password": "secret",
           "tls": False, "topic_prefix": "sniffowireless", "qos": 0, "retain": True}
    assert c.put("/api/settings/mqtt", json=body, headers=H).status_code == 200
    got = c.get("/api/settings/mqtt").json()
    assert got["host"] == "mqtt.example" and got["password"] == "••••••••"  # never echoed back in the clear

    # Saving again with the masked placeholder keeps the real password rather than overwriting it with the mask.
    body2 = {**body, "password": "••••••••", "host": "mqtt2.example"}
    assert c.put("/api/settings/mqtt", json=body2, headers=H).status_code == 200
    assert ctx.settings.get("mqtt")["password"] == "secret"

    # mqtt2.example won't resolve/connect: the test endpoint reports that cleanly rather than a 500 or a hang.
    assert c.post("/api/settings/mqtt/test", headers=H).status_code == 400
