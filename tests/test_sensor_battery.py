"""A sensor's battery: what a remote sensor (the Android app) may send, the server's own from sysfs, and where it shows."""
import gzip
import json
import os
import time

import pytest
from fastapi.testclient import TestClient

from sniffowireless import sanitize, status, sysinfo
from sniffowireless.auth import hash_password
from sniffowireless.config import Config
from sniffowireless.main import build
from sniffowireless.web import create_app

PW = "correct-horse-battery"


def test_battery_from_a_remote_sensor_is_validated():
    s = sanitize.remote_system({"battery": {"percent": 54.26, "charging": True, "source": "usb", "temperature": 31.5}})
    assert s == {"battery": {"percent": 54.3, "charging": True, "source": "usb", "temperature": 31.5}}
    assert sanitize.remote_system({"battery": {"percent": 140}}) is None          # out of range: no battery at all
    assert sanitize.remote_system({"battery": {"charging": True}}) is None        # no level, nothing to show
    s = sanitize.remote_system({"battery": {"percent": 9, "charging": "yes", "source": "<b>nuclear</b>", "temperature": 999}})
    assert s == {"battery": {"percent": 9}}
    s = sanitize.remote_system({"cpu": {"cores": 4}, "battery": "full"})
    assert "battery" not in s


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text + "\n")


def test_the_machines_own_battery(tmp_path, monkeypatch):
    root = tmp_path / "ps"
    monkeypatch.setattr(sysinfo, "POWER_SUPPLY", str(root))
    assert sysinfo.battery() is None                                      # no such folder: a desktop or a Pi
    os.makedirs(root)
    write(f"{root}/AC/type", "Mains")
    write(f"{root}/AC/online", "0")
    write(f"{root}/BAT0/type", "Battery")
    write(f"{root}/BAT0/capacity", "42")
    write(f"{root}/BAT0/status", "Discharging")
    assert sysinfo.battery() == {"percent": 42, "charging": False, "source": None}
    write(f"{root}/AC/online", "1")
    write(f"{root}/BAT0/status", "Charging")
    assert sysinfo.battery() == {"percent": 42, "charging": True, "source": "ac"}
    assert sysinfo.snapshot(str(tmp_path / "x.db"), str(tmp_path))["battery"]["percent"] == 42


@pytest.fixture
def ctx(tmp_path):
    status.SENSORS.clear()
    status.SYSTEMS.clear()
    c = build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))
    with c.wdb() as w:
        w.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('admin', ?, 'admin', 0)", (hash_password(PW, iterations=1000),))
    return c


def test_a_phone_sends_its_battery_and_it_shows_with_the_sensor(ctx):
    app = create_app(ctx)
    c = TestClient(app, base_url="http://sniffowireless.test", headers={"x-sniffowireless": "1"})
    assert c.post("/api/auth/login", json={"username": "admin", "password": PW}).status_code == 200
    r = c.post("/api/sensors", json={"name": "Phone", "room": "Hall"}).json()
    phone = TestClient(app, base_url="http://sniffowireless.test", headers={"authorization": f"Bearer {r['token']}", "content-encoding": "gzip",
                                                                            "content-type": "application/json"})
    body = {"sent_at": time.time(), "obs": [], "status": [{"name": "wifi:phone", "type": "wifi", "state": "capturing"}],
            "system": {"memory": {"total": 8 << 30, "used": 3 << 30}, "battery": {"percent": 17, "charging": False}}}
    assert phone.post("/api/ingest", content=gzip.compress(json.dumps(body).encode())).status_code == 200
    got = next(x for x in c.get("/api/status").json()["sensor_systems"] if x["id"] == r["id"])
    assert got["system"]["battery"] == {"percent": 17, "charging": False} and got["name"] == "Phone"
    metrics = c.get("/metrics").text
    assert f'sniffowireless_sensor_battery_percent{{sensor="{r["id"]}"}} 17' in metrics
    assert f'sniffowireless_sensor_battery_charging{{sensor="{r["id"]}"}} 0' in metrics
    # an app version without a battery: the field just isn't there
    body["system"] = {"memory": {"total": 8 << 30, "used": 3 << 30}}
    phone.post("/api/ingest", content=gzip.compress(json.dumps(body).encode()))
    got = next(x for x in c.get("/api/status").json()["sensor_systems"] if x["id"] == r["id"])
    assert "battery" not in got["system"]
