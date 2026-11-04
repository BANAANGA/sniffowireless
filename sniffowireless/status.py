"""Shared, in-memory sensor status shown in the web UI."""
import threading
import time

_lock = threading.Lock()
SENSORS = {}


def register(name, **fields):
    with _lock:
        SENSORS[name] = {"name": name, "state": "starting", "error": None,
                         "packets": 0, "pps": 0.0, "since": time.time(), **fields}
        return SENSORS[name]


def update(name, **fields):
    with _lock:
        SENSORS.setdefault(name, {"name": name}).update(fields)


def snapshot():
    with _lock:
        return [dict(v) for v in SENSORS.values()]
