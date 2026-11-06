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


def replace_remote(sid, entries, now):
    """The latest report of a remote sensor: exactly the entries it sent, replacing (not merging with) the last report, so
    an error it has cleared, or an interface that is gone, disappears here too."""
    prefix = f"{sid}/"
    with _lock:
        new = {}
        for e in entries:
            name = prefix + e["name"]
            new[name] = {**{k: v for k, v in e.items() if k != "name"}, "name": name, "remote": sid, "reported": now}
        for k in [k for k, v in SENSORS.items() if v.get("remote") == sid and k not in new]:
            del SENSORS[k]
        SENSORS.update(new)


def remove_remote(sid):
    with _lock:
        for k in [k for k, v in SENSORS.items() if v.get("remote") == sid]:
            del SENSORS[k]


STALE_AFTER = 90  # seconds without a report before a remote sensor's entries count as offline (it reports every ~2 s)


def snapshot():
    """The entries as shown. A remote sensor that stopped reporting is offline: what it last said (a state, an error, a
    rate) says nothing about now, so it is replaced by "offline" and how long it has been quiet."""
    now = time.time()
    with _lock:
        out = []
        for v in SENSORS.values():
            e = dict(v)
            if e.get("remote") and now - (e.get("reported") or 0) > STALE_AFTER:
                e.update(state="offline", stale=True, quiet_for=int(now - (e.get("reported") or now)), pps=0.0, error=None, warning=None)
            out.append(e)
        return out
