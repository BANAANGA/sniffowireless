"""Admin-editable settings stored as JSON in the database (key/value)."""
import copy
import json
import threading
from contextlib import closing

DEFAULTS = {
    # Devices / networks that are dropped before anything is stored.
    "ignore": {"macs": [], "prefixes": [], "ssids": []},  # ssids: [{"ssid": str, "clients": bool}]
    # "My networks": enables network-health views and evil-twin detection.
    "networks": {"ssids": [], "trusted_bssids": []},
    "security": {"deauth_threshold": 25, "deauth_window": 10, "karma_ssids": 4, "karma_window": 600},
    "report": {"email": False, "notifier_id": None, "weekday": 0, "hour": 8, "last_sent": 0},
    "floorplan": {"image": None, "width": None, "height": None},
    "lan": {"trusted_dhcp": []},
}


class Settings:
    def __init__(self, connect):
        self.connect = connect
        self.lock = threading.Lock()
        self.cache = {}
        self.listeners = []
        with closing(self.connect()) as c:
            c.execute("CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT)")
            for k, v in c.execute("SELECT key, value FROM settings"):
                try:
                    self.cache[k] = json.loads(v)
                except ValueError:
                    pass

    def get(self, key):
        with self.lock:
            v = self.cache.get(key)
        d = copy.deepcopy(DEFAULTS.get(key))
        if isinstance(d, dict) and isinstance(v, dict):
            d.update(v)
            return d
        return copy.deepcopy(v) if v is not None else d

    def set(self, key, value):
        with closing(self.connect()) as c:
            c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)", (key, json.dumps(value)))
        with self.lock:
            self.cache[key] = copy.deepcopy(value)
        for fn in self.listeners:
            fn(key)

    def on_change(self, fn):
        self.listeners.append(fn)
