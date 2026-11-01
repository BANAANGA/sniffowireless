"""Synthetic data generator so the UI can be explored without radio hardware (DEMO_MODE=1)."""
import hashlib
import logging
import random
import time

from .config import band_of, ch_to_freq, freq_to_channel
from .oui import bt_company

log = logging.getLogger("yolo.demo")

APS = [
    ("24:a4:3c:10:00:01", "HomeNet", 1, "WPA2/PSK", -42, "Ubiquiti"),
    ("24:a4:3c:10:00:02", "HomeNet", 36, "WPA2/PSK", -55, "Ubiquiti"),
    ("50:c7:bf:20:00:03", "HomeNet-IoT", 6, "WPA2/PSK", -48, "TP-Link"),
    ("a0:40:a0:30:00:04", "Vodafone-7F2A", 11, "WPA2/PSK,WPA3/SAE", -71, "Netgear"),
    ("a0:40:a0:30:00:05", "Ziggo5G-Neighbour", 44, "WPA3/SAE", -78, "Netgear"),
    ("00:1d:7e:40:00:06", "Linksys", 11, "OPN", -83, "Cisco-Linksys"),
    ("50:c7:bf:20:00:07", "", 6, "WPA2/PSK", -66, "TP-Link"),
    ("f4:f5:d8:50:00:08", "Bakery Guest", 1, "OPN", -80, "Google"),
    ("24:a4:3c:10:00:09", "HomeNet", ("6", 37), "WPA3/SAE", -58, "Ubiquiti"),
]


def _freq(ch):
    return ch_to_freq(ch[1], ch[0]) if isinstance(ch, tuple) else ch_to_freq(ch)


def _radio(ch):
    f = _freq(ch)
    return {"freq": f, "channel": freq_to_channel(f), "band": band_of(f)}

# mac, vendor, schedule, preferred AP index(es), base rssi, probes
CLIENTS = [
    ("a4:83:e7:01:00:01", "Apple", "resident", (0, 1, 8), -50, ["HomeNet", "Office-WLAN"]),
    ("a4:83:e7:01:00:02", "Apple", "worker", (0, 1), -58, ["HomeNet", "eduroam"]),
    ("5c:0a:5b:01:00:03", "Samsung", "evening", (0, 1), -61, ["HomeNet"]),
    ("a0:a8:cd:01:00:04", "Intel", "worker", (1, 8), -47, ["HomeNet", "KPN"]),
    ("b8:27:eb:01:00:05", "Raspberry Pi", "always", (0,), -39, []),
    ("24:0a:c4:01:00:06", "Espressif", "always", (2,), -52, []),
    ("24:0a:c4:01:00:07", "Espressif", "always", (2,), -63, []),
    ("fc:65:de:01:00:08", "Amazon", "always", (2,), -57, []),
    ("5c:aa:fd:01:00:09", "Sonos", "always", (1,), -49, []),
    ("f4:f5:d8:01:00:0a", "Google", "always", (2,), -60, []),
    ("da:4e:91:01:00:0b", None, "visitor", (0,), -64, ["HomeNet", "iPhone van Sam"]),
    ("3e:12:aa:01:00:0c", None, "evening", (3,), -74, ["Vodafone-7F2A"]),
    ("8c:85:90:01:00:0d", "Apple", "neighbour", (3,), -76, ["Vodafone-7F2A"]),
    ("a0:a8:cd:01:00:0e", "Intel", "neighbour", (4,), -80, ["Ziggo5G-Neighbour"]),
    ("5c:0a:5b:01:00:0f", "Samsung", "visitor", (5,), -79, ["Linksys", "Starbucks"]),
]

BLE = [
    ("4c:11:aa:02:00:01", "AirPods Pro", 0x004C, "resident", -60, "random-static", "audio sink"),
    ("c9:22:bb:02:00:02", "Galaxy Watch5", 0x0075, "evening", -66, "random-static", "watch"),
    ("e1:33:cc:02:00:03", "Mi Smart Band 7", 0x038F, "worker", -71, "random-static", "watch"),
    ("a4:c1:38:02:00:04", "GVH5075_8A1C", 0x04F7, "always", -68, "public", "thermometer"),
    ("d4:44:dd:02:00:05", "Tile", 0x00ED, "always", -82, "random-static", "tag"),
    ("f0:55:ee:02:00:06", "MX Keys", 0x01DA, "worker", -57, "random-static", "HID"),
    ("4a:66:ff:02:00:07", None, 0x004C, "passer", -85, "random-resolvable", None),
    ("5b:77:00:02:00:08", None, 0x0006, "passer", -88, "random-resolvable", None),
    ("6c:88:11:02:00:09", None, 0x004C, "visitor", -73, "random-resolvable", "phone"),
    ("cb:99:22:02:00:0a", "Ruuvi 3F2C", 0x0499, "always", -75, "random-static", "sensor"),
]

CLASSIC = [
    ("00:1b:66:03:00:01", "Sennheiser MOMENTUM 4", "evening", -59, "audio/video", True),
    ("88:c6:26:03:00:02", "Car Multimedia", "worker", -80, "audio/video", False),
    ("ac:bc:32:03:00:03", "Sjaak's MacBook", "worker", -54, "computer", False),
]


def _h(*parts):
    return int(hashlib.md5("|".join(map(str, parts)).encode()).hexdigest()[:8], 16)


def present(sched, mac, t):
    """Deterministic presence model for a schedule at epoch time t (local ~= UTC+1)."""
    lt = t + 3600
    day, hour = int(lt // 86400), (lt % 86400) / 3600
    weekday = (day + 3) % 7
    r = _h(mac, day) % 1000 / 1000.0
    if sched == "always":
        return _h(mac, int(t // 1800)) % 50 != 0  # occasional short drop-out
    if sched == "resident":
        return not (8.5 + r < hour < 17.5 + r) or weekday >= 5
    if sched == "worker":
        return weekday < 5 and 8.0 + r < hour < 17.0 + r * 2
    if sched == "evening":
        return 17.5 + r < hour or hour < 0.5 + r
    if sched == "neighbour":
        return 7 + r * 3 < hour < 23
    if sched == "visitor":
        return r < 0.4 and 13 + r * 10 < hour < 17 + r * 10
    if sched == "passer":
        return _h(mac, int(t // 600)) % 9 == 0
    return False


class DemoGenerator:
    def __init__(self, cfg, store):
        self.cfg, self.store = cfg, store
        self.rng = random.Random(42)
        self.passers = [f"{0x02 | (i * 4 & 0xfc):02x}:{self.rng.randrange(256):02x}:{self.rng.randrange(256):02x}:"
                        f"9{i % 10}:{self.rng.randrange(256):02x}:{self.rng.randrange(256):02x}" for i in range(40)]

    def _rssi(self, base):
        return int(base + self.rng.gauss(0, 3))

    def observations(self, t):
        rng = self.rng
        out = []
        for mac, ssid, ch, enc, base, vendor in APS:
            out.append({"t": "wifi_ap", "ts": t + rng.random() * 50, "mac": mac, "ssid": ssid or None,
                        **_radio(ch), "enc": enc, "rssi": self._rssi(base), "vendor": vendor,
                        "extra": {"hidden": True} if not ssid else None})
        for mac, vendor, sched, aps, base, probes in CLIENTS:
            if not present(sched, mac, t):
                continue
            ap_i = aps[(_h(mac, int(t // 5400)) % len(aps))] if len(aps) > 1 else aps[0]
            bssid = APS[ap_i][0]
            for _ in range(rng.randint(2, 6)):
                out.append({"t": "wifi_client", "ts": t + rng.random() * 55, "mac": mac, "bssid": bssid,
                            "frame": "data", "rssi": self._rssi(base), **_radio(APS[ap_i][2]), "vendor": vendor})
            if probes and rng.random() < 0.05:
                out.append({"t": "wifi_client", "ts": t + rng.random() * 55, "mac": mac, "frame": "probe",
                            "probe": rng.choice(probes), "rssi": self._rssi(base), "vendor": vendor})
        for i, mac in enumerate(self.passers):
            if _h(mac, int(t // 900)) % 25 == 0:
                out.append({"t": "wifi_client", "ts": t + rng.random() * 55, "mac": mac, "frame": "probe",
                            "probe": rng.choice([None, None, "Starbucks", "KPN", "eduroam", "NS WiFi", "HomeNet"]),
                            "rssi": self._rssi(-82)})
        for mac, name, cid, sched, base, atype, app in BLE:
            if not present(sched, mac, t):
                continue
            for _ in range(rng.randint(3, 10)):
                out.append({"t": "bt", "kind": "ble", "ts": t + rng.random() * 55, "mac": mac, "name": name,
                            "rssi": self._rssi(base), "randomized": atype.startswith("random-") and
                            atype != "random-static", "addr_random": atype != "public",
                            "vendor": bt_company(cid) if atype != "public" else "Govee",
                            "extra": {"addr_type": atype, "company": bt_company(cid), "appearance": app,
                                      "connectable": True}})
        minute = int(t // 60)
        for mac, name, sched, base, cls, connects in CLASSIC:
            if not present(sched, mac, t):
                continue
            out.append({"t": "bt", "kind": "bt_classic", "ts": t + 1, "mac": mac, "name": name,
                        "rssi": self._rssi(base), "randomized": False, "extra": {"class": cls}})
        if _h("deauth", int(t // 3600)) % 11 == 0 and minute % 60 < 3:
            out.append({"t": "event", "ts": t + 5, "mac": APS[5][0], "type": "deauth_broadcast",
                        "detail": "deauth to ff:ff:ff:ff:ff:ff reason 7"})
        out.sort(key=lambda o: o["ts"])
        return out

    def _bt_connections(self, t, prev):
        """Simulate the headphones connecting to the sensor's own adapter in the evening."""
        out = []
        for mac, name, sched, base, cls, connects in CLASSIC:
            if not connects:
                continue
            now = present(sched, mac, t) and (_h(mac, int(t // 2700)) % 3 != 0)
            if now != prev.get(mac, False):
                out.append({"t": "bt_conn", "kind": "bt_classic", "ts": t, "mac": mac, "connected": now,
                            "peer": "hci0", "detail": "ACL link" if now else "reason 0x13"})
                prev[mac] = now
        return out

    def backfill(self, hours):
        if not hours:
            return
        if self.store.conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]:
            log.info("Demo database already populated; skipping backfill")
            return
        log.info("Generating %d hours of demo history...", hours)
        now = time.time()
        t = int((now - hours * 3600) // 60) * 60
        self._conn_state = {}
        n = 0
        while t < now - 60:
            for o in self.observations(t) + self._bt_connections(t, self._conn_state):
                self.store.process(o)
                n += 1
            self.store.sweep(t + 60)
            if (t // 60) % 30 == 0:
                self.store.flush()
            t += 60
        self.store.flush()
        log.info("Demo backfill done (%d observations)", n)

    def run(self, stop):
        state = getattr(self, "_conn_state", {})
        while not stop.wait(30):
            t = time.time()
            for o in self.observations(t - 55):
                o["ts"] = t
                self.store.put(o)
            for o in self._bt_connections(t, state):
                self.store.put(o)
