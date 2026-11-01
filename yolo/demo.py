"""Synthetic data generator so the UI can be explored without radio hardware (DEMO_MODE=1)."""
import hashlib
import logging
import random
import time

from .config import band_of, ch_to_freq, freq_to_channel
from .identify import wifi_fingerprint
from .oui import bt_company

log = logging.getLogger("yolo.demo")

def _wps(**attrs):
    ids = {"manufacturer": 0x1021, "model": 0x1023, "model_number": 0x1024, "device_name": 0x1011}
    out = b""
    for k, v in attrs.items():
        if k == "category":
            val = v[0].to_bytes(2, "big") + bytes.fromhex("0050f204") + v[1].to_bytes(2, "big")
            out += (0x1054).to_bytes(2, "big") + len(val).to_bytes(2, "big") + val
        else:
            out += ids[k].to_bytes(2, "big") + len(v).to_bytes(2, "big") + v.encode()
    return out


def wifi_fp(gen, ss=1, width=20, vendors=(), wfa=(), wps=None, base=(1, 50, 127)):
    """Build raw 802.11 capability elements like a real device sends and run the real parser on them."""
    elts = [(eid, b"\x00" * 8) for eid in base]
    if gen and gen >= 4:
        mcs = bytes([0xFF] * ss + [0] * (16 - ss))
        elts.append((45, (0x0002 if width >= 40 else 0).to_bytes(2, "little") + b"\x17" + mcs + b"\x00" * 7))
    if gen and gen >= 5:
        mcs_map = sum((2 if i < ss else 3) << (2 * i) for i in range(8))
        elts.append((191, ((1 if width >= 160 else 0) << 2).to_bytes(4, "little") + mcs_map.to_bytes(2, "little")
                     + b"\x00" * 6))
    if gen and gen >= 6:
        phy0 = 0x06 | (0x08 if width >= 160 else 0)
        mcs_map = sum((2 if i < ss else 3) << (2 * i) for i in range(8))
        elts.append((255, bytes([35]) + b"\x00" * 6 + bytes([phy0]) + b"\x00" * 10 + mcs_map.to_bytes(2, "little")))
    if gen and gen >= 7:
        elts.append((255, bytes([108]) + b"\x00\x00" + bytes([0x02 if width >= 320 else 0]) + b"\x00" * 8))
    for v in vendors:
        oui, vtype = v.split("/") if "/" in v else (v, "1")
        elts.append((221, bytes.fromhex(oui.replace(":", "")) + bytes([int(vtype)]) + b"\x00\x01"))
    for t in wfa:
        elts.append((221, bytes.fromhex("506f9a") + bytes([t]) + b"\x00"))
    if wps:
        elts.append((221, bytes.fromhex("0050f204") + _wps(**wps)))
    return wifi_fingerprint(elts)


APPLE_PHONE = dict(gen=6, ss=2, width=80, vendors=("00:17:f2/10", "00:10:18/2", "00:50:f2/2"))
ANDROID_PHONE = dict(gen=6, ss=2, width=80, vendors=("8c:fd:f0/1", "00:50:f2/2"), wfa=(0x09, 0x16))
WINDOWS_PC = dict(gen=6, ss=2, width=160, vendors=("00:50:f2/2",), wfa=(0x09,), base=(1, 50, 59, 127))
# per-MAC Wi-Fi fingerprints (clients: probe/assoc capabilities, APs: beacon capabilities)
WIFI_FPS = {
    "a4:83:e7:01:00:01": APPLE_PHONE,
    "a4:83:e7:01:00:02": dict(gen=6, ss=2, width=80, vendors=("00:17:f2/10", "00:10:18/2"), base=(1, 50, 59, 127)),
    "5c:0a:5b:01:00:03": dict(ANDROID_PHONE, vendors=("00:00:f0/1", "8c:fd:f0/1")),
    "a0:a8:cd:01:00:04": dict(WINDOWS_PC, wps=dict(device_name="LAPTOP-8K3J2QH9", category=(1, 5))),
    "b8:27:eb:01:00:05": dict(gen=5, ss=1, width=80, vendors=("00:10:18/2",)),
    "24:0a:c4:01:00:06": dict(gen=4, ss=1, width=20),
    "24:0a:c4:01:00:07": dict(gen=4, ss=1, width=20),
    "fc:65:de:01:00:08": dict(gen=5, ss=2, width=80, vendors=("00:0c:e7/4",)),
    "5c:aa:fd:01:00:09": dict(gen=5, ss=2, width=80, vendors=("00:03:7f/1",)),
    "f4:f5:d8:01:00:0a": dict(gen=5, ss=1, width=80, vendors=("00:10:18/2",)),
    "da:4e:91:01:00:0b": APPLE_PHONE,
    "3e:12:aa:01:00:0c": ANDROID_PHONE,
    "8c:85:90:01:00:0d": dict(gen=5, ss=2, width=80, vendors=("00:17:f2/10", "00:10:18/2")),
    "a0:a8:cd:01:00:0e": dict(gen=5, ss=2, width=80, wfa=(0x09,), wps=dict(device_name="DESKTOP-4MJ8T2Q",
                                                                          category=(1, 6))),
    "5c:0a:5b:01:00:0f": dict(gen=6, ss=2, width=80, vendors=("00:00:f0/1",), wfa=(0x09,),
                              wps=dict(manufacturer="Samsung Electronics", model="QE55Q80T",
                                       device_name="[TV] Samsung Q80 Series (55)", category=(7, 1))),
    # access points
    "24:a4:3c:10:00:01": dict(gen=6, ss=2, width=40),
    "24:a4:3c:10:00:02": dict(gen=6, ss=4, width=160),
    "24:a4:3c:10:00:09": dict(gen=7, ss=2, width=320),
    "50:c7:bf:20:00:03": dict(gen=4, ss=2, width=40, vendors=("00:e0:4c/2",)),
    "a0:40:a0:30:00:04": dict(gen=5, ss=4, width=80, wps=dict(manufacturer="Arcadyan Technology Corporation",
                                                              model="VRV9517", category=(6, 1))),
    "a0:40:a0:30:00:05": dict(gen=6, ss=4, width=160),
    "00:1d:7e:40:00:06": dict(gen=None, wps=dict(manufacturer="Linksys", model="WRT54GL", category=(6, 1))),
    "50:c7:bf:20:00:07": dict(gen=4, ss=1, width=20),
    "f4:f5:d8:50:00:08": dict(gen=5, ss=2, width=80),
    "9c:7b:ef:60:00:0a": dict(gen=4, ss=1, width=20, wfa=(0x09,),
                              wps=dict(manufacturer="HP", model="OfficeJet Pro 9010 series", category=(3, 1))),
}
WIFI_FPS = {k: wifi_fp(**v) for k, v in WIFI_FPS.items()}
# random-MAC passers-by fall into three device families, showing probe-fingerprint grouping
PASSER_FPS = [WIFI_FPS["a4:83:e7:01:00:01"], WIFI_FPS["3e:12:aa:01:00:0c"], wifi_fp(**WINDOWS_PC)]

BLE_FPS = {
    "4c:11:aa:02:00:01": {"company": 0x004C, "apple": [0x07], "apple_model": 0x2014},
    "c9:22:bb:02:00:02": {"company": 0x0075, "ext_adv": True},
    "e1:33:cc:02:00:03": {"company": 0x038F, "uuids": ["fe95"]},
    "d4:44:dd:02:00:05": {"uuids": ["feed"]},
    "f0:55:ee:02:00:06": {"company": 0x01DA, "uuids": ["1812"]},
    "4a:66:ff:02:00:07": {"company": 0x004C, "apple": [0x0C, 0x10]},
    "5b:77:00:02:00:08": {"company": 0x0006, "ms_type": 15},
    "6c:88:11:02:00:09": {"company": 0x004C, "apple": [0x12]},
    "cb:99:22:02:00:0a": {"company": 0x0499, "ext_adv": True},
}

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
    ("9c:7b:ef:60:00:0a", "DIRECT-4F-HP OfficeJet Pro 9010", 6, "WPA2/PSK", -69, "Hewlett Packard"),
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
    ("5c:0a:5b:01:00:0f", "Samsung", "evening", (2,), -62, []),
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
    ("00:1b:66:03:00:01", "Sennheiser MOMENTUM 4", "evening", -59, "audio/video", True, "0x240418"),
    ("00:1c:d7:03:00:02", "Car Multimedia", "worker", -80, "audio/video", False, "0x200420"),
    ("ac:bc:32:03:00:03", "MacBook Pro", "worker", -54, "computer", False, "0x5a010c"),
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
                        "extra": {"hidden": True} if not ssid else None,
                        "fp": {"wifi": WIFI_FPS[mac], "src": "beacon"} if mac in WIFI_FPS else None})
        for mac, vendor, sched, aps, base, probes in CLIENTS:
            if not present(sched, mac, t):
                continue
            ap_i = aps[(_h(mac, int(t // 5400)) % len(aps))] if len(aps) > 1 else aps[0]
            bssid = APS[ap_i][0]
            fp = WIFI_FPS.get(mac)
            for n in range(rng.randint(2, 6)):
                out.append({"t": "wifi_client", "ts": t + rng.random() * 55, "mac": mac, "bssid": bssid,
                            "frame": "data", "rssi": self._rssi(base), **_radio(APS[ap_i][2]), "vendor": vendor,
                            "fp": {"wifi": fp, "src": "assoc"} if fp and n == 0 else None})
            if probes and rng.random() < 0.05:
                out.append({"t": "wifi_client", "ts": t + rng.random() * 55, "mac": mac, "frame": "probe",
                            "probe": rng.choice(probes), "rssi": self._rssi(base), "vendor": vendor,
                            "fp": {"wifi": fp, "src": "probe"} if fp else None})
        for i, mac in enumerate(self.passers):
            if _h(mac, int(t // 900)) % 25 == 0:
                out.append({"t": "wifi_client", "ts": t + rng.random() * 55, "mac": mac, "frame": "probe",
                            "probe": rng.choice([None, None, "Starbucks", "KPN", "eduroam", "NS WiFi", "HomeNet"]),
                            "rssi": self._rssi(-82), "fp": {"wifi": PASSER_FPS[i % 3], "src": "probe"}})
        for mac, name, cid, sched, base, atype, app in BLE:
            if not present(sched, mac, t):
                continue
            for n in range(rng.randint(3, 10)):
                out.append({"t": "bt", "kind": "ble", "fp": {"ble": BLE_FPS[mac]} if mac in BLE_FPS and n == 0 else None, "ts": t + rng.random() * 55, "mac": mac, "name": name,
                            "rssi": self._rssi(base), "randomized": atype.startswith("random-") and
                            atype != "random-static", "addr_random": atype != "public",
                            "vendor": bt_company(cid) if atype != "public" else "Govee",
                            "extra": {"addr_type": atype, "company": bt_company(cid), "appearance": app,
                                      "connectable": True}})
        minute = int(t // 60)
        for mac, name, sched, base, cls, connects, cod in CLASSIC:
            if not present(sched, mac, t):
                continue
            out.append({"t": "bt", "kind": "bt_classic", "ts": t + 1, "mac": mac, "name": name,
                        "rssi": self._rssi(base), "randomized": False, "extra": {"class": cls, "cod": cod}})
        if _h("deauth", int(t // 3600)) % 11 == 0 and minute % 60 < 3:
            out.append({"t": "event", "ts": t + 5, "mac": APS[5][0], "type": "deauth_broadcast",
                        "detail": "deauth to ff:ff:ff:ff:ff:ff reason 7"})
        out.sort(key=lambda o: o["ts"])
        return out

    def _bt_connections(self, t, prev):
        """Simulate the headphones connecting to the sensor's own adapter in the evening."""
        out = []
        for mac, name, sched, base, cls, connects, cod in CLASSIC:
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
