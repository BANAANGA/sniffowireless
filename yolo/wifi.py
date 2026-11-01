"""802.11 monitor-mode capture: monitor setup, channel hopping and frame parsing."""
import logging
import os
import re
import subprocess
import threading
import time

from scapy.all import conf, sniff
from scapy.layers.dot11 import (Dot11, Dot11AssoResp, Dot11Beacon, Dot11Deauth, Dot11Disas,
                                Dot11Elt, Dot11ProbeResp, Dot11ReassoResp, RadioTap)

from . import status
from .config import band_of, chan_label, freq_to_channel
from .identify import wifi_fingerprint

conf.verb = 0
log = logging.getLogger("yolo.wifi")

BROADCAST = "ff:ff:ff:ff:ff:ff"


def is_unicast(mac):
    if not mac or mac == BROADCAST or mac == "00:00:00:00:00:00":
        return False
    try:
        return not (int(mac[0:2], 16) & 0x01)
    except ValueError:
        return False


def decode_ssid(raw):
    if raw is None:
        return None
    if not raw or all(b == 0 for b in raw):
        return ""
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        s = raw.decode("latin-1")
    return "".join(ch for ch in s if ch.isprintable())


def _elt_ssid(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 0:
            return decode_ssid(bytes(elt.info))
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return None


def _elts(pkt):
    out = []
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        out.append((elt.ID, bytes(elt.info or b"")))
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return out


class FingerprintGate:
    """Only fingerprint a given (device, frame source) every `interval` seconds: beacons arrive ~10/s."""

    def __init__(self, interval=600):
        self.interval, self.seen = interval, {}

    def __call__(self, mac, src, ts):
        k = (mac, src)
        if ts - self.seen.get(k, 0) < self.interval:
            return False
        if len(self.seen) > 100_000:
            self.seen.clear()
        self.seen[k] = ts
        return True


def _radio(pkt):
    rssi = freq = None
    if pkt.haslayer(RadioTap):
        rt = pkt[RadioTap]
        try:
            rssi = rt.dBm_AntSignal
        except AttributeError:
            pass
        try:
            freq = rt.ChannelFrequency
        except AttributeError:
            pass
    if rssi is not None and not (-120 < rssi < 10):
        rssi = None
    return rssi, freq


def parse_frame(pkt, fp_gate=None):
    """Turn one captured 802.11 frame into zero or more store observations.

    Management frames carrying capability elements also get a device fingerprint ('fp'),
    subject to `fp_gate(mac, source, ts)` so busy devices aren't re-parsed on every frame.
    """
    if not pkt.haslayer(Dot11):
        return []
    d = pkt[Dot11]
    ts = float(pkt.time)
    rssi, freq = _radio(pkt)
    a1 = d.addr1.lower() if d.addr1 else None
    a2 = d.addr2.lower() if d.addr2 else None
    a3 = d.addr3.lower() if d.addr3 else None
    ch = freq_to_channel(freq)
    band = band_of(freq)
    out = []

    def fingerprint(mac, src):
        if not is_unicast(mac) or (fp_gate and not fp_gate(mac, src, ts)):
            return None
        fp = wifi_fingerprint(_elts(pkt))
        return {"wifi": fp, "src": src} if fp else None

    def client(mac, bssid=None, frame=None, r=None, **kw):
        if is_unicast(mac) and mac != bssid:
            out.append({"t": "wifi_client", "ts": ts, "mac": mac, "bssid": bssid, "frame": frame,
                        "rssi": r, "freq": freq, "band": band, **kw})

    def ap(mac, r=None, **kw):
        if is_unicast(mac):
            beacon_ch = kw.pop("channel", None)
            out.append({"t": "wifi_ap", "ts": ts, "mac": mac, "rssi": r, "freq": freq, "band": band,
                        # 6 GHz beacons carry no DS Parameter Set; the tuned frequency is authoritative there.
                        "channel": ch if band == "6" else (beacon_ch or ch), **kw})

    if d.type == 0:
        st = d.subtype
        if st in (8, 5):  # beacon / probe response
            layer = pkt.getlayer(Dot11Beacon) or pkt.getlayer(Dot11ProbeResp)
            if layer is None:
                return out
            try:
                stats = layer.network_stats()
            except Exception:
                stats = {}
            ssid = _elt_ssid(pkt)
            crypto = stats.get("crypto") or set()
            ap(a2 or a3, rssi, ssid=ssid or None, channel=stats.get("channel"),
               enc=",".join(sorted(crypto)) or None,
               extra={"hidden": True} if st == 8 and ssid == "" else None,
               fp=fingerprint(a2 or a3, "beacon"))
            if st == 5:
                client(a1, None, "probe_resp")
        elif st == 4:  # probe request
            ssid = _elt_ssid(pkt)
            client(a2, None, "probe", rssi, probe=ssid or None, fp=fingerprint(a2, "probe"))
        elif st in (0, 2):  # (re)association request: client -> AP
            client(a2, a1, "assoc", rssi, fp=fingerprint(a2, "assoc"))
            ap(a1)
        elif st in (1, 3):  # (re)association response: AP -> client
            layer = pkt.getlayer(Dot11AssoResp) or pkt.getlayer(Dot11ReassoResp)
            ok = layer is None or getattr(layer, "status", 0) == 0
            ap(a2, rssi)
            client(a1, a2 if ok else None, "assoc" if ok else "assoc_fail")
        elif st == 11:  # authentication
            if a2 == a3:
                ap(a2, rssi)
                client(a1, None, "auth")
            else:
                client(a2, None, "auth", rssi)
        elif st in (10, 12):  # disassociation / deauthentication
            layer = pkt.getlayer(Dot11Deauth) or pkt.getlayer(Dot11Disas)
            reason = getattr(layer, "reason", None)
            frame = "deauth" if st == 12 else "disassoc"
            bssid = a3
            if a2 == bssid:
                target = a1
                ap(a2, rssi)
                if not is_unicast(target):
                    out.append({"t": "event", "ts": ts, "mac": bssid, "type": "deauth_broadcast",
                                "detail": f"{frame} to {target} reason {reason}"})
                else:
                    client(target, bssid, frame, reason=reason)
            else:
                client(a2, bssid, frame, rssi, reason=reason)
    elif d.type == 2:
        fc = int(d.FCfield)
        to_ds, from_ds = bool(fc & 0x1), bool(fc & 0x2)
        if to_ds and not from_ds:      # client -> AP
            client(a2, a1, "data", rssi)
            ap(a1)
        elif from_ds and not to_ds:    # AP -> client
            ap(a2, rssi)
            client(a1, a2, "data")
    return out


# ------------------------------------------------------------------ interface
def run_cmd(*args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=10)
        return p.returncode, (p.stdout + p.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)


def iface_type(iface):
    rc, out = run_cmd("iw", "dev", iface, "info")
    if rc != 0:
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("type "):
            return line.split(None, 1)[1]
    return None


def ensure_monitor(iface, allow_change=True):
    """Return the name of a monitor-mode interface for `iface`."""
    if not os.path.exists(f"/sys/class/net/{iface}"):
        raise RuntimeError(f"interface {iface} not found (is the adapter plugged in and the "
                           f"container running with network_mode: host?)")
    if iface_type(iface) == "monitor":
        run_cmd("ip", "link", "set", iface, "up")
        return iface
    if not allow_change:
        raise RuntimeError(f"{iface} is not in monitor mode and WIFI_SET_MONITOR=0")
    log.info("Switching %s to monitor mode", iface)
    run_cmd("ip", "link", "set", iface, "down")
    rc, out = run_cmd("iw", "dev", iface, "set", "type", "monitor")
    run_cmd("ip", "link", "set", iface, "up")
    if rc == 0 and iface_type(iface) == "monitor":
        return iface
    log.warning("Could not set %s to monitor mode directly (%s); trying a virtual interface", iface, out)
    try:
        phy = os.path.basename(os.readlink(f"/sys/class/net/{iface}/phy80211"))
    except OSError:
        raise RuntimeError(f"{iface} is not a wireless (cfg80211) interface")
    mon = (iface + "mon")[:15]
    if iface_type(mon) != "monitor":
        rc, out = run_cmd("iw", "phy", phy, "interface", "add", mon, "type", "monitor")
        if rc != 0:
            raise RuntimeError(f"driver refused monitor mode on {iface}: {out}")
    run_cmd("ip", "link", "set", mon, "up")
    return mon


def supported_freqs(iface):
    """Frequencies (MHz) the adapter's phy can tune to, or None if it can't be determined."""
    try:
        phy = os.path.basename(os.readlink(f"/sys/class/net/{iface}/phy80211"))
    except OSError:
        return None
    rc, out = run_cmd("iw", "phy", phy, "info")
    if rc != 0:
        return None
    freqs = set()
    for line in out.splitlines():
        m = re.match(r"\s*\* (\d+)(?:\.\d+)? MHz \[\d+\](.*)", line)
        if m and "disabled" not in m.group(2):
            freqs.add(int(m.group(1)))
    return freqs or None


def assign_channels(freqs, ifaces, supported):
    """Spread frequencies over adapters, giving each one only to adapters that support it."""
    plan = {i: [] for i in ifaces}
    for f in freqs:
        able = [i for i in ifaces if supported.get(i) is None or f in supported[i]]
        if able:
            plan[min(able, key=lambda i: len(plan[i]))].append(f)
    return plan


def set_freq(iface, freq):
    # Tuning by frequency works for every band and avoids 2.4 / 6 GHz channel-number clashes.
    rc, out = run_cmd("iw", "dev", iface, "set", "freq", str(freq))
    return rc == 0, out


def set_regdomain(country):
    rc, out = run_cmd("iw", "reg", "set", country)
    if rc != 0:
        log.warning("Could not set regulatory domain %s: %s", country, out)
    else:
        log.info("Regulatory domain set to %s", country)


class WifiSensor:
    def __init__(self, iface, channels, cfg, store):
        self.iface, self.channels, self.cfg, self.store = iface, list(channels), cfg, store
        self.name = f"wifi:{iface}"
        self.mon = None
        self.packets = 0
        self.fp_gate = FingerprintGate()
        self.stop = None
        status.register(self.name, type="wifi", iface=iface, channel=None, band=None,
                        channels=[chan_label(f) for f in self.channels],
                        bands=sorted({band_of(f) for f in self.channels}))

    def start(self, stop):
        self.stop = stop
        for target, n in ((self._capture_loop, "cap"), (self._hop_loop, "hop"), (self._rate_loop, "rate")):
            threading.Thread(target=target, daemon=True, name=f"{self.name}:{n}").start()

    def _handle(self, pkt):
        self.packets += 1
        try:
            for o in parse_frame(pkt, self.fp_gate):
                self.store.put(o)
        except Exception:
            log.debug("Failed to parse frame", exc_info=True)

    def _capture_loop(self):
        while not self.stop.is_set():
            try:
                self.mon = ensure_monitor(self.iface, self.cfg.wifi_set_monitor)
                status.update(self.name, state="capturing", mon=self.mon, error=None)
                sniff(iface=self.mon, prn=self._handle, store=False, timeout=30,
                      stop_filter=lambda _p: self.stop.is_set())
            except Exception as e:
                self.mon = None
                log.error("%s: %s", self.name, e)
                status.update(self.name, state="error", error=str(e))
                self.stop.wait(10)

    def _hop_loop(self):
        bad = {}
        while not self.stop.is_set():
            if not self.mon:
                self.stop.wait(1)
                continue
            freqs = [f for f in self.channels if bad.get(f, 0) < 3]
            if not freqs:
                status.update(self.name, error="no usable channels for this adapter")
                self.stop.wait(10)
                bad.clear()
                continue
            if len(freqs) == 1:
                ok, _ = set_freq(self.mon, freqs[0])
                status.update(self.name, channel=chan_label(freqs[0]) if ok else None,
                              band=band_of(freqs[0]) if ok else None)
                self.stop.wait(30)
                continue
            for f in freqs:
                if self.stop.is_set() or not self.mon:
                    break
                ok, out = set_freq(self.mon, f)
                if ok:
                    bad.pop(f, None)
                    status.update(self.name, channel=chan_label(f), band=band_of(f))
                    self.stop.wait(self.cfg.wifi_hop_interval)
                else:
                    bad[f] = bad.get(f, 0) + 1
                    if bad[f] == 3:
                        log.info("%s: channel %s (%d MHz) unsupported, skipping (%s)",
                                 self.name, chan_label(f), f, out)
                    status.update(self.name, skipped=[chan_label(x) for x in sorted(bad) if bad[x] >= 3])

    def _rate_loop(self):
        last, last_t = 0, time.time()
        while not self.stop.wait(5):
            now = time.time()
            status.update(self.name, packets=self.packets, pps=round((self.packets - last) / (now - last_t), 1))
            last, last_t = self.packets, now
