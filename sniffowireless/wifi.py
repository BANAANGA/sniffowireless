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
from scapy.layers.eap import EAPOL

from . import status
from .config import band_of, chan_label, freq_to_channel
from .handshake import eapol_message
from .identify import wifi_fingerprint
from .wifiattrs import ap_attributes, radio_quality, seq_number
from .survey import frame_airtime_us, rate_from_radiotap

conf.verb = 0
log = logging.getLogger("sniffowireless.wifi")

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


def _chan_elts(pkt):
    """(csa, ht_primary) from one walk over a beacon / probe response's elements.

    csa: Channel Switch Announcement (IE 37) or Extended CSA (IE 60), which APs on DFS channels send when radar
    forces them off the channel; ht_primary: the primary channel from HT Operation (IE 61), which 5 GHz beacons
    carry even when they have no DS Parameter Set."""
    csa = primary = None
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        info = bytes(elt.info or b"")
        if csa is None and elt.ID == 37 and len(info) >= 3:
            csa = {"mode": info[0], "new_channel": info[1], "count": info[2]}
        elif csa is None and elt.ID == 60 and len(info) >= 4:
            csa = {"mode": info[0], "op_class": info[1], "new_channel": info[2], "count": info[3]}
        elif elt.ID == 61 and info:
            primary = info[0]
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return csa, primary


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


def radio_freq(rt_freq, tuned):
    """The frequency a frame was received on. Normally the radiotap value, but some drivers (seen with mt76 on
    6 GHz) report the right channel number in the wrong band (6 GHz ch 37 as 5185 MHz) or no frequency at all;
    then the frequency the radio is tuned to is used."""
    if not tuned:
        return rt_freq
    if not rt_freq:
        return tuned
    if band_of(rt_freq) != band_of(tuned) and freq_to_channel(rt_freq) == freq_to_channel(tuned):
        return tuned
    return rt_freq


def is_local(mac):
    """Locally administered (randomised) address."""
    try:
        return bool(int(mac[0:2], 16) & 0x02)
    except (TypeError, ValueError):
        return False


class AttrGates:
    """Rate limits for the extra attributes: AP details (load, uptime...) and link quality are refreshed every so often."""

    def __init__(self, ap_interval=60, link_interval=30):
        self.ap, self.link = FingerprintGate(ap_interval), FingerprintGate(link_interval)


def parse_frame(pkt, fp_gate=None, tuned=None, gates=None, seq_on=False):
    """Turn one captured 802.11 frame into zero or more store observations.

    Management frames carrying capability elements also get a device fingerprint ('fp'),
    subject to `fp_gate(mac, source, ts)` so busy devices aren't re-parsed on every frame.
    `tuned` is the frequency the radio is tuned to (used when the driver mislabels the frame's frequency).
    `gates` (AttrGates) switches on the extra AP details and link quality; `seq_on` adds the frame sequence number of
    randomised transmitters (only used by the opt-in address linking).
    """
    if not pkt.haslayer(Dot11):
        return []
    d = pkt[Dot11]
    ts = float(pkt.time)
    rssi, freq = _radio(pkt)
    freq = radio_freq(freq, tuned)
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

    seqn = seq_number(pkt) if seq_on else None

    def client(mac, bssid=None, frame=None, r=None, tx=False, link=None, **kw):
        """tx: this client sent the frame (so the sequence number is its own); link: "up"/"down" rate direction."""
        if is_unicast(mac) and mac != bssid:
            if tx and seqn is not None and is_local(mac):
                kw["seq"] = seqn
            if link and gates and gates.link(mac, link, ts):
                q = radio_quality(pkt)
                ex = {k: v for k, v in (("rate_" + link, q.get("phy_rate")), ("noise", q.get("noise"))) if v is not None}
                if ex:
                    kw["extra"] = ex
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
            csa, primary = _chan_elts(pkt)
            extra = {"hidden": True} if st == 8 and ssid == "" else {}
            if gates and gates.ap(a2 or a3, "ap", ts):
                info = ap_attributes(_elts(pkt), getattr(layer, "beacon_interval", None))
                tsf = getattr(layer, "timestamp", None)
                if isinstance(tsf, int) and 0 < tsf < 5 * 365 * 86400 * 1_000_000:  # AP timer in µs: roughly its uptime
                    info["boot"] = int(ts - tsf / 1e6)
                if info:
                    extra["ap"] = info
            ap(a2 or a3, rssi, ssid=ssid or None, channel=stats.get("channel") or primary,
               enc=",".join(sorted(crypto)) or None, extra=extra or None,
               fp=fingerprint(a2 or a3, "beacon"), csa=csa)
            if st == 5:
                client(a1, None, "probe_resp")
        elif st == 4:  # probe request
            ssid = _elt_ssid(pkt)
            client(a2, None, "probe", rssi, tx=True, probe=ssid or None, fp=fingerprint(a2, "probe"))
        elif st in (0, 2):  # (re)association request: client -> AP
            client(a2, a1, "assoc", rssi, tx=True, fp=fingerprint(a2, "assoc"))
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
                client(a2, None, "auth", rssi, tx=True)
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
                    client(target, bssid, frame, reason=reason, from_ap=True)
            else:
                client(a2, bssid, frame, rssi, reason=reason)
    elif d.type == 2:
        fc = int(d.FCfield)
        to_ds, from_ds = bool(fc & 0x1), bool(fc & 0x2)
        if to_ds and not from_ds:      # client -> AP
            client(a2, a1, "data", rssi, tx=True, link="up")
            ap(a1)
        elif from_ds and not to_ds:    # AP -> client
            ap(a2, rssi)
            client(a1, a2, "data", link="down")
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


def bring_up(iface):
    """Set the link up, and say why when it can't be (rfkill-blocked, adapter gone) instead of capturing nothing."""
    rc, out = run_cmd("ip", "link", "set", iface, "up")
    if rc != 0:
        raise RuntimeError(f"could not bring {iface} up: {out or 'ip link failed'}")


def ensure_monitor(iface, allow_change=True):
    """Return the name of a monitor-mode interface for `iface`."""
    if not os.path.exists(f"/sys/class/net/{iface}"):
        raise RuntimeError(f"interface {iface} not found (is the adapter plugged in and the "
                           f"container running with network_mode: host?)")
    if iface_type(iface) == "monitor":
        bring_up(iface)
        return iface
    if not allow_change:
        raise RuntimeError(f"{iface} is not in monitor mode and WIFI_SET_MONITOR=0")
    log.info("Switching %s to monitor mode", iface)
    run_cmd("ip", "link", "set", iface, "down")
    rc, out = run_cmd("iw", "dev", iface, "set", "type", "monitor")
    run_cmd("ip", "link", "set", iface, "up")  # a failure here shows up below as "could not set monitor mode"
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
    bring_up(mon)
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


def global_regdomain():
    """The kernel's global regulatory country ('00' = world rules), or None if `iw reg get` fails."""
    rc, out = run_cmd("iw", "reg", "get")
    if rc != 0:
        return None
    m = re.search(r"global\s*\n\s*country (\w\w):", out)
    return m.group(1) if m else None


def regulatory_warning(country, wanted, want_6ghz):
    """Explain a regulatory domain that blocks 6 GHz; None when it is fine."""
    if country is None or not want_6ghz:
        return None
    if country == "00":
        if wanted:
            return (f"Regulatory domain is still 00 (world rules) although WIFI_REGDOMAIN={wanted}, so 6 GHz is "
                    "disabled. The host is most likely missing the wireless-regdb package (regulatory.db); install "
                    "it and reboot, or run ./scripts/configure.sh on the host.")
        return ("Regulatory domain is 00 (world rules), so 6 GHz is disabled. Set WIFI_REGDOMAIN to your country "
                "code (e.g. NL) in .env, or run ./scripts/configure.sh on the host.")
    if wanted and country != wanted:
        return (f"WIFI_REGDOMAIN={wanted} was not applied: the kernel reports country {country}. Check "
                "'iw reg get' on the host (another tool may be setting the country).")
    return None


CAPTURE_WINDOW = 30  # seconds one sniff() call listens before the loop re-checks the interface


class WifiSensor:
    def __init__(self, iface, channels, cfg, store, handshake=None):
        self.iface, self.channels, self.cfg, self.store = iface, list(channels), cfg, store
        self.handshake = handshake  # HandshakeCapture, only passed where capture settings are reachable (server mode)
        self.name = f"wifi:{iface}"
        self.mon = None
        self.packets = 0
        self.fp_gate = FingerprintGate()
        self.gates = AttrGates()
        self.cur_freq = None
        self.band_frames = {}  # band -> frames received (after any frequency correction)
        self.relabelled = 0    # frames whose radiotap frequency was corrected to the tuned one
        self.eapol_errors = 0  # frames that raised while checking for a handshake (see _handle)
        self.acc = {}  # freq -> [frames, bytes, airtime_us, retries, noise_sum, noise_cnt] for the channel survey
        self.stop = None
        self.hop_interval = cfg.wifi_hop_interval
        self._changed = threading.Event()  # set when the channel list / hop interval changes, to wake the hopper
        status.register(self.name, type="wifi", iface=iface, channel=None, band=None,
                        channels=[chan_label(f) for f in self.channels],
                        bands=sorted({band_of(f) for f in self.channels}))

    def set_channels(self, channels, hop_interval=None):
        """Change what this adapter listens on, while it runs: the hopper picks it up at once."""
        self.channels = list(channels)
        if hop_interval:
            self.hop_interval = hop_interval
        status.update(self.name, channels=[chan_label(f) for f in self.channels],
                      bands=sorted({band_of(f) for f in self.channels}), skipped=[])
        self._changed.set()

    def _pause(self, seconds):
        """Wait, but wake early on shutdown or when the channel settings change."""
        end = time.monotonic() + seconds
        while not self.stop.is_set() and not self._changed.is_set():
            left = end - time.monotonic()
            if left <= 0:
                return
            self._changed.wait(min(left, 1.0))

    def start(self, stop):
        self.stop = stop
        for target, n in ((self._capture_loop, "cap"), (self._hop_loop, "hop"), (self._rate_loop, "rate")):
            threading.Thread(target=target, daemon=True, name=f"{self.name}:{n}").start()

    def _measure(self, pkt):
        f = self.cur_freq
        if f is None:
            return
        a = self.acc.get(f)
        if a is None:
            a = self.acc[f] = [0, 0, 0.0, 0, 0, 0]
        n = len(pkt)
        rate = noise = None
        if pkt.haslayer(RadioTap):
            rt = pkt[RadioTap]
            rate = rate_from_radiotap(rt)
            noise = getattr(rt, "dBm_AntNoise", None)
        a[0] += 1
        a[1] += n
        a[2] += frame_airtime_us(n, rate)
        if pkt.haslayer(Dot11) and int(pkt[Dot11].FCfield) & 0x08:
            a[3] += 1
        if noise is not None and -120 < noise < 0:
            a[4] += noise
            a[5] += 1

    def _emit_survey(self, freq, dwell_s):
        a = self.acc.pop(freq, None) or [0, 0, 0.0, 0, 0, 0]
        self.store.put({"t": "chan", "ts": time.time(), "mac": "-", "freq": freq, "dwell_ms": int(dwell_s * 1000),
                        "frames": a[0], "bytes": a[1], "airtime_us": int(a[2]), "retries": a[3],
                        "noise_sum": a[4], "noise_cnt": a[5]})

    def _handle(self, pkt):
        self.packets += 1
        try:
            self._measure(pkt)
        except Exception:
            pass
        tuned = self.cur_freq
        try:
            rt = _radio(pkt)[1]
            f = radio_freq(rt, tuned)
            if f != rt and rt:
                self.relabelled += 1
                if self.relabelled == 1:
                    log.warning("%s: driver reports %s MHz while tuned to %s MHz; using the tuned frequency "
                                "(known with some mt76 drivers on 6 GHz)", self.name, rt, tuned)
            b = band_of(f) or "?"
            self.band_frames[b] = self.band_frames.get(b, 0) + 1
        except Exception:
            pass
        try:
            for o in parse_frame(pkt, self.fp_gate, tuned, self.gates, True):
                self.store.put(o)
                if self.handshake and o["t"] == "wifi_ap" and o.get("ssid"):
                    self.handshake.note_ap(o["mac"], o["ssid"])
        except Exception:
            log.debug("Failed to parse frame", exc_info=True)
        if self.handshake and self.handshake.wanted:  # skip the EAPOL check entirely when nothing is enabled
            try:
                self._capture_handshake(pkt)
            except Exception:
                self.eapol_errors += 1
                if self.eapol_errors == 1:  # a bug here would otherwise look exactly like "no handshake yet"
                    log.warning("%s: failed to inspect a frame for a handshake (will keep trying; only "
                               "logging this once)", self.name, exc_info=True)

    def _capture_handshake(self, pkt):
        """Hand a 4-way-handshake frame to self.handshake, if this one is part of one. Passive only: this
        never transmits anything (no deauth), so a handshake is only captured if a client naturally
        (re)associates while capture is enabled for its SSID."""
        if not pkt.haslayer(Dot11):
            return
        d = pkt[Dot11]
        if d.type != 2 or not pkt.haslayer(EAPOL):  # EAPOL rides on a Data frame
            return
        msg = eapol_message(pkt)
        if not msg:
            return
        fc = int(d.FCfield)
        to_ds, from_ds = bool(fc & 0x1), bool(fc & 0x2)
        if to_ds and not from_ds:      # client -> AP (message 2 or 4)
            sta, bssid = d.addr2, d.addr1
        elif from_ds and not to_ds:    # AP -> client (message 1 or 3)
            bssid, sta = d.addr2, d.addr1
        else:
            return
        if bssid and sta:
            self.handshake.feed(pkt, bssid.lower(), sta.lower(), msg)

    def _capture_loop(self):
        while not self.stop.is_set():
            try:
                self.mon = ensure_monitor(self.iface, self.cfg.wifi_set_monitor)
                status.update(self.name, state="capturing", mon=self.mon, error=None)
                t0 = time.monotonic()
                sniff(iface=self.mon, prn=self._handle, store=False, timeout=CAPTURE_WINDOW,
                      stop_filter=lambda _p: self.stop.is_set())
                # When the interface goes down (adapter reset, USB hiccup, NetworkManager) scapy only logs
                # "Socket ... failed with 'Network is down'" and sniff() returns early. That isn't a normal end of the
                # window: report it and wait, instead of looping at full speed while showing "capturing".
                took = time.monotonic() - t0
                if not self.stop.is_set() and took < CAPTURE_WINDOW - 3:
                    raise RuntimeError(f"capture on {self.mon} stopped after {took:.0f}s: the interface went down or "
                                       f"the adapter was reset. Retrying")
            except Exception as e:
                self.mon = None
                log.error("%s: %s", self.name, e)
                status.update(self.name, state="error", error=str(e))
                self.stop.wait(10)

    def _hop_loop(self):
        bad = {}
        while not self.stop.is_set():
            if self._changed.is_set():  # new channel settings: start over with the new list
                self._changed.clear()
                bad.clear()
            if not self.mon:
                self.stop.wait(1)
                continue
            freqs = [f for f in self.channels if bad.get(f, 0) < 3]
            if not freqs:
                status.update(self.name, error="no usable channels for this adapter")
                self._pause(10)
                bad.clear()
                continue
            if len(freqs) == 1:
                ok, _ = set_freq(self.mon, freqs[0])
                status.update(self.name, channel=chan_label(freqs[0]) if ok else None,
                              band=band_of(freqs[0]) if ok else None)
                self.cur_freq = freqs[0] if ok else None
                t0 = time.time()
                self._pause(30)
                if ok:
                    self._emit_survey(freqs[0], time.time() - t0)
                continue
            for f in freqs:
                if self.stop.is_set() or not self.mon or self._changed.is_set():
                    break
                ok, out = set_freq(self.mon, f)
                if ok:
                    bad.pop(f, None)
                    status.update(self.name, channel=chan_label(f), band=band_of(f))
                    self.acc.pop(f, None)  # discard frames counted before the radio settled
                    self.cur_freq = f
                    t0 = time.time()
                    self._pause(self.hop_interval)
                    self.cur_freq = None
                    self._emit_survey(f, time.time() - t0)
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
            status.update(self.name, packets=self.packets, pps=round((self.packets - last) / (now - last_t), 1),
                          band_frames=dict(self.band_frames), relabelled=self.relabelled)
            last, last_t = self.packets, now
