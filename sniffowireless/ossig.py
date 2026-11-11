"""Operating-system evidence that is learned from the network itself, and the helpers that combine evidence.

* Learned Wi-Fi signatures: a client's probe-request layout (fp_hash), its extended-capability bits and the vendor elements it adds make
  a signature. When a device with that signature has its OS established by strong evidence of another kind (a DHCP vendor class, a
  Microsoft or Apple broadcast, an mDNS model ...), the pair (signature, OS) is counted, once per device. A device whose own evidence is
  silent about its OS then gets "the same pattern as N devices identified as Android" at a modest confidence, which grows with N and
  falls with disagreement. Nothing is shipped: it learns from your own network, so it works for what is around you, and it is only as
  good as the strong evidence it learns from. Learned and linked evidence is never used to learn (no feedback).
* Source categories: two clues from the same kind of source (two DHCP details) are not independent, so they count once.
"""
import math

# (category, words that mark a source text), first match wins
CATEGORIES = [
    ("learned", ("capability pattern shared",)), ("learned-scan", ("scan behaviour",)), ("linked", ("linked to",)), ("dhcp", ("dhcp",)), ("mdns", ("mdns",)),
    ("ssdp", ("upnp", "ssdp")), ("lldp", ("lldp",)), ("wps", ("wps",)), ("vendor-ie", ("vendor element",)),
    ("ble-apple", ("continuity", "proximity pairing", "airpods")), ("ble-ms", ("cdp",)),
    ("vendor", ("mac vendor", "manufacturer data", "bluetooth manufacturer")), ("name", ("device name", "network name", "hostname", "system name")),
    ("capabilities", ("capabilities", "no ht/vht")), ("ble", ("service", "appearance", "bluetooth", "ble ")),
]
FAMILIES = {"android": "Android", "apple": "iOS / macOS", "windows": "Windows", "linux": "Linux"}
MIN_DEVICES = 3        # a signature needs this many devices before it says anything
MIN_SHARE = 0.9        # and this share of them must agree
TRUSTED_CONF = 80      # evidence at least this strong may teach a signature


def source_category(source):
    s = (source or "").lower()
    for cat, words in CATEGORIES:
        if any(w in s for w in words):
            return cat
    return s.split(" ")[0] or "other"


def os_key(value):
    """Family key of an OS name ("Android 14" and "Android" are one, "iOS / macOS" and "iOS" too)."""
    v = (value or "").lower()
    if v.startswith("android"):
        return "android"
    if "ios" in v or "macos" in v or "ipados" in v or "tvos" in v or "watchos" in v:
        return "apple"
    if v.startswith("windows"):
        return "windows"
    if v.startswith("linux") and "android" not in v:
        return "linux"
    return v


LINUX_BASED = {"home assistant os", "openwrt", "raspberry pi os", "ubuntu", "debian", "fedora", "arch linux", "embedded linux (busybox)", "dsm", "qts",
               "tizen", "webos", "chromeos"}


def os_compatible(a, b):
    """True when two OS names do not contradict each other: the same family, or a generic "Linux" / "Linux / Android" next to anything
    that is Linux underneath (Android, Home Assistant OS, OpenWrt ...)."""
    ka, kb = os_key(a), os_key(b)
    if ka == kb:
        return True
    generic = {"linux", "linux / android"}
    for x, y in ((ka, kb), (kb, ka)):
        if x in generic and (y in generic or y in LINUX_BASED or y in ("android", "linux")):
            return True
    return False


def os_family(value):
    """The coarse family label the learner works with, or None for anything it should not learn (embedded, unknown)."""
    return FAMILIES.get(os_key(value))


def trusted_family(evidence, min_conf=TRUSTED_CONF):
    """The one OS family that strong, non-derived evidence agrees on, else None. `evidence`: the ident["evidence"] list."""
    fams = set()
    for e in evidence or []:
        if e.get("field") != "os" or e.get("conf", 0) < min_conf or source_category(e.get("source")) in ("learned", "learned-scan", "linked"):
            continue
        fams.add(os_family(e.get("value")))
    return fams.pop() if len(fams) == 1 and None not in fams else None


def wifi_signature(dev):
    """Signature of a Wi-Fi client's probe behaviour, or None when there is not enough to tell (needs a probe fingerprint)."""
    if dev.get("kind") != "wifi_client" or not dev.get("fp_hash"):
        return None
    wfp = ((dev.get("extra") or {}).get("fp") or {}).get("wifi") or {}
    ext = (wfp.get("capinfo") or {}).get("extcap") or ""
    return f"{dev['fp_hash']}|{ext}|{','.join(sorted(wfp.get('vendors') or []))}"


def scan_signature(dev):
    """Signature of how a Wi-Fi client scans (scanbehavior.py), or None until enough bursts were heard."""
    if dev.get("kind") != "wifi_client":
        return None
    return ((dev.get("extra") or {}).get("scan") or {}).get("sig")


def scan_conf(n, share):
    """Scan behaviour says less than the capability pattern: at most 55 (from about 10 devices)."""
    return min(55, int(30 + 12 * math.log2(n / 2 + 1) * share))


def learned_conf(n, share):
    """Confidence for 'n devices with this signature, `share` of them this OS': 59 for 3 devices, 70 (the cap) from about 8."""
    return min(70, int(40 + 15 * math.log2(n / 2 + 1) * share))


class OsLearner:
    """Counts (signature, OS family) once per device, in the database (tables os_signatures and os_sig_devices) and in memory."""

    def __init__(self, conn, prefix="os"):
        """prefix: which learner this is ("os": Wi-Fi capability signatures; "scan": scan-behaviour signatures); it names the tables."""
        self.conn = conn
        self.sigs, self.devs = f"{prefix}_signatures", f"{prefix}_sig_devices"
        conn.execute(f"CREATE TABLE IF NOT EXISTS {self.sigs}(sig TEXT NOT NULL, os TEXT NOT NULL, devices INTEGER NOT NULL, "
                     "PRIMARY KEY(sig, os)) WITHOUT ROWID")
        conn.execute(f"CREATE TABLE IF NOT EXISTS {self.devs}(mac TEXT PRIMARY KEY, sig TEXT NOT NULL, os TEXT NOT NULL) WITHOUT ROWID")
        self.reload()

    def reload(self):
        self.counts, self.seen = {}, {}
        for sig, os_, n in self.conn.execute(f"SELECT sig, os, devices FROM {self.sigs}"):
            self.counts.setdefault(sig, {})[os_] = n
        for mac, sig, os_ in self.conn.execute(f"SELECT mac, sig, os FROM {self.devs}"):
            self.seen[mac] = (sig, os_)

    def _bump(self, sig, os_, delta):
        n = self.counts.setdefault(sig, {}).get(os_, 0) + delta
        if n > 0:
            self.counts[sig][os_] = n
            self.conn.execute(f"INSERT INTO {self.sigs}(sig, os, devices) VALUES(?,?,?) ON CONFLICT(sig, os) DO UPDATE SET devices=excluded.devices",
                              (sig, os_, n))
        else:
            self.counts[sig].pop(os_, None)
            self.conn.execute(f"DELETE FROM {self.sigs} WHERE sig=? AND os=?", (sig, os_))

    def observe(self, mac, sig, os_):
        """A device whose OS is established says its signature belongs to that OS (a device counts once; a changed OS moves it)."""
        prev = self.seen.get(mac)
        if prev == (sig, os_):
            return
        if prev:
            self._bump(prev[0], prev[1], -1)
        self._bump(sig, os_, 1)
        self.seen[mac] = (sig, os_)
        self.conn.execute(f"INSERT OR REPLACE INTO {self.devs}(mac, sig, os) VALUES(?,?,?)", (mac, sig, os_))

    def lookup(self, sig, mac=None):
        """(os family, devices, share) for a signature, leaving out the asking device itself; None if it is not clear enough."""
        counts = dict(self.counts.get(sig) or {})
        mine = self.seen.get(mac)
        if mine and mine[0] == sig and counts.get(mine[1]):
            counts[mine[1]] -= 1
        total = sum(counts.values())
        if total < MIN_DEVICES:
            return None
        os_, n = max(counts.items(), key=lambda kv: kv[1])
        share = n / total
        return (os_, n, share) if n >= MIN_DEVICES and share >= MIN_SHARE else None

    def forget_all(self):
        self.conn.execute(f"DELETE FROM {self.sigs}")
        self.conn.execute(f"DELETE FROM {self.devs}")
        self.counts, self.seen = {}, {}
