"""Input validation for data that comes from outside: radio frames (any device nearby controls names / SSIDs),
remote sensors (anyone holding a sensor token) and the API. Everything is coerced to the expected type, bounded
in length/size and stripped of control characters; anything that doesn't fit is dropped."""
import ipaddress
import math
import re
import unicodedata

MAC_RX = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
MAC_PREFIX_RX = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){1,4}$")
SENSOR_ID_RX = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
BANDS = {"2.4", "5", "6"}
FRAMES = {"data", "assoc", "assoc_fail", "auth", "probe", "probe_resp", "deauth", "disassoc"}
REMOTE_EVENTS = {"deauth_broadcast"}
LAN_SOURCES = {"arp", "dhcp", "mdns", "ssdp", "lldp", "dns", "traffic", "dhcp-server"}
MAX_STR = 256


def clean_str(v, max_len=128):
    """Printable text only (no control / format characters such as newlines or bidi overrides), trimmed."""
    if v is None:
        return None
    if isinstance(v, bytes):
        v = v.decode("utf-8", "replace")
    if not isinstance(v, str):
        v = str(v)
    v = "".join(ch for ch in v if unicodedata.category(ch)[0] != "C")
    return v.strip()[:max_len] or None


def clean_mac(v):
    if not isinstance(v, str):
        return None
    v = v.strip().lower().replace("-", ":")
    return v if MAC_RX.match(v) else None


def clean_ip(v):
    if v is None:
        return None
    try:
        return str(ipaddress.ip_address(str(v).strip()))
    except ValueError:
        return None


def clean_num(v, lo=None, hi=None, integer=False):
    if isinstance(v, bool) or v is None:
        return None
    try:
        n = int(v) if integer else float(v)
    except (TypeError, ValueError, OverflowError):
        return None
    if not integer and not math.isfinite(n):
        return None
    if (lo is not None and n < lo) or (hi is not None and n > hi):
        return None
    return n


def clean_json(v, depth=0, max_items=64):
    """Bounded copy of a JSON-ish value (fingerprints, extra info): str/num/bool/None, lists and dicts."""
    if depth > 5:
        return None
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, (int, float)):
        return v if math.isfinite(v) else None
    if isinstance(v, str):
        return clean_str(v, MAX_STR)
    if isinstance(v, (list, tuple)):
        return [x for x in (clean_json(i, depth + 1, max_items) for i in list(v)[:max_items]) if x is not None]
    if isinstance(v, dict):
        out = {}
        for k, x in list(v.items())[:max_items]:
            k = clean_str(k, 64)
            x = clean_json(x, depth + 1, max_items)
            if k and x is not None:
                out[k] = x
        return out
    return None


def clean_csa(c):
    """Channel switch announcement from a remote sensor: {mode, new_channel, count[, op_class]} or None."""
    if not isinstance(c, dict):
        return None
    ch = clean_num(c.get("new_channel"), 1, 233, True)
    if ch is None:
        return None
    r = {"mode": clean_num(c.get("mode"), 0, 255, True) or 0, "new_channel": ch,
         "count": clean_num(c.get("count"), 0, 255, True) or 0}
    if c.get("op_class") is not None:
        r["op_class"] = clean_num(c.get("op_class"), 0, 255, True)
    return r


def remote_observation(o, now):
    """Validate one observation pushed by a remote sensor. Returns a cleaned dict or None."""
    if not isinstance(o, dict):
        return None
    t = o.get("t")
    ts = clean_num(o.get("ts"), now - 7 * 86400, now + 300)
    if ts is None:
        return None
    if t == "chan":
        freq = clean_num(o.get("freq"), 2000, 8000, True)
        if freq is None:
            return None
        r = {"t": t, "ts": ts, "mac": "-", "freq": freq}
        for k in ("dwell_ms", "frames", "bytes", "airtime_us", "retries", "noise_cnt"):
            r[k] = clean_num(o.get(k), 0, 10 ** 12, True) or 0
        r["noise_sum"] = clean_num(o.get("noise_sum"), -10 ** 9, 0, True) or 0
        return r
    if t == "lan_traffic":
        items = []
        for it in (o.get("items") or [])[:50_000]:
            if not isinstance(it, (list, tuple)) or len(it) != 8:
                continue
            mac, peer = clean_mac(it[0]), clean_ip(it[1])
            proto, port = clean_num(it[2], 0, 255, True), clean_num(it[3], 0, 65535, True)
            b_out, b_in, pk = (clean_num(x, 0, 10 ** 13, True) for x in it[4:7])
            if None in (mac, peer, proto, port, b_out, b_in, pk):
                continue
            items.append((mac, peer, proto, port, b_out, b_in, pk, clean_str(it[7], 253)))
        hosts = {}
        for m, ip in list((o.get("hosts") or {}).items())[:50_000] if isinstance(o.get("hosts"), dict) else []:
            m, ip = clean_mac(m), clean_ip(ip)
            if m and ip:
                hosts[m] = ip
        return {"t": t, "ts": ts, "mac": "-", "items": items, "hosts": hosts}
    mac = clean_mac(o.get("mac"))
    if mac is None:
        return None
    r = {"t": t, "ts": ts, "mac": mac, "rssi": clean_num(o.get("rssi"), -127, 20, True)}
    if t in ("wifi_ap", "wifi_client"):
        r.update(freq=clean_num(o.get("freq"), 2000, 8000, True), channel=clean_num(o.get("channel"), 1, 233, True),
                 band=o.get("band") if o.get("band") in BANDS else None, vendor=clean_str(o.get("vendor")))
        if t == "wifi_ap":
            r.update(ssid=clean_str(o.get("ssid"), 64), enc=clean_str(o.get("enc"), 64), csa=clean_csa(o.get("csa")))
        else:
            r.update(bssid=clean_mac(o.get("bssid")), frame=o.get("frame") if o.get("frame") in FRAMES else None,
                     probe=clean_str(o.get("probe"), 64), reason=clean_num(o.get("reason"), 0, 65535, True),
                     from_ap=True if o.get("from_ap") else None)
    elif t in ("bt", "bt_conn"):
        if o.get("kind") not in ("ble", "bt_classic"):
            return None
        r.update(kind=o["kind"], name=clean_str(o.get("name")), vendor=clean_str(o.get("vendor")),
                 randomized=bool(o.get("randomized")), addr_random=bool(o.get("addr_random")))
        if t == "bt_conn":
            r.update(connected=bool(o.get("connected")), peer=clean_str(o.get("peer"), 64),
                     detail=clean_str(o.get("detail"), 128))
    elif t == "lan":
        r.update(ip=clean_ip(o.get("ip")), name=clean_str(o.get("name")), dns=clean_str(o.get("dns"), 253),
                 src=o.get("src") if o.get("src") in LAN_SOURCES else None)
    elif t == "dhcp_server":
        r.update(ip=clean_ip(o.get("ip")), msg=clean_str(o.get("msg"), 16), client=clean_mac(o.get("client")),
                 router=clean_ip(o.get("router")))
    elif t == "event":
        if o.get("type") not in REMOTE_EVENTS:
            return None
        r.update(type=o["type"], detail=clean_str(o.get("detail"), 200), peer=clean_str(o.get("peer"), 64))
    else:
        return None
    for k in ("fp", "extra"):
        if isinstance(o.get(k), dict):
            r[k] = clean_json(o[k])
    return {k: v for k, v in r.items() if v is not None}


SENSOR_STATUS = {"name": 64, "state": 32, "error": 200, "type": 32, "iface": 32, "mon": 32, "channel": 16,
                 "band": 8, "scan": 16}


def remote_status(s):
    """Validate a sensor status entry pushed by a remote sensor."""
    if not isinstance(s, dict) or not clean_str(s.get("name"), 64):
        return None
    out = {k: clean_str(s.get(k), n) for k, n in SENSOR_STATUS.items() if s.get(k) is not None}
    for k in ("packets", "adverts", "inquiries"):
        if s.get(k) is not None:
            out[k] = clean_num(s.get(k), 0, 10 ** 15, True)
    if s.get("pps") is not None:
        out["pps"] = clean_num(s.get("pps"), 0, 10 ** 9)
    return {k: v for k, v in out.items() if v is not None}


# ------------------------------------------------------------------ API field types (pydantic)
from typing import Annotated, List  # noqa: E402

from pydantic import AfterValidator, Field  # noqa: E402


def _mac(v):
    m = clean_mac(v)
    if not m:
        raise ValueError("invalid MAC address (expected aa:bb:cc:dd:ee:ff)")
    return m


def _prefix(v):
    v = v.strip().lower().replace("-", ":").rstrip(":*")
    if not MAC_PREFIX_RX.match(v):
        raise ValueError("invalid MAC prefix (expected e.g. 24:0a:c4)")
    return v


def _text(v):
    return clean_str(v, 10_000) or ""


def _multiline(v):
    return "\n".join(clean_str(line, 10_000) or "" for line in v.splitlines()).strip()


Mac = Annotated[str, Field(max_length=17), AfterValidator(_mac)]
MacPrefix = Annotated[str, Field(max_length=14), AfterValidator(_prefix)]
Ssid = Annotated[str, Field(min_length=1, max_length=64), AfterValidator(_text)]
Name = Annotated[str, Field(max_length=80), AfterValidator(_text)]
Notes = Annotated[str, Field(max_length=2000), AfterValidator(_multiline)]
MacList = Annotated[List[Mac], Field(max_length=1000)]
