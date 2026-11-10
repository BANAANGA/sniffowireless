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
ZB_SHORT = re.compile(r"0x[0-9a-f]{4}")
ZB_EUI64 = re.compile(r"(?:[0-9a-f]{2}:){7}[0-9a-f]{2}")
ZB_CHANNEL_BITS = 0x07FFF800
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


def _zb_channel(v):
    return clean_num(v, 11, 26, True)


def _zb_address(v):
    """A short address ('0x1a2b') or an EUI-64."""
    if isinstance(v, str) and (ZB_SHORT.fullmatch(v) or ZB_EUI64.fullmatch(v)):
        return v
    return None


LORA_HEX = re.compile(r"[0-9a-f]{2,510}")
LORA_BANDWIDTHS = (7.8, 10.4, 15.6, 20.8, 31.25, 41.7, 62.5, 125.0, 250.0, 500.0)


def _lora_observation(o, ts):
    """A LoRa frame heard by a remote sniffer: radio figures in the range the radio can have, and the frame as lower-case hex."""
    freq, bw, sf = clean_num(o.get("freq"), 150, 960), clean_num(o.get("bw"), 7, 500), clean_num(o.get("sf"), 5, 12, True)
    sync, rssi, snr = clean_num(o.get("sync"), 0, 255, True), clean_num(o.get("rssi"), -200, 20), clean_num(o.get("snr"), -60, 60)
    hexed = o.get("hex").lower() if isinstance(o.get("hex"), str) else None
    if None in (freq, bw, sf, sync, rssi, snr) or not isinstance(hexed, str) or len(hexed) % 2 or not LORA_HEX.fullmatch(hexed):
        return None
    if min(abs(bw - b) for b in LORA_BANDWIDTHS) > 0.5:
        return None
    r = {"t": "lora_frame", "ts": ts, "mac": "-", "freq": freq, "bw": bw, "sf": sf, "sync": sync, "rssi": rssi, "snr": snr, "hex": hexed,
         "profile": clean_str(o.get("profile"), 32), "ferr": clean_num(o.get("ferr"), -200000, 200000)}
    return {k: v for k, v in r.items() if v is not None}


def _zigbee_observation(o, t, ts):
    r = {"t": t, "ts": ts, "mac": "-"}
    if t == "zb_network":
        ext_pan, pan, channel = o.get("ext_pan"), clean_num(o.get("pan"), 0, 0xFFFF, True), _zb_channel(o.get("channel"))
        if not (isinstance(ext_pan, str) and ZB_EUI64.fullmatch(ext_pan)) or pan is None or channel is None:
            return None
        routers = o.get("routers") if isinstance(o.get("routers"), list) else []
        r.update(ext_pan=ext_pan, pan=pan, channel=channel, permit_join=bool(o.get("permit_join")),
                 stack_profile=clean_num(o.get("stack_profile"), 0, 15, True), update_id=clean_num(o.get("update_id"), 0, 255, True),
                 lqi=clean_num(o.get("lqi"), 0, 255, True), rssi=clean_num(o.get("rssi"), -127, 20, True),
                 routers=[x for x in (clean_num(v, 0, 0xFFFF, True) for v in routers[:256]) if x is not None])
    elif t == "zb_energy":
        readings = []
        for it in (o.get("readings") or [])[:16] if isinstance(o.get("readings"), list) else []:
            if isinstance(it, (list, tuple)) and len(it) == 2:
                ch, rssi = _zb_channel(it[0]), clean_num(it[1], -127, 20, True)
                if ch is not None and rssi is not None:
                    readings.append([ch, rssi])
        r["readings"] = readings
    else:
        channels = {}
        for ch, n in list(o.get("channels").items())[:16] if isinstance(o.get("channels"), dict) else []:
            c, frames = clean_num(ch, 11, 26, True) if str(ch).isdigit() else None, clean_num(n, 0, 10 ** 9, True)
            if c is not None and frames is not None:
                channels[str(c)] = frames
        radios = []
        for it in (o.get("radios") or [])[:5000] if isinstance(o.get("radios"), list) else []:
            if not isinstance(it, (list, tuple)) or len(it) != 10:
                continue
            pan, addr = clean_num(it[0], -1, 0xFFFF, True), _zb_address(it[1])
            mask = clean_num(it[2], 0, ZB_CHANNEL_BITS, True)
            sent, received, encrypted = (clean_num(x, 0, 10 ** 9, True) for x in it[3:6])
            hint, types = clean_num(it[6], 0, 3, True), clean_num(it[7], 0, 31, True)
            if None in (pan, addr, mask, sent, received, encrypted, hint, types):
                continue
            radios.append([pan, addr, mask, sent, received, encrypted, hint, types,
                           clean_num(it[8], -127, 20, True), clean_num(it[9], 0, 255, True)])
        r.update(channels=channels, radios=radios)
    return {k: v for k, v in r.items() if v is not None}


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
    if t in ("zb_network", "zb_energy", "zb_frames"):
        return _zigbee_observation(o, t, ts)
    if t == "lora_frame":
        return _lora_observation(o, ts)
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
                 "band": 8, "scan": 16, "firmware": 64, "warning": 300, "regdomain": 8, "note": 160, "profile": 48, "bt_version": 16, "chip": 40}


def remote_version(v):
    """The version a remote sensor reports about itself: short plain strings only (it is shown on the Sensors page)."""
    if not isinstance(v, dict):
        return None
    out = {k: clean_str(v[k], 40) for k in ("version", "commit", "built", "arch") if isinstance(v.get(k), str)}
    out = {k: x for k, x in out.items() if x}
    if out.get("version"):
        out["release"] = bool(re.match(r"^v?\d+(\.\d+)*$", out["version"]))
    return out or None


LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
LOG_KEEP = {"\n", "\t"}


def remote_log_line(x, now, adjust=0.0):
    """One log line a remote sensor sent: level, source and text only, with control and bidi characters removed (newlines of a
    traceback stay), and the time moved by the sensor's clock offset and kept within a sane range. None when it is not a line."""
    if not isinstance(x, dict) or x.get("level") not in LOG_LEVELS or not isinstance(x.get("msg"), str):
        return None
    ts = clean_num(x.get("ts"), 0, 4_000_000_000)
    ts = ts + adjust if ts is not None else now
    if not now - 7 * 86400 <= ts <= now + 300:
        ts = now
    msg = "".join(ch for ch in x["msg"][:2000] if ch in LOG_KEEP or unicodedata.category(ch)[0] != "C")
    return {"src_id": clean_num(x.get("id"), 0, 10 ** 12, True) or 0, "ts": ts, "level": x["level"],
            "logger": clean_str(x.get("logger"), 64) or "?", "msg": msg, "thread": clean_str(x.get("thread"), 40)}


def remote_system(s):
    """A remote sensor's load and memory figures (the shape of sysinfo.snapshot, without the database): numbers in
    sane ranges only, since the server shows them and exports them to Prometheus."""
    if not isinstance(s, dict):
        return None
    c, m, d = (s[k] if isinstance(s.get(k), dict) else {} for k in ("cpu", "memory", "disk"))
    load = [clean_num(x, 0, 100000) for x in c["load"][:3]] if isinstance(c.get("load"), list) else None
    big = 2 ** 50
    out = {"cpu": {"percent": clean_num(c.get("percent"), 0, 100), "sniffowireless_percent": clean_num(c.get("sniffowireless_percent"), 0, 100),
                   "cores": clean_num(c.get("cores"), 1, 4096, True), "load": load if load and len(load) == 3 and None not in load else None},
           "memory": {"total": clean_num(m.get("total"), 0, big, True), "used": clean_num(m.get("used"), 0, big, True),
                      "sniffowireless_rss": clean_num(m.get("sniffowireless_rss"), 0, big, True)},
           "disk": {k: clean_num(d.get(k), 0, big, True) for k in ("total", "used", "free")}}
    out = {k: {a: b for a, b in v.items() if b is not None} for k, v in out.items()}
    return {k: v for k, v in out.items() if v} or None


def remote_status(s):
    """Validate a sensor status entry pushed by a remote sensor."""
    if not isinstance(s, dict) or not clean_str(s.get("name"), 64):
        return None
    out = {k: clean_str(s.get(k), n) for k, n in SENSOR_STATUS.items() if s.get(k) is not None}
    for k in ("packets", "adverts", "inquiries", "crc_errors", "fw_version"):
        if s.get(k) is not None:
            out[k] = clean_num(s.get(k), 0, 10 ** 15, True)
    if s.get("pps") is not None:
        out["pps"] = clean_num(s.get("pps"), 0, 10 ** 9)
    if s.get("chan_rev") is not None:
        out["chan_rev"] = clean_num(s.get("chan_rev"), 0, 10 ** 9, True)
    if s.get("lora_rev") is not None:
        out["lora_rev"] = clean_num(s.get("lora_rev"), 0, 10 ** 9, True)
    if s.get("zb_rev") is not None:
        out["zb_rev"] = clean_num(s.get("zb_rev"), 0, 10 ** 9, True)
    if isinstance(s.get("zb_channels"), list):  # the Zigbee channels a stick listens on
        out["zb_channels"] = [clean_num(c, 11, 26, True) for c in s["zb_channels"][:16] if isinstance(c, int) and 11 <= c <= 26]
    if isinstance(s.get("profiles"), list):  # the LoRa profiles a board hops over
        out["profiles"] = [x for x in (clean_str(p, 48) for p in s["profiles"][:64] if isinstance(p, str)) if x]
    for k, valid in (("channels", None), ("skipped", None), ("caps", None), ("bands", BANDS), ("supported_bands", BANDS)):
        if isinstance(s.get(k), list):  # Wi-Fi channel labels / bands, for the Channels page
            items = [clean_str(x, 16) for x in s[k][:100] if isinstance(x, str)]
            out[k] = [x for x in items if x and (valid is None or x in valid)]
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
