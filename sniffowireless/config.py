"""Runtime configuration, read from environment variables."""
import os
from dataclasses import dataclass, field

CHANNELS_24 = list(range(1, 14))
CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120,
              124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
CHANNELS_5_COMMON = [36, 40, 44, 48, 149, 153, 157, 161, 165]
CHANNELS_6 = list(range(1, 234, 4))  # 20 MHz channels 1..233
# Preferred Scanning Channels: 6 GHz APs advertise on these, so they find most networks quickly.
CHANNELS_6_PSC = list(range(5, 230, 16))


def _env(name, default=""):
    return os.environ.get(name, default).strip()


LEGACY_DB_PATH = "/data/yolo.db"  # the default database path before the yolo -> sniffowireless rename


def _default_db_path():
    """DB_PATH, falling back to the pre-rename default if that's where an existing install's data already
    is (so upgrading doesn't look like all your data vanished just because the default path changed)."""
    env = _env("DB_PATH")
    if env:
        return env
    new_default = "/data/sniffowireless.db"
    if not os.path.exists(new_default) and os.path.exists(LEGACY_DB_PATH):
        return LEGACY_DB_PATH
    return new_default


def _bool(name, default=False):
    return _env(name, "1" if default else "0").lower() in ("1", "true", "yes", "on")


def _int(name, default):
    v = _env(name)
    return int(v) if v else default


def _float(name, default):
    v = _env(name)
    return float(v) if v else default


def _list(name):
    return [p.strip() for p in _env(name).split(",") if p.strip()]


def _default_lora_profiles():
    from .lora_protocols import parse_profiles
    return parse_profiles("", "EU868")


def zigbee_channels(spec):
    """'15,20-25' -> channel numbers, keeping only 802.15.4's 2.4 GHz channels 11-26. Empty means all of them."""
    out = []
    for tok in [t.strip() for t in (spec or "").split(",") if t.strip()]:
        lo, _, hi = tok.partition("-")
        out.extend(c for c in range(int(lo), int(hi or lo) + 1) if 11 <= c <= 26 and c not in out)
    return out or list(range(11, 27))


def band_of(freq):
    if not freq:
        return None
    if freq >= 5925:
        return "6"
    if freq >= 4900:
        return "5"
    return "2.4"


def ch_to_freq(ch, band=None):
    """Channel number -> centre frequency (MHz). Without a band, 1-14 is 2.4 GHz, else 5 GHz."""
    if band == "6":
        return 5935 if ch == 2 else 5950 + ch * 5
    if band == "2.4" or (band is None and ch <= 14):
        return 2484 if ch == 14 else 2407 + ch * 5
    return 5000 + ch * 5


def freq_to_channel(f):
    if not f:
        return None
    if f == 2484:
        return 14
    if 2412 <= f <= 2472:
        return (f - 2407) // 5
    if 5000 <= f <= 5900:
        return (f - 5000) // 5
    if f == 5935:
        return 2
    if 5955 <= f <= 7115:
        return (f - 5950) // 5
    return None


def chan_label(freq):
    """Human readable channel label for a frequency, e.g. '6', '36', '6G:37'."""
    ch = freq_to_channel(freq)
    if ch is None:
        return f"{freq}MHz"
    return f"6G:{ch}" if band_of(freq) == "6" else str(ch)


PRESETS = {
    "2.4ghz": [ch_to_freq(c, "2.4") for c in CHANNELS_24],
    "5ghz": [ch_to_freq(c, "5") for c in CHANNELS_5],
    "5common": [ch_to_freq(c, "5") for c in CHANNELS_5_COMMON],
    "6ghz": [ch_to_freq(c, "6") for c in CHANNELS_6_PSC],
    "6all": [ch_to_freq(c, "6") for c in CHANNELS_6],
}
PRESETS["default"] = PRESETS["2.4ghz"] + PRESETS["5common"]
PRESETS["all"] = PRESETS["2.4ghz"] + PRESETS["5ghz"] + PRESETS["6ghz"]
ALIASES = {"": "default", "2.4": "2.4ghz", "6g": "6ghz", "6e": "6ghz", "6psc": "6ghz",
           "6g:psc": "6ghz", "6g:all": "6all"}
# A bare "5" or "6" is a band preset only when it is the whole spec ("1,5,9" are channels).
WHOLE_SPEC = {"5": "5ghz", "6": "6ghz"}


def _valid_channels(band):
    if band == "6":
        return set(CHANNELS_6)
    if band == "2.4":
        return set(CHANNELS_24) | {14}
    if band == "5":
        return set(CHANNELS_5)
    return set(CHANNELS_24) | set(CHANNELS_5)


def parse_channels(spec):
    """Parse a channel spec into a list of frequencies (MHz).

    Tokens are comma separated and may be presets (default, all, 2.4ghz, 5ghz, 6ghz, 6all),
    plain channels/ranges (1,6,11,36-48: 1-14 are 2.4 GHz, the rest 5 GHz) or 6 GHz
    channels with a '6g:' prefix (6g:5,6g:37-69). Ranges keep only valid channel numbers.
    """
    spec = (spec or "").strip().lower()
    if spec in WHOLE_SPEC:
        return list(PRESETS[WHOLE_SPEC[spec]])
    out = []
    for tok in [t.strip() for t in spec.split(",")] if spec else [""]:
        tok = ALIASES.get(tok, tok)
        if tok in PRESETS:
            out.extend(PRESETS[tok])
            continue
        band = None
        for prefix, b in (("6g:", "6"), ("5g:", "5"), ("2g:", "2.4")):
            if tok.startswith(prefix):
                band, tok = b, tok[len(prefix):]
                break
        if not tok:
            continue
        if "-" in tok:
            lo, hi = (int(x) for x in tok.split("-", 1))
            valid = _valid_channels(band)
            out.extend(ch_to_freq(c, band) for c in range(lo, hi + 1) if c in valid)
        else:
            out.append(ch_to_freq(int(tok), band))
    seen = set()
    return [f for f in out if not (f in seen or seen.add(f))]


@dataclass
class Config:
    db_path: str = "/data/sniffowireless.db"
    manuf_path: str = "/app/data/manuf"
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    web_user: str = ""
    web_password: str = ""
    reset_2fa_user: str = ""   # RESET_2FA_USER: remove this user's two-factor login at startup (lost phone)
    auth_disabled: bool = False
    allowed_hosts: list = field(default_factory=list)
    trusted_proxies: str = "127.0.0.1"
    data_dir: str = "/data"
    # "server" (default: capture + store + web UI) or "sensor" (capture only, forward to a server)
    mode: str = "server"
    server_url: str = ""
    sensor_token: str = ""
    log_level: str = "INFO"

    wifi_interfaces: list = field(default_factory=list)
    wifi_channels: list = field(default_factory=lambda: list(PRESETS["default"]))  # MHz
    wifi_channels_per_iface: dict = field(default_factory=dict)
    wifi_hop_interval: float = 0.5
    wifi_set_monitor: bool = True
    wifi_regdomain: str = ""

    bt_devices: list = field(default_factory=list)
    bt_active_scan: bool = True
    bt_extended_scan: bool = True   # use LE extended scanning (Bluetooth 5/6 advertisements) when the controller supports it
    bt_inquiry: bool = True
    bt_inquiry_interval: int = 60
    bt_resolve_names: bool = True

    eth_interfaces: list = field(default_factory=list)
    eth_promisc: bool = True
    zigbee_devices: list = field(default_factory=list)
    zigbee_channels: list = field(default_factory=lambda: list(range(11, 27)))
    zigbee_hop_interval: float = 2.0
    zigbee_scan_interval: int = 600
    zigbee_sniff: bool = True
    lora_devices: list = field(default_factory=list)
    lora_region: str = "EU868"
    lora_profiles: list = field(default_factory=lambda: _default_lora_profiles())
    lora_hop_interval: float = 5.0

    lan_session_timeout: int = 900
    wifi_session_timeout: int = 300
    bt_session_timeout: int = 180
    active_window: int = 300
    retention_days: int = 30
    flush_interval: float = 2.0
    events_for_randomized: bool = False
    ignore_macs: set = field(default_factory=set)

    demo: bool = False
    demo_backfill_hours: int = 72

    @classmethod
    def from_env(cls):
        from .lora_protocols import parse_profiles
        region = (_env("LORA_REGION") or "EU868").upper()
        try:
            lora_profiles = parse_profiles(_env("LORA_PROFILES"), region)
        except ValueError as e:
            raise SystemExit(f"LORA_PROFILES / LORA_REGION: {e}")
        ifaces = _list("WIFI_INTERFACES")
        per_iface = {}
        for i in ifaces:
            v = _env(f"WIFI_CHANNELS_{i}")
            if v:
                per_iface[i] = parse_channels(v)
        return cls(
            db_path=_default_db_path(),
            manuf_path=_env("MANUF_PATH", "/app/data/manuf"),
            web_host=_env("WEB_HOST", "0.0.0.0"),
            web_port=_int("WEB_PORT", 8080),
            web_user=_env("WEB_USER"),
            web_password=_env("WEB_PASSWORD"),
            reset_2fa_user=_env("RESET_2FA_USER"),
            auth_disabled=_bool("AUTH_DISABLED", False),
            allowed_hosts=_list("ALLOWED_HOSTS"),
            trusted_proxies=_env("TRUSTED_PROXIES", "127.0.0.1"),
            data_dir=_env("DATA_DIR") or os.path.dirname(os.path.abspath(_default_db_path())),
            mode=_env("SNIFFOWIRELESS_MODE", "server").lower(),
            server_url=_env("SERVER_URL").rstrip("/"),
            sensor_token=_env("SENSOR_TOKEN"),
            log_level=_env("LOG_LEVEL", "INFO").upper(),
            wifi_interfaces=ifaces,
            wifi_channels=parse_channels(_env("WIFI_CHANNELS")),
            wifi_channels_per_iface=per_iface,
            wifi_hop_interval=_float("WIFI_HOP_INTERVAL", 0.5),
            wifi_set_monitor=_bool("WIFI_SET_MONITOR", True),
            wifi_regdomain=_env("WIFI_REGDOMAIN").upper(),
            bt_devices=_list("BT_DEVICES"),
            bt_active_scan=_bool("BT_ACTIVE_SCAN", True),
            bt_extended_scan=_bool("BT_EXTENDED_SCAN", True),
            bt_inquiry=_bool("BT_INQUIRY", True),
            bt_inquiry_interval=_int("BT_INQUIRY_INTERVAL", 60),
            bt_resolve_names=_bool("BT_RESOLVE_NAMES", True),
            zigbee_devices=_list("ZIGBEE_DEVICES"),
            zigbee_channels=zigbee_channels(_env("ZIGBEE_CHANNELS")),
            zigbee_hop_interval=max(0.2, _float("ZIGBEE_HOP_INTERVAL", 2.0)),
            zigbee_scan_interval=max(30, _int("ZIGBEE_SCAN_INTERVAL", 600)),
            zigbee_sniff=_bool("ZIGBEE_SNIFF", True),
            lora_devices=_list("LORA_DEVICES"),
            lora_region=region,
            lora_profiles=lora_profiles,
            lora_hop_interval=max(0.5, _float("LORA_HOP_INTERVAL", 5.0)),
            eth_interfaces=_list("ETH_INTERFACES"),
            eth_promisc=_bool("ETH_PROMISC", True),
            lan_session_timeout=_int("LAN_SESSION_TIMEOUT", 900),
            wifi_session_timeout=_int("WIFI_SESSION_TIMEOUT", 300),
            bt_session_timeout=_int("BT_SESSION_TIMEOUT", 180),
            active_window=_int("ACTIVE_WINDOW", 300),
            retention_days=_int("RETENTION_DAYS", 30),
            flush_interval=_float("FLUSH_INTERVAL", 2.0),
            events_for_randomized=_bool("EVENTS_FOR_RANDOMIZED", False),
            ignore_macs={m.lower() for m in _list("IGNORE_MACS")},
            demo=_bool("DEMO_MODE", False),
            demo_backfill_hours=_int("DEMO_BACKFILL_HOURS", 72),
        )
