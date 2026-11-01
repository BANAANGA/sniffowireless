"""Runtime configuration, read from environment variables."""
import os
from dataclasses import dataclass, field

CHANNELS_24 = list(range(1, 14))
CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120,
              124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
CHANNELS_DEFAULT = CHANNELS_24 + [36, 40, 44, 48, 149, 153, 157, 161, 165]


def _env(name, default=""):
    return os.environ.get(name, default).strip()


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


def parse_channels(spec):
    """Parse '1,6,11', '1-13,36-48', 'all', '2.4', '5' or '' (default set)."""
    spec = (spec or "").strip().lower()
    if spec in ("", "default"):
        return list(CHANNELS_DEFAULT)
    if spec == "all":
        return CHANNELS_24 + CHANNELS_5
    if spec in ("2.4", "2.4ghz", "24"):
        return list(CHANNELS_24)
    if spec in ("5", "5ghz"):
        return list(CHANNELS_5)
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            rng = range(int(a), int(b) + 1)
            # A range like 36-48 only makes sense for valid 5 GHz channels.
            out.extend(c for c in rng if c in CHANNELS_24 or c in CHANNELS_5 or c > 165)
        else:
            out.append(int(part))
    seen = set()
    return [c for c in out if not (c in seen or seen.add(c))]


@dataclass
class Config:
    db_path: str = "/data/yolo.db"
    manuf_path: str = "/app/data/manuf"
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    web_user: str = ""
    web_password: str = ""
    log_level: str = "INFO"

    wifi_interfaces: list = field(default_factory=list)
    wifi_channels: list = field(default_factory=lambda: list(CHANNELS_DEFAULT))
    wifi_channels_per_iface: dict = field(default_factory=dict)
    wifi_hop_interval: float = 0.5
    wifi_set_monitor: bool = True

    bt_devices: list = field(default_factory=list)
    bt_active_scan: bool = True
    bt_inquiry: bool = True
    bt_inquiry_interval: int = 60
    bt_resolve_names: bool = True

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
        ifaces = _list("WIFI_INTERFACES")
        per_iface = {}
        for i in ifaces:
            v = _env(f"WIFI_CHANNELS_{i}")
            if v:
                per_iface[i] = parse_channels(v)
        return cls(
            db_path=_env("DB_PATH", "/data/yolo.db"),
            manuf_path=_env("MANUF_PATH", "/app/data/manuf"),
            web_host=_env("WEB_HOST", "0.0.0.0"),
            web_port=_int("WEB_PORT", 8080),
            web_user=_env("WEB_USER"),
            web_password=_env("WEB_PASSWORD"),
            log_level=_env("LOG_LEVEL", "INFO").upper(),
            wifi_interfaces=ifaces,
            wifi_channels=parse_channels(_env("WIFI_CHANNELS")),
            wifi_channels_per_iface=per_iface,
            wifi_hop_interval=_float("WIFI_HOP_INTERVAL", 0.5),
            wifi_set_monitor=_bool("WIFI_SET_MONITOR", True),
            bt_devices=_list("BT_DEVICES"),
            bt_active_scan=_bool("BT_ACTIVE_SCAN", True),
            bt_inquiry=_bool("BT_INQUIRY", True),
            bt_inquiry_interval=_int("BT_INQUIRY_INTERVAL", 60),
            bt_resolve_names=_bool("BT_RESOLVE_NAMES", True),
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
