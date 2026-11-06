"""Wi-Fi channel settings that can be changed from the web UI, for this server's adapters and for remote sensors.

The settings live on the server (settings key "channels"): one entry for "local" and one per remote sensor id, each
{rev, channels, per_iface, regdomain, hop_interval}. A missing value means "use the sensor's own environment"
(WIFI_CHANNELS, WIFI_CHANNELS_<iface>, WIFI_REGDOMAIN, WIFI_HOP_INTERVAL), so nothing changes until an admin sets
something. `rev` goes up on every change.

* This server: saving applies at once to the running adapters (WifiControl.apply).
* A remote sensor: the server returns the entry in every ingest response; the sensor applies it when `rev` is new and
  reports the revision it runs (status field `chan_rev`), which is how the UI knows it arrived.
"""
import logging
import re
import threading
import time
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from . import status
from .auth import require_admin
from .config import PRESETS, band_of, chan_label, parse_channels

log = logging.getLogger("sniffowireless.channels")

KNOWN_FREQS = set(PRESETS["2.4ghz"]) | {2484} | set(PRESETS["5ghz"]) | set(PRESETS["6all"])
IFACE_RX = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
REGDOMAIN_RX = re.compile(r"^[A-Z]{2}$")
HOP_MIN, HOP_MAX = 0.2, 60.0
OVERRIDE_KEYS = ("channels", "per_iface", "regdomain", "hop_interval")


def check_spec(spec):
    """The frequencies a channel list stands for, or a ValueError saying what is wrong with it."""
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError("The channel list is empty")
    if len(spec) > 200:
        raise ValueError("The channel list is too long")
    try:
        freqs = parse_channels(spec)
    except (ValueError, TypeError):
        raise ValueError(f"“{spec}” is not a valid channel list. Use presets (default, 5common, 6ghz, all, …) or channel "
                         "numbers like 1,6,11 or 36-48; 6 GHz channels need a 6g: prefix (6g:37)")
    unknown = [f for f in freqs if f not in KNOWN_FREQS]
    if unknown:
        raise ValueError("Unknown channel(s): " + ", ".join(chan_label(f) for f in unknown[:6]))
    return freqs


def clean_override(o):
    """Only the known keys, with their values checked (ValueError if one is not valid)."""
    o = o if isinstance(o, dict) else {}
    out = {"channels": None, "per_iface": {}, "regdomain": None, "hop_interval": None}
    if o.get("channels"):
        check_spec(o["channels"])
        out["channels"] = o["channels"].strip()
    for iface, spec in list((o.get("per_iface") or {}).items())[:8]:
        if not isinstance(iface, str) or not IFACE_RX.match(iface):
            raise ValueError(f"“{iface}” is not an interface name")
        if spec is None:
            continue
        if spec != "":
            check_spec(spec)
            spec = spec.strip()
        out["per_iface"][iface] = spec  # "" = share the general list (also drops a per-adapter list from the environment)
    if o.get("regdomain"):
        rd = str(o["regdomain"]).strip().upper()
        if not REGDOMAIN_RX.match(rd):
            raise ValueError("The regulatory domain is a two-letter country code, for example NL")
        out["regdomain"] = rd
    if o.get("hop_interval") not in (None, ""):
        try:
            hop = float(o["hop_interval"])
        except (TypeError, ValueError):
            raise ValueError("The hop interval is a number of seconds")
        if not HOP_MIN <= hop <= HOP_MAX:
            raise ValueError(f"The hop interval must be between {HOP_MIN:g} and {HOP_MAX:g} seconds")
        out["hop_interval"] = hop
    return out


def effective(cfg, override=None):
    """What an adapter set should run: the override on top of the process's environment."""
    o = clean_override(override) if override else {}
    channels = parse_channels(o["channels"]) if o.get("channels") else list(cfg.wifi_channels)
    per = {i: list(f) for i, f in cfg.wifi_channels_per_iface.items()}
    for iface, spec in (o.get("per_iface") or {}).items():
        if spec == "":
            per.pop(iface, None)
        elif spec:
            per[iface] = parse_channels(spec)
    return {"channels": channels, "per_iface": per,
            "regdomain": (o.get("regdomain") or cfg.wifi_regdomain or "").upper(),
            "hop_interval": float(o.get("hop_interval") or cfg.wifi_hop_interval)}


class WifiControl:
    """The Wi-Fi adapters of this process (the server, or a remote sensor) and the plan that says which channels each
    one hops over. Starts them from the environment plus any saved override, and can re-plan while they run."""

    def __init__(self, cfg, sink, handshake=None, override=None, rev=0):
        self.cfg, self.sink, self.handshake = cfg, sink, handshake
        self.override, self.rev = override or None, rev   # rev 0: the process's own settings
        self.sensors, self.supported = [], {}
        self.lock = threading.Lock()
        self.regdomain = None          # the country last set by us
        self.reg_warning = None
        self._rejected_rev = None      # a pushed revision that failed validation: log it once

    # ---------------------------------------------------------------- planning
    def _plan(self, eff, log_it=False):
        from .wifi import assign_channels
        per = eff["per_iface"]
        auto = [i for i in self.cfg.wifi_interfaces if i not in per]
        plan = assign_channels(eff["channels"], auto, {i: self.supported.get(i) for i in auto})
        out = {}
        for iface in self.cfg.wifi_interfaces:
            out[iface] = per.get(iface) or plan.get(iface) or eff["channels"]
        if log_it:
            for iface in auto:
                sup = self.supported.get(iface)
                if sup is None:
                    continue
                missing = [chan_label(f) for f in eff["channels"] if f not in sup]
                if missing:
                    log.info("%s cannot tune %d configured channels (%s...)", iface, len(missing), ",".join(missing[:6]))
                six = [f for f in eff["channels"] if band_of(f) == "6"]
                others = [self.supported.get(i) for i in self.cfg.wifi_interfaces if i != iface]
                if six and not any(f in sup for f in six):
                    covered = any(o and any(f in o for f in six) for o in others)  # another adapter takes them
                    (log.info if covered else log.warning)(
                        "%s: none of the %d configured 6 GHz channels is usable: the adapter has no 6 GHz support or the "
                        "regulatory domain disables it (set WIFI_REGDOMAIN; check 'iw reg get' and 'iw phy' on the host)",
                        iface, len(six))
        return out

    def _read_supported(self):
        from .wifi import supported_freqs
        self.supported = {i: supported_freqs(i) for i in self.cfg.wifi_interfaces}

    def _regulatory(self, eff):
        """Set the country if it changed, and note whether 6 GHz is blocked. Returns True when a country was set."""
        from .wifi import global_regdomain, regulatory_warning, set_regdomain
        changed = False
        if eff["regdomain"] and eff["regdomain"] != self.regdomain:
            set_regdomain(eff["regdomain"])
            self.regdomain = eff["regdomain"]
            time.sleep(2)  # the kernel applies a new regulatory domain asynchronously
            changed = True
        every = list(eff["channels"]) + [f for fl in eff["per_iface"].values() for f in fl]
        self.reg_warning = regulatory_warning(global_regdomain(), eff["regdomain"], any(band_of(f) == "6" for f in every))
        return changed

    def _bands(self, iface):
        sup = self.supported.get(iface)
        return sorted({band_of(f) for f in sup}) if sup else None

    # ---------------------------------------------------------------- start
    def start(self, stop):
        """Start a WifiSensor for every configured adapter; returns how many."""
        from .wifi import WifiSensor
        try:
            eff = effective(self.cfg, self.override)
        except ValueError as e:  # e.g. a backup restored with a value this version doesn't accept: don't stop capturing
            log.warning("Ignoring the saved channel settings (%s); using the environment", e)
            self.override, self.rev = None, 0
            eff = effective(self.cfg)
        self._regulatory(eff)   # the country decides which channels the adapters can tune, so it comes first
        self._read_supported()
        plan = self._plan(eff, log_it=True)
        for iface in self.cfg.wifi_interfaces:
            sensor = WifiSensor(iface, plan[iface], self.cfg, self.sink, handshake=self.handshake)
            sensor.hop_interval = eff["hop_interval"]
            self.sensors.append(sensor)
            status.update(sensor.name, chan_rev=self.rev, regdomain=eff["regdomain"] or None,
                          **({"supported_bands": self._bands(iface)} if self._bands(iface) else {}),
                          **({"warning": self.reg_warning} if self.reg_warning else {}))
            sensor.start(stop)
            log.info("Wi-Fi sensor on %s, channels %s", iface, ",".join(chan_label(f) for f in plan[iface]))
        return len(self.sensors)

    # ---------------------------------------------------------------- change while running
    def apply(self, override, rev):
        """Switch to new settings. Raises ValueError, changing nothing, if they are not valid."""
        override = clean_override(override) if override else None
        eff = effective(self.cfg, override)
        with self.lock:
            self.override, self.rev = override, rev
        if not self.sensors:  # nothing to retune here (a server without adapters): keep the settings, leave the host alone
            return
        if eff["regdomain"] and eff["regdomain"] != self.regdomain:
            threading.Thread(target=self._apply_after_regdomain, args=(eff, rev), daemon=True,
                             name="channels-regdomain").start()  # the country takes ~2 s and changes what is tunable
        else:
            self._apply_plan(eff, rev)

    def _apply_after_regdomain(self, eff, rev):
        self._regulatory(eff)
        self._read_supported()
        if rev == self.rev:  # not superseded while we waited
            self._apply_plan(eff, rev)

    def _apply_plan(self, eff, rev):
        with self.lock:
            if not eff["regdomain"] or eff["regdomain"] == self.regdomain:
                self._regulatory(eff)  # refreshes the 6 GHz warning
            plan = self._plan(eff, log_it=True)
            for sensor in self.sensors:
                sensor.set_channels(plan[sensor.iface], eff["hop_interval"])
                status.update(sensor.name, chan_rev=rev, regdomain=eff["regdomain"] or None, warning=self.reg_warning,
                              **({"supported_bands": self._bands(sensor.iface)} if self._bands(sensor.iface) else {}))
                log.info("Wi-Fi sensor on %s: channels now %s", sensor.iface,
                         ",".join(chan_label(f) for f in plan[sensor.iface]))

    def apply_local(self, settings):
        """The server's own adapters, after the settings changed."""
        entry = (settings.get("local") or {}) if isinstance(settings, dict) else {}
        rev = entry.get("rev") or 0
        if rev != self.rev:
            try:
                self.apply({k: entry.get(k) for k in OVERRIDE_KEYS}, rev)
            except ValueError as e:
                log.warning("Ignoring the channel settings: %s", e)

    def apply_remote(self, conf):
        """A remote sensor, with the entry the server sent in its ingest response."""
        if not isinstance(conf, dict) or not isinstance(conf.get("rev"), int) or conf["rev"] == self.rev:
            return
        if conf["rev"] == self._rejected_rev:
            return
        try:
            self.apply({k: conf.get(k) for k in OVERRIDE_KEYS}, conf["rev"])
            log.info("Channel settings from the server applied (revision %d)", conf["rev"])
        except ValueError as e:
            self._rejected_rev = conf["rev"]
            log.warning("Ignoring channel settings from the server (revision %d): %s", conf["rev"], e)


def attach(ctx):
    """The server's own Wi-Fi control, started from the saved channel settings and kept in step with later changes."""
    entry = ctx.settings.get("channels")["local"] or {}
    ctx.wifi = WifiControl(ctx.cfg, ctx.store, handshake=ctx.handshake, rev=entry.get("rev") or 0,
                           override={k: entry.get(k) for k in OVERRIDE_KEYS} if entry else None)
    ctx.settings.on_change(lambda k: ctx.wifi.apply_local(ctx.settings.get("channels")) if k == "channels" else None)
    return ctx.wifi


# ------------------------------------------------------------------ API
class ChannelConfig(BaseModel):
    channels: Optional[str] = Field(None, max_length=200)             # None / "" = the sensor's own WIFI_CHANNELS
    per_iface: Dict[str, Optional[str]] = Field(default_factory=dict, max_length=8)
    regdomain: Optional[str] = Field(None, max_length=2)
    hop_interval: Optional[float] = None


def routes(ctx):
    r = APIRouter()

    def entries():
        return ctx.settings.get("channels")

    def target_entry(cfg_all, target):
        return (cfg_all["local"] if target == "local" else cfg_all["sensors"].get(target)) or None

    def adapters(target):
        out = []
        for s in status.snapshot():
            if s.get("type") != "wifi":
                continue
            if (target == "local") != (s.get("remote") is None):
                continue
            if target != "local" and s.get("remote") != target:
                continue
            out.append({k: s.get(k) for k in ("iface", "name", "state", "error", "channel", "channels", "bands",
                                              "supported_bands", "chan_rev", "regdomain", "warning", "pps")})
        return sorted(out, key=lambda a: a["iface"] or "")

    def describe(target, name, online):
        entry = target_entry(entries(), target)
        ads = adapters(target)
        rev = (entry or {}).get("rev") or 0
        return {"id": target, "name": name, "online": online,
                "config": ({k: entry.get(k) for k in ("rev",) + OVERRIDE_KEYS} if entry else None),
                "adapters": ads,
                "applied": bool(ads) and all(a.get("chan_rev") == rev for a in ads) if online else None,
                # a remote sensor that is online but doesn't report which revision it runs is on an older version
                "too_old": target != "local" and online and bool(ads) and any("chan_rev" not in a or a["chan_rev"] is None for a in ads),
                "env_channels": [chan_label(f) for f in ctx.cfg.wifi_channels] if target == "local" else None}

    def warnings_for(target, override):
        ads = adapters(target)
        if not ads or not all(a.get("supported_bands") for a in ads):
            return []
        able = {b for a in ads for b in a["supported_bands"]}
        freqs = parse_channels(override["channels"]) if override.get("channels") else []
        for spec in (override.get("per_iface") or {}).values():
            if spec:
                freqs += parse_channels(spec)
        return [f"No adapter on this sensor can tune {b} GHz" for b in sorted({band_of(f) for f in freqs} - able)]

    @r.get("/api/channel-settings")
    def get_channels(_=Depends(require_admin)):
        now = time.time()
        out = [describe("local", "This server", True)]
        for s in ctx.rows("SELECT id, name, last_seen FROM sensors WHERE id != 'local' ORDER BY name"):
            out.append(describe(s["id"], s["name"], (s["last_seen"] or 0) > now - 60))
        return {"targets": out}

    def _check_target(target):
        if target != "local" and not ctx.one("SELECT 1 FROM sensors WHERE id=?", (target,)):
            raise HTTPException(404, "No such sensor")

    def _store(target, override):
        cfg_all = entries()
        old = target_entry(cfg_all, target) or {}
        override = clean_override(override)
        new = {"rev": (old.get("rev") or 0) + 1, **{k: override[k] for k in OVERRIDE_KEYS}}
        if target == "local":
            cfg_all["local"] = new
        else:
            cfg_all["sensors"][target] = new
        ctx.settings.set("channels", cfg_all)  # on_change applies it to this server's adapters
        return new

    @r.put("/api/channel-settings/{target}")
    def put_channels(target: str, body: ChannelConfig, _=Depends(require_admin)):
        _check_target(target)
        try:
            override = clean_override(body.model_dump())
        except ValueError as e:
            raise HTTPException(400, str(e))
        return {"ok": True, "config": _store(target, override), "warnings": warnings_for(target, override)}

    @r.delete("/api/channel-settings/{target}")
    def reset_channels(target: str, _=Depends(require_admin)):
        """Back to the sensor's own settings (its environment)."""
        _check_target(target)
        return {"ok": True, "config": _store(target, {})}

    return r
