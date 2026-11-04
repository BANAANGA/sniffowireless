import logging
import os
import threading
import time

from .config import Config
from .oui import VendorLookup

log = logging.getLogger("sniffowireless")


def start_sensors(cfg, sink, stop, handshake=None):
    """Start Wi-Fi / Bluetooth capture; `sink` is the Store (server) or a Forwarder (remote sensor).

    `handshake` (a HandshakeCapture) is only passed in server mode, where admin settings are reachable;
    a remote sensor process (SNIFFOWIRELESS_MODE=sensor) only forwards observations, so it can't honour capture
    settings and doesn't offer this feature.
    """
    n = 0
    if cfg.wifi_interfaces:
        from .config import band_of, chan_label
        from . import status
        from .wifi import (WifiSensor, assign_channels, global_regdomain, regulatory_warning, set_regdomain,
                           supported_freqs)
        if cfg.wifi_regdomain:
            set_regdomain(cfg.wifi_regdomain)
            time.sleep(2)  # the kernel applies a new regulatory domain asynchronously
        want6 = any(band_of(f) == "6" for f in cfg.wifi_channels) or \
            any(band_of(f) == "6" for chans in cfg.wifi_channels_per_iface.values() for f in chans)
        reg_warning = regulatory_warning(global_regdomain(), cfg.wifi_regdomain, want6)
        if reg_warning:
            log.warning(reg_warning)
        # Split the channel list between adapters (unless given per interface), only handing
        # each channel to adapters whose hardware/regulatory domain allows it.
        auto = [i for i in cfg.wifi_interfaces if i not in cfg.wifi_channels_per_iface]
        supported = {i: supported_freqs(i) for i in auto}
        plan = assign_channels(cfg.wifi_channels, auto, supported)
        for iface in auto:
            if supported[iface] is not None:
                missing = [chan_label(f) for f in cfg.wifi_channels if f not in supported[iface]]
                if missing:
                    log.info("%s cannot tune %d configured channels (%s...)", iface, len(missing),
                             ",".join(missing[:6]))
                six = [f for f in cfg.wifi_channels if band_of(f) == "6"]
                if six and not any(f in supported[iface] for f in six):
                    log.warning("%s: none of the %d configured 6 GHz channels is usable: the adapter has no 6 GHz "
                                "support or the regulatory domain disables it (set WIFI_REGDOMAIN; check "
                                "'iw reg get' and 'iw phy' on the host)", iface, len(six))
        for iface in cfg.wifi_interfaces:
            chans = cfg.wifi_channels_per_iface.get(iface) or plan.get(iface) or cfg.wifi_channels
            sensor = WifiSensor(iface, chans, cfg, sink, handshake=handshake)
            if reg_warning:
                status.update(sensor.name, warning=reg_warning)
            sensor.start(stop)
            log.info("Wi-Fi sensor on %s, channels %s", iface, ",".join(chan_label(f) for f in chans))
            n += 1
    if cfg.eth_interfaces:
        from .ethernet import EthernetSensor
        for iface in cfg.eth_interfaces:
            EthernetSensor(iface, cfg, sink).start(stop)
            log.info("Ethernet sensor on %s (promiscuous=%s)", iface, cfg.eth_promisc)
            n += 1
    if cfg.bt_devices:
        from .bluetooth import BluetoothSensor
        for dev in cfg.bt_devices:
            BluetoothSensor(dev, cfg, sink).start(stop)
            log.info("Bluetooth sensor on %s", dev)
            n += 1
    return n


def run_sensor(cfg):
    """SNIFFOWIRELESS_MODE=sensor: capture only and forward everything to the central server."""
    from .sensors import Forwarder
    stop = threading.Event()
    fwd = Forwarder(cfg)
    if not start_sensors(cfg, fwd, stop):
        raise SystemExit("Sensor mode needs WIFI_INTERFACES, ETH_INTERFACES and/or BT_DEVICES")
    log.info("Remote sensor forwarding to %s", cfg.server_url)
    try:
        fwd.run(stop)
    except KeyboardInterrupt:
        stop.set()


def build(cfg):
    """Create the store, plugins and shared context for server mode."""
    from .alerts import AlertEngine
    from .auth import Auth
    from .backup import BackupScheduler, apply_staged_restore
    from .dfs import DfsMonitor
    from .handshake import HandshakeCapture
    from .interference import InterferenceDetector
    from .investigate import InvestigationMonitor
    from .trackers import TrackerMonitor
    from .context import Ctx
    from .lan import LanMonitor
    from .manage import apply_ignore, apply_meta
    from .mqtt import MqttPublisher
    from .reports import ReportScheduler
    from .security import SecurityMonitor
    from .sensors import LocationTracker
    from .settings import Settings
    from .store import Store, connect
    from .survey import SurveyCollector

    os.makedirs(cfg.data_dir, exist_ok=True)
    apply_staged_restore(cfg)  # a full restore staged from the UI is applied before the database is opened
    store = Store(cfg, VendorLookup(cfg.manuf_path))
    ctx = Ctx(cfg, store, Settings(lambda: connect(cfg.db_path)))
    ctx.auth = Auth(cfg, ctx.wdb)
    ctx.alerts = AlertEngine(ctx)
    ctx.security = SecurityMonitor(ctx)
    ctx.survey = SurveyCollector(ctx)
    ctx.location = LocationTracker(ctx)
    ctx.reports = ReportScheduler(ctx)
    ctx.lan = LanMonitor(ctx)
    ctx.interference = InterferenceDetector(ctx)
    ctx.trackers = TrackerMonitor(ctx)
    ctx.backups = BackupScheduler(ctx)
    ctx.investigate = InvestigationMonitor(ctx)
    ctx.handshake = HandshakeCapture(ctx)
    ctx.mqtt = MqttPublisher(ctx)
    from .matching import SCHEMA as MATCHING_SCHEMA
    store.conn.executescript(MATCHING_SCHEMA)
    ctx.dfs = DfsMonitor(ctx)
    store.hooks += [ctx.security, ctx.survey, ctx.location, ctx.lan, ctx.interference, ctx.trackers, ctx.investigate, ctx.dfs]
    store.listeners += [ctx.alerts.on_events, ctx.mqtt.on_events]
    apply_ignore(ctx)
    apply_meta(ctx)
    return ctx


def main():
    cfg = Config.from_env()
    logging.basicConfig(level=cfg.log_level, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    from .logs import install as install_log_buffer
    install_log_buffer(cfg.log_level)  # keeps recent log lines for the live Logs page
    if cfg.mode == "sensor":
        return run_sensor(cfg)

    import uvicorn

    from .web import create_app

    ctx = build(cfg)
    store = ctx.store
    stop = threading.Event()
    ctx.alerts.start(stop)
    ctx.mqtt.start(stop)
    ctx.reports.start(stop)
    ctx.backups.start(stop)
    if cfg.demo:
        from .demo import DemoGenerator
        demo = DemoGenerator(cfg, store, ctx)
        demo.backfill(cfg.demo_backfill_hours)
        threading.Thread(target=demo.run, args=(stop,), daemon=True, name="demo").start()
        log.info("Demo mode enabled: generating synthetic devices")
    if not start_sensors(cfg, store, stop, handshake=ctx.handshake) and not cfg.demo:
        log.warning("No local sensors configured: set WIFI_INTERFACES, ETH_INTERFACES and/or BT_DEVICES, add remote sensors in "
                    "Settings → Sensors, or use DEMO_MODE=1")

    writer = threading.Thread(target=store.run, args=(stop,), name="store")
    writer.start()
    try:
        uvicorn.run(create_app(ctx), host=cfg.web_host, port=cfg.web_port, log_level="warning",
                    # X-Forwarded-For/-Proto are only believed from these addresses (else anyone could fake
                    # their IP to dodge login throttling)
                    proxy_headers=True, forwarded_allow_ips=cfg.trusted_proxies, server_header=False)
    finally:
        log.info("Shutting down")
        stop.set()
        writer.join(timeout=15)
        time.sleep(0.1)


if __name__ == "__main__":
    main()
