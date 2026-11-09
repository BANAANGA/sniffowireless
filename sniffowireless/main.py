import logging
import os
import threading
import time

from .config import Config
from .oui import VendorLookup

log = logging.getLogger("sniffowireless")


def start_sensors(cfg, sink, stop, handshake=None, wifi=None, lora=None, zigbee=None):
    """Start Wi-Fi / Bluetooth capture; `sink` is the Store (server) or a Forwarder (remote sensor).

    `handshake` (a HandshakeCapture) is only passed in server mode, where admin settings are reachable;
    a remote sensor process (SNIFFOWIRELESS_MODE=sensor) only forwards observations, so it can't honour capture
    settings and doesn't offer this feature.
    `wifi` is the WifiControl that owns the Wi-Fi adapters, so channel settings can be changed while they run.
    """
    n = 0
    if cfg.wifi_interfaces:
        from .channels import WifiControl
        n += (wifi or WifiControl(cfg, sink, handshake)).start(stop)
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
    if cfg.zigbee_devices:
        from .zigbee import ZigbeeControl, ZigbeeSensor
        zigbee = zigbee or ZigbeeControl(cfg)
        for dev in cfg.zigbee_devices:
            ZigbeeSensor(dev, cfg, sink, control=zigbee).start(stop)
            log.info("Zigbee sensor on %s, channels %s", dev, ",".join(str(c) for c in zigbee.effective()["channels"]))
            n += 1
    if cfg.lora_devices:
        from .lora import LoraControl, LoraSensor
        lora = lora or LoraControl(cfg)
        for dev in cfg.lora_devices:
            LoraSensor(dev, cfg, sink, control=lora).start(stop)
            log.info("LoRa sensor on %s, profiles %s", dev, ", ".join(p.name for p in lora.effective()[0]))
            n += 1
    return n


def run_sensor(cfg):
    """SNIFFOWIRELESS_MODE=sensor: capture only and forward everything to the central server."""
    from .sensors import Forwarder
    from .channels import WifiControl
    stop = threading.Event()
    fwd = Forwarder(cfg)
    wifi = WifiControl(cfg, fwd)
    fwd.on_channel_config = wifi.apply_remote  # channel settings the admin sets in the server's web UI
    from .lora import LoraControl
    lora = LoraControl(cfg)
    fwd.on_lora_config = lora.apply_remote     # the LoRa profiles the same way
    from .zigbee import ZigbeeControl
    zigbee = ZigbeeControl(cfg)
    fwd.on_zigbee_config = zigbee.apply_remote  # and the Zigbee channels
    if not start_sensors(cfg, fwd, stop, wifi=wifi, lora=lora, zigbee=zigbee):
        raise SystemExit("Sensor mode needs WIFI_INTERFACES, ETH_INTERFACES, BT_DEVICES, ZIGBEE_DEVICES and/or LORA_DEVICES")
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
    from .store import Store, connect, set_db_cache
    from .survey import SurveyCollector
    from .lora import LoraMonitor
    from .zigbee import ZigbeeMonitor

    os.makedirs(cfg.data_dir, exist_ok=True)
    apply_staged_restore(cfg)  # a full restore staged from the UI is applied before the database is opened
    store = Store(cfg, VendorLookup(cfg.manuf_path))
    ctx = Ctx(cfg, store, Settings(lambda: connect(cfg.db_path)))
    set_db_cache(ctx.settings.get("performance")["db_cache"])
    store.retune()
    ctx.settings.on_change(lambda k: (set_db_cache(ctx.settings.get("performance")["db_cache"]), store.retune())
                           if k == "performance" else None)
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
    ctx.zigbee = ZigbeeMonitor(ctx)
    ctx.lora = LoraMonitor(ctx)
    from .radiowatch import RadioWatch
    ctx.radiowatch = RadioWatch(ctx)
    store.hooks += [ctx.security, ctx.survey, ctx.location, ctx.lan, ctx.interference, ctx.trackers, ctx.investigate, ctx.dfs,
                    ctx.zigbee, ctx.lora, ctx.radiowatch]
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
    from .channels import attach
    from .lora import attach as attach_lora
    from .zigbee import attach as attach_zigbee
    if not start_sensors(cfg, store, stop, handshake=ctx.handshake, wifi=attach(ctx), lora=attach_lora(ctx), zigbee=attach_zigbee(ctx)) and not cfg.demo:
        log.warning("No local sensors configured: set WIFI_INTERFACES, ETH_INTERFACES, BT_DEVICES, ZIGBEE_DEVICES and/or LORA_DEVICES, add remote sensors in "
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
