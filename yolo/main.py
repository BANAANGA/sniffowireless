import logging
import threading
import time

import uvicorn

from .config import Config
from .oui import VendorLookup
from .store import Store
from .web import create_app

log = logging.getLogger("yolo")


def main():
    cfg = Config.from_env()
    logging.basicConfig(level=cfg.log_level, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    vendors = VendorLookup(cfg.manuf_path)
    store = Store(cfg, vendors)
    stop = threading.Event()
    sensors = 0

    if cfg.demo:
        from .demo import DemoGenerator
        demo = DemoGenerator(cfg, store)
        demo.backfill(cfg.demo_backfill_hours)
        threading.Thread(target=demo.run, args=(stop,), daemon=True, name="demo").start()
        log.info("Demo mode enabled: generating synthetic devices")

    if cfg.wifi_interfaces:
        from .config import chan_label
        from .wifi import WifiSensor, assign_channels, set_regdomain, supported_freqs
        if cfg.wifi_regdomain:
            set_regdomain(cfg.wifi_regdomain)
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
        for iface in cfg.wifi_interfaces:
            chans = cfg.wifi_channels_per_iface.get(iface) or plan.get(iface) or cfg.wifi_channels
            WifiSensor(iface, chans, cfg, store).start(stop)
            log.info("Wi-Fi sensor on %s, channels %s", iface, ",".join(chan_label(f) for f in chans))
            sensors += 1

    if cfg.bt_devices:
        from .bluetooth import BluetoothSensor
        for dev in cfg.bt_devices:
            BluetoothSensor(dev, cfg, store).start(stop)
            log.info("Bluetooth sensor on %s", dev)
            sensors += 1

    if not sensors and not cfg.demo:
        log.warning("No sensors configured: set WIFI_INTERFACES and/or BT_DEVICES (or DEMO_MODE=1)")

    writer = threading.Thread(target=store.run, args=(stop,), name="store")
    writer.start()
    try:
        uvicorn.run(create_app(cfg, store), host=cfg.web_host, port=cfg.web_port, log_level="warning")
    finally:
        log.info("Shutting down")
        stop.set()
        writer.join(timeout=15)
        time.sleep(0.1)


if __name__ == "__main__":
    main()
