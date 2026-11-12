"""What hardware a sensor interface is: driver, bus, USB IDs, maker and product, link speed. Read from sysfs once, when the
interface is set up, and carried in its status entry (so a remote sensor reports its own, like the rest of its status).

Every field is optional: a built-in adapter has no USB IDs, a virtual one has no driver, and inside some containers sysfs is
incomplete. Nothing here touches the device itself.
"""
import os

SYSFS = "/sys"  # tests point this at a fake tree


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip() or None
    except (OSError, UnicodeDecodeError):
        return None


def _usb(device):
    """USB details of the device a sysfs node belongs to: the first parent directory that has idVendor."""
    p = device
    while p and p not in ("/", SYSFS):
        vid = _read(os.path.join(p, "idVendor"))
        if vid:
            pid = _read(os.path.join(p, "idProduct")) or "????"
            speed = _read(os.path.join(p, "speed"))
            return {"hw_usb": f"{vid}:{pid}", "hw_maker": _read(os.path.join(p, "manufacturer")),
                    "hw_product": _read(os.path.join(p, "product")),
                    "hw_speed": f"{speed} Mbps" if speed and speed.replace(".", "").isdigit() else None}
        p = os.path.dirname(p)
    return {}


def _device(node):
    """Driver, bus and (for USB) IDs of the device behind a class node such as /sys/class/net/wlan1."""
    dev = os.path.join(node, "device")
    if not os.path.exists(dev):
        return {}
    real = os.path.realpath(dev)
    out = {"hw_driver": os.path.basename(os.path.realpath(os.path.join(real, "driver"))) if os.path.exists(os.path.join(real, "driver")) else None,
           "hw_bus": os.path.basename(os.path.realpath(os.path.join(real, "subsystem"))) if os.path.exists(os.path.join(real, "subsystem")) else None}
    if out["hw_bus"] in ("usb", None) or "/usb" in real:
        out.update(_usb(real))
        out["hw_bus"] = "usb" if out.get("hw_usb") else out["hw_bus"]
    return out


def _clean(d):
    return {k: v for k, v in d.items() if v}


def net(iface):
    """A Wi-Fi or wired interface."""
    node = os.path.join(SYSFS, "class", "net", iface)
    if not os.path.isdir(node):
        return {}
    out = _device(node)
    out["hw_phy"] = _read(os.path.join(node, "phy80211", "name"))
    speed = _read(os.path.join(node, "speed"))  # wired link speed; -1 or unreadable while the link is down
    if speed and speed.isdigit() and int(speed) > 0:
        out["hw_link"] = f"{int(speed)} Mbps" if int(speed) < 1000 else f"{int(speed) / 1000:g} Gbps"
    return _clean(out)


def bluetooth(dev):
    """A Bluetooth adapter, by name (hci0) or number."""
    name = dev if str(dev).startswith("hci") else f"hci{dev}"
    node = os.path.join(SYSFS, "class", "bluetooth", name)
    return _clean(_device(node)) if os.path.isdir(node) else {}


def serial(path):
    """A serial stick (Zigbee, LoRa), by its device path; a /dev/serial/by-id link is followed to the ttyUSB / ttyACM it names."""
    tty = os.path.basename(os.path.realpath(path))
    node = os.path.join(SYSFS, "class", "tty", tty)
    return _clean(_device(node)) if os.path.isdir(node) else {}
