"""Reset a capture adapter from the web interface: for an adapter that stopped capturing (a Wi-Fi interface that went down, a
Bluetooth dongle that stopped answering, a USB serial stick that hung). What it does depends on the kind:

  Wi-Fi       the interface is brought down and up again; the capture loop then sets monitor mode again by itself
  Bluetooth   the HCI device is taken down, reset and brought up (the same ioctls hciconfig uses)
  Zigbee/LoRa the serial link is closed and the stick opened again (the firmware's handshake runs again)
  + USB       optionally the USB device is reset as well, like unplugging and replugging it (needs the container to see
              /dev/bus/usb: it does when it runs privileged)

For a remote sensor the server keeps the request until the sensor's next upload and hands it over in the reply."""
import fcntl
import logging
import os
import re
import socket
import threading
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from . import status
from .auth import require_admin

log = logging.getLogger("sniffowireless.adapters")

REGISTRY = {}                 # status name -> sensor object with reset(usb) (serial sticks), filled by the sensors themselves
USBDEVFS_RESET = 0x5514
HCIDEVUP, HCIDEVDOWN, HCIDEVRESET = 0x400448C9, 0x400448CA, 0x400448CB
NAME_RX = re.compile(r"^(wifi|bt|zigbee|lora):[\w./:@+-]{1,100}$")
PENDING = {}                  # remote sensor id -> requests waiting for its next upload
_lock = threading.Lock()


def usb_device_dir(sys_path):
    """The USB device (not interface) directory a sysfs entry belongs to: the first parent with busnum and devnum."""
    p = os.path.realpath(sys_path)
    while p and p != "/":
        if os.path.exists(os.path.join(p, "busnum")) and os.path.exists(os.path.join(p, "devnum")):
            return p
        p = os.path.dirname(p)
    return None


def usb_reset(sys_path):
    """Reset the USB device behind a sysfs path. Returns a sentence about what happened."""
    d = usb_device_dir(sys_path)
    if not d:
        return "not a USB device: nothing to reset on the USB bus"
    bus, dev = int(open(os.path.join(d, "busnum")).read()), int(open(os.path.join(d, "devnum")).read())
    node = f"/dev/bus/usb/{bus:03d}/{dev:03d}"
    try:
        fd = os.open(node, os.O_WRONLY)
    except OSError as e:
        return f"could not open {node} ({e.strerror}): is the container privileged?"
    try:
        fcntl.ioctl(fd, USBDEVFS_RESET, 0)
    except OSError as e:
        return f"the USB reset of {node} failed ({e.strerror})"
    finally:
        os.close(fd)
    return f"USB device {os.path.basename(d)} reset"


def _wait_for(path, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if os.path.exists(path):
            return True
        time.sleep(0.5)
    return os.path.exists(path)


def reset_wifi(entry, usb):
    from .wifi import run_cmd
    iface = entry.get("iface") or entry["name"].split(":", 1)[1]
    steps = []
    for n in {entry.get("mon"), iface} - {None}:
        rc, out = run_cmd("ip", "link", "set", n, "down")
        steps.append(f"{n} down" if rc == 0 else f"{n} down failed ({out or 'ip link'})")
    if usb:
        steps.append(usb_reset(f"/sys/class/net/{iface}/device"))
        if not _wait_for(f"/sys/class/net/{iface}", 15):
            steps.append(f"{iface} did not come back within 15 s")
    rc, out = run_cmd("ip", "link", "set", iface, "up")
    steps.append(f"{iface} up" if rc == 0 else f"{iface} up failed ({out or 'ip link'})")
    return steps + ["monitor mode is set again by the capture loop"]


def reset_bluetooth(entry, usb):
    dev = entry.get("iface") or entry["name"].split(":", 1)[1]
    m = re.fullmatch(r"hci(\d+)", dev)
    if not m:
        raise ValueError(f"{dev} is not an HCI device")
    dev_id, steps = int(m.group(1)), []
    s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    try:
        for label, req in (("down", HCIDEVDOWN), ("reset", HCIDEVRESET)):
            try:
                fcntl.ioctl(s.fileno(), req, dev_id)
                steps.append(f"{dev} {label}")
            except OSError as e:
                steps.append(f"{dev} {label} failed ({e.strerror})")
        if usb:
            steps.append(usb_reset(f"/sys/class/bluetooth/{dev}/device"))
            _wait_for(f"/sys/class/bluetooth/{dev}", 15)
        try:
            fcntl.ioctl(s.fileno(), HCIDEVUP, dev_id)
            steps.append(f"{dev} up")
        except OSError as e:
            steps.append(f"{dev} up failed ({e.strerror})")
    finally:
        s.close()
    return steps


def reset_serial(entry, usb):
    sensor = REGISTRY.get(entry["name"])
    if sensor is None:
        raise ValueError(f"{entry['name']} cannot be reset from here")
    return sensor.reset(usb)


def reset(name, usb=False):
    """Reset a local interface by its status name; returns what was done. Raises ValueError for what is not possible."""
    if not NAME_RX.match(name or ""):
        raise ValueError("Unknown interface")
    entry = status.SENSORS.get(name)
    if not entry or entry.get("remote"):
        raise ValueError("Unknown interface")
    kind = name.split(":", 1)[0]
    steps = {"wifi": reset_wifi, "bt": reset_bluetooth, "zigbee": reset_serial, "lora": reset_serial}[kind](entry, bool(usb))
    log.info("Reset %s (usb=%s): %s", name, bool(usb), "; ".join(steps))
    status.update(name, note=f"Reset at {time.strftime('%H:%M')}: {steps[-1] if steps else 'done'}")
    return steps


# ------------------------------------------------------------------ remote sensors
def queue(sid, name, usb):
    with _lock:
        q = PENDING.setdefault(sid, [])
        q[:] = [c for c in q if c["name"] != name][-9:] + [{"action": "reset", "name": name, "usb": bool(usb), "at": time.time()}]


def take(sid):
    """The requests waiting for this sensor (handed over once, and only fresh ones)."""
    with _lock:
        cmds = [c for c in PENDING.pop(sid, []) if time.time() - c["at"] < 600]
    return [{k: v for k, v in c.items() if k != "at"} for c in cmds]


def run_commands(cmds):
    """On the sensor: carry out what the server asked for, in a thread (a USB reset can take several seconds)."""
    def work():
        for c in cmds[:10]:
            if not isinstance(c, dict) or c.get("action") != "reset" or not isinstance(c.get("name"), str):
                continue
            try:
                reset(c["name"], c.get("usb") is True)
            except Exception as e:
                log.warning("Reset of %s failed: %s", c.get("name"), e)
                status.update(c["name"], note=f"Reset failed: {e}") if c["name"] in status.SENSORS else None
    threading.Thread(target=work, daemon=True, name="adapter-reset").start()


class ResetBody(BaseModel):
    sensor: str = Field("local", max_length=64)   # "local" or a remote sensor's id
    name: str = Field(max_length=120)             # the interface, as the sensor itself names it: wifi:wlan1, bt:hci0, ...
    usb: bool = False


def routes(ctx):
    r = APIRouter()

    @r.post("/api/adapters/reset")
    def reset_adapter(body: ResetBody, _=Depends(require_admin)):
        if not NAME_RX.match(body.name):
            raise HTTPException(400, "Unknown interface")
        if body.sensor == "local":
            try:
                steps = reset(body.name, body.usb)
            except ValueError as e:
                raise HTTPException(400, str(e))
            return {"done": True, "steps": steps}
        if f"{body.sensor}/{body.name}" not in status.SENSORS:
            raise HTTPException(404, "That sensor does not report such an interface")
        queue(body.sensor, body.name, body.usb)
        return {"done": False, "queued": True}

    return r
