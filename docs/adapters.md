[← Back to the README](../README.md)

# Connecting USB Wi-Fi / Bluetooth adapters

The container uses `network_mode: host` + `privileged: true`, so it sees the same network interfaces and HCI devices as the host. **What you need is for the adapter to be visible on the host (or VM) that runs Docker.**

## 1. Plug in and identify the adapter (bare metal / Raspberry Pi)

```bash
lsusb                       # the adapter should appear, e.g. "MediaTek Inc. Wireless_Device"
iw dev                      # lists wireless interfaces, e.g. wlan1 / wlx00c0ca123456
ip -br link                 # same, short form
hciconfig -a  # or: bluetoothctl list   -> hci0, hci1 ...
sudo dmesg | tail -n 30     # driver / firmware messages if nothing shows up
```

Check that the driver supports monitor mode:

```bash
iw phy "$(cat /sys/class/net/wlan1/phy80211/name)" info | grep -A8 "Supported interface modes"
# must list:  * monitor
```

An adapter that stopped capturing can be reset from the web interface: admins see a **Reset…** button per interface in the overview's *Sensors* panel (also for remote sensors, which do it with their next upload). Wi-Fi is brought down and up again, Bluetooth gets an HCI reset, Zigbee and LoRa sticks are reconnected, and *Also reset the USB device* does what unplugging and replugging would (needs the container to see `/dev/bus/usb`, which `privileged` does).

If the interface is missing, the adapter usually needs firmware. On Debian/Ubuntu/Raspberry Pi OS install `firmware-misc-nonfree` (MediaTek), `firmware-atheros` or `firmware-realtek`. On Arch install `linux-firmware`. Then replug the adapter.

## 2. Keep NetworkManager / wpa_supplicant away from it

If NetworkManager manages the adapter, it will keep switching it back to managed mode. Mark it unmanaged:

```bash
# one-off
sudo nmcli device set wlan1 managed no

# permanent: /etc/NetworkManager/conf.d/99-sniffowireless.conf
[keyfile]
unmanaged-devices=interface-name:wlan1;mac:00:c0:ca:12:34:56
```

then run `sudo systemctl reload NetworkManager`. If you use plain `wpa_supplicant`/`dhcpcd`, exclude the interface there (`denyinterfaces wlan1` in `/etc/dhcpcd.conf` on Raspberry Pi OS).

## 3. Give it a stable name (recommended)

USB adapters can be renamed between boots (`wlan1` ↔ `wlan2`, or `wlx…`). Pin a name with a udev rule. Use the adapter's MAC from `ip link`:

```bash
# /etc/udev/rules.d/70-sniffowireless-wifi.rules
SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="00:c0:ca:12:34:56", NAME="wlmon0"
```

Run `sudo udevadm control --reload && sudo udevadm trigger` (or replug) and set `WIFI_INTERFACES=wlmon0`.

## 4. Unblock radios

```bash
rfkill list
sudo rfkill unblock wifi
sudo rfkill unblock bluetooth
```

sniffowireless switches the interface to monitor mode itself (`WIFI_SET_MONITOR=1`, default). If the driver refuses, it falls back to adding a `<iface>mon` virtual monitor interface. To do it manually instead:

```bash
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
```

## Bluetooth 5 and 6 adapters

At start the sensor asks each adapter which Bluetooth version it implements (shown in the overview's *Sensors* panel, for example *Bluetooth 6.0 (Intel)*) and which LE features it has (2M PHY, Coded PHY, extended and periodic advertising, LE Audio, Channel Sounding). What that changes:

- **Extended scanning.** A Bluetooth 5 or newer adapter is scanned with the extended LE commands, which is the only way to see extended advertisements: newer phones, trackers, and **LE Audio broadcasts (Auracast)**. With the Coded PHY (long range) in the feature list, that is scanned as well. An adapter without extended advertising (Bluetooth 4.x) still works, with a warning in the Sensors panel that Bluetooth 5/6 advertisements are invisible to it. `BT_EXTENDED_SCAN=0` goes back to the legacy commands; if a controller refuses a mode, the sensor falls back by itself.
- **New advertisement types.** The device page shows LE Audio broadcasts (the broadcast name, ID, whether it is encrypted and its quality), electronic shelf labels, encrypted advertising data (Bluetooth 5.4) and the radio (PHY) a device advertised on. A broadcast's name is used as the device name when it has none.
- **Peer versions.** For a device connected to the host's own Bluetooth stack, the Bluetooth version and chip maker it reports are shown on its device page.
- **Bluetooth version of every device.** The Devices page has a *Bluetooth* column, the device page a *Bluetooth version* row, and Statistics a *Bluetooth version* breakdown you can click through to the devices (filter `bt_ver`). A version is **exact** (`5.4`, green) only when the device is connected to the host's stack and reported it. Otherwise it is **at least** (`5.2+`), from the strongest feature the device advertises, since a feature exists only from a given version on: extended advertising `5.0+`, an LE Audio broadcast `5.2+`, encrypted advertising data or Electronic Shelf Labels `5.4+`, and plain LE advertising `4.0+`. Classic (BR/EDR) devices stay unknown until something connects to them. A passive scanner cannot read a version that nothing transmits, so most devices show `4.0+`. Devices stored before this feature are filled in once at the first start.

What a passive scanner cannot see: the headline Bluetooth 6.0 features (Channel Sounding distance measurement, connection subrating, monitoring advertisers) are exchanged inside connections or are not part of advertisements, so a device using them looks like any other device. The adapter listing tells you whether the *adapter* supports them, not whether the devices around it do.

## Bluetooth and the host's `bluetoothd`

sniffowireless talks to the adapter over a raw HCI socket. It can run **alongside** the host's BlueZ daemon. It enables LE scanning and periodic inquiry and listens to all controller events, so devices the host connects to (headphones, keyboards) show up as Bluetooth connections. If you want sniffowireless to have the adapter to itself (best results on a dedicated dongle), stop BlueZ from using it: `sudo systemctl disable --now bluetooth`. Alternatively, give sniffowireless a second dongle (`BT_DEVICES=hci1`).

## Virtual machines and other platforms

| Platform | How to connect the USB adapter |
|---|---|
| **Proxmox VM** | VM → Hardware → Add → **USB Device** → *Use USB Vendor/Device ID* (survives replugging). Use a USB 3 controller (`qemu-xhci`) for MT7921AU/MT7612U. Then follow the bare-metal steps inside the VM. |
| **Proxmox LXC** | Possible but fiddly: the wireless phy has to be moved into the container's netns (`iw phy phyX set netns <pid>`) and HCI sockets only work in the initial netns. A VM is strongly recommended. |
| **VMware / VirtualBox** | Install the Extension Pack (VirtualBox) and add a USB device filter for the adapter. Disconnect the adapter from the host OS so the guest gets it. |
| **Unraid / TrueNAS SCALE** | Run the compose file on the host (or in a VM with USB passthrough). Make sure the host kernel ships the driver for your chipset. |
| **Raspberry Pi 4/5** | Works well (arm64 image builds natively). The onboard Wi-Fi (`brcmfmac`) has no reliable monitor mode, so use a USB adapter. Onboard Bluetooth (`hci0`) works. Use a powered hub for high-current adapters. |
| **Windows (WSL2)** | Install [usbipd-win](https://github.com/dorssel/usbipd-win), then `usbipd list`, `usbipd bind --busid <id>`, `usbipd attach --wsl --busid <id>`. The stock WSL kernel lacks most Wi-Fi drivers, so you need a custom kernel. A Linux VM or a Pi is far easier. |
| **Docker Desktop (macOS / Windows)** | Not supported: containers run inside a VM with no access to USB radios or host network namespaces. |
