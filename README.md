# yolo

A self-hosted Wi-Fi and Bluetooth monitor that runs as a single Docker container. It works like a small Kismet, with one difference: it is built to track **how devices connect over time**. It records which Wi-Fi client was associated with which access point and when. It also records when phones, wearables and other Bluetooth devices come into and leave range. You can drill into all of it from a dark, minimal web UI.

- **Wi-Fi:** passive monitor-mode capture with channel hopping across 2.4 GHz and 5 GHz, on one or more USB adapters
- **Bluetooth:** BLE advertising plus Classic inquiry over a raw HCI socket. No BlueZ daemon is needed inside the container.
- **Connectivity history:** presence sessions ("visits") for every device, connection sessions for Wi-Fi client→AP links (including roaming between BSSIDs and deauths), and Bluetooth links to the sensor's adapter
- **Drill-down statistics:** overview → device type → device → sessions; SSID → APs → clients; vendor / channel / probed SSID → devices; per-device signal history, weekly presence heatmap, timeline, peers, events
- **Storage:** SQLite in a single volume, per-minute signal samples, configurable retention, CSV export, JSON API
- **Demo mode** so you can try the UI without any radios

---

## Contents

1. [How it works](#how-it-works)
2. [Hardware](#hardware)
3. [Connecting USB Wi-Fi / Bluetooth adapters](#connecting-usb-wi-fi--bluetooth-adapters)
4. [Deploy](#deploy)
5. [Configuration](#configuration)
6. [Using the UI](#using-the-ui)
7. [API](#api)
8. [Troubleshooting](#troubleshooting)
9. [Development](#development)
10. [Legal](#legal)

---

## How it works

```
 USB Wi-Fi (monitor mode) ──► scapy sniffer + channel hopper ─┐
                                                              ├─► queue ─► store (SQLite, WAL) ◄── FastAPI ◄── browser UI
 USB / onboard Bluetooth ───► raw HCI socket: LE scan + inquiry┘
```

| Concept | Meaning |
|---|---|
| **Device** | One MAC / Bluetooth address. Types: `ap`, `wifi_client`, `ble`, `bt_classic`. |
| **Visit (presence session)** | A continuous period in which a device was heard. It closes after `WIFI_SESSION_TIMEOUT` / `BT_SESSION_TIMEOUT` seconds of silence. |
| **Connection (assoc session)** | A Wi-Fi client exchanging data with or associating to a specific BSSID. It closes on deauth/disassoc, on timeout, or when the client roams to another BSSID. For Bluetooth it means an ACL/LE link to the sensor's own adapter. |
| **Samples** | Per-device, per-minute frame count and RSSI min/avg/max. These drive the signal charts, the timelines and the heatmaps. |
| **Events** | `new_device`, `arrived`, `left`, `connected`, `disconnected`, `roamed`, `new_probe`, `deauth_broadcast`. |

Modern phones use **randomized MAC addresses** for probe requests and BLE advertising, so one phone can show up as many short-lived entries. These are flagged `rand` in the UI and can be hidden with one click. Presence events for them are suppressed by default (`EVENTS_FOR_RANDOMIZED=0`). When a phone actually connects to a network it normally keeps a stable per-network address, so **connection history stays meaningful**.

---

## Hardware

### Wi-Fi adapters

You need an adapter whose Linux driver supports **monitor mode**. In-kernel drivers are the most reliable:

| Chipset | Bands | Driver | Notes |
|---|---|---|---|
| MediaTek **MT7921AU** (e.g. Alfa AWUS036AXML, Comfast CF-951AX) | 2.4/5/6 GHz | `mt7921u` (kernel ≥ 5.18) | Recommended |
| MediaTek **MT7612U** (Alfa AWUS036ACM, Netgear A6210) | 2.4/5 GHz | `mt76x2u` | Excellent, very stable |
| MediaTek **MT7610U** (Alfa AWUS036ACHM) | 2.4/5 GHz | `mt76x0u` | Good, 1×1 |
| Atheros **AR9271** (Alfa AWUS036NHA, TP-Link TL-WN722N **v1**) | 2.4 GHz | `ath9k_htc` | Classic choice, 2.4 GHz only |
| Ralink **RT5370 / RT3070** | 2.4 GHz | `rt2800usb` | Cheap and works |
| Realtek **RTL8812AU / RTL8814AU** (Alfa AWUS036ACH / ACS) | 2.4/5 GHz | out-of-tree `aircrack-ng/rtl8812au` | Works, but you build the driver on the host |

> **Don't use the adapter your host relies on for its own network.** Putting it in monitor mode disconnects it. Use a dedicated USB adapter. Two adapters (for example one locked to 2.4 GHz and one hopping 5 GHz) give much better coverage than one adapter that hops across everything.

### Bluetooth adapters

Any adapter the Linux kernel exposes as `hciX` works: an onboard controller, or a USB dongle such as CSR8510 A10, Realtek RTL8761B (BT 5.0) or Intel AX200/AX210 combo cards. For BLE range, a dongle with an external antenna helps a lot. Ubertooth / nRF sniffers are not supported. They capture differently.

---

## Connecting USB Wi-Fi / Bluetooth adapters

The container uses `network_mode: host` + `privileged: true`, so it sees the same network interfaces and HCI devices as the host. **What you need is for the adapter to be visible on the host (or VM) that runs Docker.**

### 1. Plug in and identify the adapter (bare metal / Raspberry Pi)

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

If the interface is missing, the adapter usually needs firmware. On Debian/Ubuntu/Raspberry Pi OS install `firmware-misc-nonfree` (MediaTek), `firmware-atheros` or `firmware-realtek`. On Arch install `linux-firmware`. Then replug the adapter.

### 2. Keep NetworkManager / wpa_supplicant away from it

If NetworkManager manages the adapter, it will keep switching it back to managed mode. Mark it unmanaged:

```bash
# one-off
sudo nmcli device set wlan1 managed no

# permanent: /etc/NetworkManager/conf.d/99-yolo.conf
[keyfile]
unmanaged-devices=interface-name:wlan1;mac:00:c0:ca:12:34:56
```

then run `sudo systemctl reload NetworkManager`. If you use plain `wpa_supplicant`/`dhcpcd`, exclude the interface there (`denyinterfaces wlan1` in `/etc/dhcpcd.conf` on Raspberry Pi OS).

### 3. Give it a stable name (recommended)

USB adapters can be renamed between boots (`wlan1` ↔ `wlan2`, or `wlx…`). Pin a name with a udev rule. Use the adapter's MAC from `ip link`:

```bash
# /etc/udev/rules.d/70-yolo-wifi.rules
SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="00:c0:ca:12:34:56", NAME="wlmon0"
```

Run `sudo udevadm control --reload && sudo udevadm trigger` (or replug) and set `WIFI_INTERFACES=wlmon0`.

### 4. Unblock radios

```bash
rfkill list
sudo rfkill unblock wifi
sudo rfkill unblock bluetooth
```

yolo switches the interface to monitor mode itself (`WIFI_SET_MONITOR=1`, default). If the driver refuses, it falls back to adding a `<iface>mon` virtual monitor interface. To do it manually instead:

```bash
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
```

### Bluetooth and the host's `bluetoothd`

yolo talks to the adapter over a raw HCI socket. It can run **alongside** the host's BlueZ daemon. It enables LE scanning and periodic inquiry and listens to all controller events, so devices the host connects to (headphones, keyboards) show up as Bluetooth connections. If you want yolo to have the adapter to itself (best results on a dedicated dongle), stop BlueZ from using it: `sudo systemctl disable --now bluetooth`. Alternatively, give yolo a second dongle (`BT_DEVICES=hci1`).

### Virtual machines and other platforms

| Platform | How to connect the USB adapter |
|---|---|
| **Proxmox VM** | VM → Hardware → Add → **USB Device** → *Use USB Vendor/Device ID* (survives replugging). Use a USB 3 controller (`qemu-xhci`) for MT7921AU/MT7612U. Then follow the bare-metal steps inside the VM. |
| **Proxmox LXC** | Possible but fiddly: the wireless phy has to be moved into the container's netns (`iw phy phyX set netns <pid>`) and HCI sockets only work in the initial netns. A VM is strongly recommended. |
| **VMware / VirtualBox** | Install the Extension Pack (VirtualBox) and add a USB device filter for the adapter. Disconnect the adapter from the host OS so the guest gets it. |
| **Unraid / TrueNAS SCALE** | Run the compose file on the host (or in a VM with USB passthrough). Make sure the host kernel ships the driver for your chipset. |
| **Raspberry Pi 4/5** | Works well (arm64 image builds natively). The onboard Wi-Fi (`brcmfmac`) has no reliable monitor mode, so use a USB adapter. Onboard Bluetooth (`hci0`) works. Use a powered hub for high-current adapters. |
| **Windows (WSL2)** | Install [usbipd-win](https://github.com/dorssel/usbipd-win), then `usbipd list`, `usbipd bind --busid <id>`, `usbipd attach --wsl --busid <id>`. The stock WSL kernel lacks most Wi-Fi drivers, so you need a custom kernel. A Linux VM or a Pi is far easier. |
| **Docker Desktop (macOS / Windows)** | Not supported: containers run inside a VM with no access to USB radios or host network namespaces. |

---

## Deploy

Requirements: Linux host, Docker Engine ≥ 20.10 with the compose plugin, and the adapters set up as above.

```bash
git clone https://github.com/BANAANGA/yolo.git
cd yolo
cp .env.example .env
$EDITOR .env          # set WIFI_INTERFACES and BT_DEVICES
docker compose up -d --build
docker compose logs -f
```

Open **http://<host>:8080**. Data is stored in `./data/yolo.db`. Back up that file to keep your history.

Try it without hardware:

```bash
DEMO_MODE=1 docker compose up -d --build
```

Demo mode backfills 72 h of synthetic history and keeps generating live data. For a clean real deployment afterwards, delete `./data/yolo.db`.

### Without compose

```bash
docker build -t yolo .
docker run -d --name yolo --restart unless-stopped \
  --network host --privileged \
  -v "$PWD/data:/data" \
  -e WIFI_INTERFACES=wlan1 -e BT_DEVICES=hci0 -e TZ=Europe/Amsterdam \
  yolo
```

### Less privilege

`privileged: true` is the simplest option that works. If you prefer, replace it with:

```yaml
    cap_add: [NET_ADMIN, NET_RAW]
    security_opt: ["seccomp=unconfined"]   # some Docker versions block AF_BLUETOOTH sockets
```

### Updating

```bash
git pull && docker compose up -d --build
```

The database schema is created and upgraded automatically.

---

## Configuration

All settings are environment variables (put them in `.env`).

| Variable | Default | Description |
|---|---|---|
| `WIFI_INTERFACES` | *(empty)* | Comma-separated Wi-Fi adapters to capture on, e.g. `wlan1,wlan2`. Empty disables Wi-Fi. |
| `WIFI_CHANNELS` | `default` | `default` (1–13 + 36–48 + 149–165), `all`, `2.4`, `5`, or a list/ranges like `1,6,11,36-48`. With several adapters the list is split between them. |
| `WIFI_CHANNELS_<iface>` | – | Per-adapter channel list, e.g. `WIFI_CHANNELS_wlan1=1,6,11`. A single channel locks the adapter (no hopping). |
| `WIFI_HOP_INTERVAL` | `0.5` | Seconds spent on each channel. |
| `WIFI_SET_MONITOR` | `1` | Put interfaces in monitor mode automatically. |
| `BT_DEVICES` | *(empty)* | Bluetooth adapters, e.g. `hci0`. Empty disables Bluetooth. |
| `BT_ACTIVE_SCAN` | `1` | Active LE scanning (sends scan requests, which gets device names). `0` is fully passive. |
| `BT_INQUIRY` | `1` | Periodic Bluetooth Classic inquiry (finds *discoverable* classic devices). |
| `BT_INQUIRY_INTERVAL` | `60` | Seconds between inquiries. |
| `BT_RESOLVE_NAMES` | `1` | Ask newly found classic devices for their name. |
| `WIFI_SESSION_TIMEOUT` | `300` | Seconds of silence before a Wi-Fi visit or connection is closed. |
| `BT_SESSION_TIMEOUT` | `180` | Same for Bluetooth. |
| `ACTIVE_WINDOW` | `300` | "Active now" window used by the overview cards. |
| `RETENTION_DAYS` | `30` | Samples, sessions, events and devices older than this are pruned hourly. |
| `EVENTS_FOR_RANDOMIZED` | `0` | Also log arrive/leave/new-device events for randomized addresses. |
| `IGNORE_MACS` | – | Comma-separated addresses to ignore completely. |
| `WEB_PORT` | `8080` | HTTP port (on the host, because of host networking). |
| `WEB_HOST` | `0.0.0.0` | Bind address. Use `127.0.0.1` behind a reverse proxy. |
| `WEB_USER` / `WEB_PASSWORD` | – | Enable HTTP basic auth for the UI and API. |
| `DB_PATH` | `/data/yolo.db` | SQLite database location. |
| `TZ` | `UTC` | Container time zone (logs). The UI always shows the viewer's local time. |
| `LOG_LEVEL` | `INFO` | `DEBUG` shows HCI command failures and parse errors. |
| `DEMO_MODE` | `0` | Generate synthetic devices. |
| `DEMO_BACKFILL_HOURS` | `72` | History generated on first demo start. |

---

## Using the UI

- **Overview:** active vs. total devices per type, active devices and connected clients over time (6 h to 30 d), currently connected clients with the network they're on, sensor health (packets/s, current channel, errors), and recent events. Every card and row links deeper.
- **Devices:** a searchable, sortable list. Filter by type, recency or vendor, and hide randomized MACs. Filter chips from drill-downs (SSID, channel, probed SSID, BSSID, vendor) can be removed individually. CSV export.
- **Device detail** (click any device):
  - key facts, total time present, visits, average and longest visit, time connected
  - **signal strength** chart (avg plus min–max band)
  - **weekly pattern** heatmap: when the device is usually around
  - **presence & connectivity timeline**: visits plus one lane per AP (or per client, on an AP's page) showing exactly when it was connected
  - for APs: **connected clients over time**, the client list, and other BSSIDs with the same SSID
  - for clients: the APs/networks it connected to, with session counts and total time, and the SSIDs it probes for
  - a session table (connections or visits) with duration, frames, signal and why each session ended, plus device events
- **Statistics:** activity by hour of day, new devices per day, session duration distribution, top vendors, AP channel usage, SSID table (BSSIDs, clients, security), most-connected clients, busiest APs, probed SSIDs, MAC-randomization ratio and event counts. Click any bar or row to jump to the matching devices or events.
- **Events:** the full, filterable event log.

---

## API

Interactive docs are at `/api/docs`. Main endpoints:

| Endpoint | Description |
|---|---|
| `GET /api/summary` | Counts per type, recent events |
| `GET /api/timeline?hours=24` | Active devices per type and connected clients per time bucket |
| `GET /api/devices?kind=&active=&q=&vendor=&ssid=&probe=&bssid=&channel=&randomized=&connected=&sort=&order=&limit=&offset=` | Device list |
| `GET /api/devices/{mac}` | Device detail, stats, peers, probes, events |
| `GET /api/devices/{mac}/rssi?hours=` | Signal history |
| `GET /api/devices/{mac}/sessions?hours=&as_peer=1` | Visits/connections (`as_peer=1`: client sessions on an AP) |
| `GET /api/devices/{mac}/clients?hours=` | Connected clients over time for an AP |
| `GET /api/devices/{mac}/heatmap?days=28&tz=` | Weekday × hour presence matrix |
| `GET /api/stats?days=7` | All statistics shown on the Statistics page |
| `GET /api/events?type=&mac=&kind=&before=` | Event log |
| `GET /api/status` | Sensor and store health |
| `GET /api/export/devices.csv`, `/api/export/sessions.csv?days=7` | CSV export |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `interface wlan1 not found` | Check `iw dev` on the host, make sure the container uses `network_mode: host`, and pin the name with udev. |
| `driver refused monitor mode` | The chipset/driver doesn't support it (common for onboard Broadcom and many Realtek chips with in-kernel drivers). Use an adapter from the table above. |
| Adapter keeps leaving monitor mode | NetworkManager / wpa_supplicant is managing it. See [step 2](#2-keep-networkmanager--wpa_supplicant-away-from-it). |
| Only 2.4 GHz networks show up | The adapter is 2.4 GHz only (channels it can't tune are skipped automatically; see the sensor panel), or 5 GHz APs are out of range. |
| Few clients compared to APs | Clients transmit far less than APs beacon. Lock one adapter to your busiest channel(s) with `WIFI_CHANNELS_<iface>`, or add a second adapter. |
| `hci0 is blocked by rfkill` | `sudo rfkill unblock bluetooth` |
| No BLE devices, sensor shows `scanning` | Run with `LOG_LEVEL=DEBUG`. If LE commands fail with status `0x0c`, another process holds the scanner. Stop `bluetoothd` or use a dedicated dongle. |
| Classic BT devices missing | Classic devices only answer inquiries while *discoverable* (usually only in their pairing screen). Devices connected to the host are always recorded. |
| `Operation not permitted` on HCI | Run privileged (or add `NET_RAW`, `NET_ADMIN` and `seccomp=unconfined`). |
| Many short-lived "devices" | These are randomized MACs. Tick **Hide randomized MACs**. |
| `dropped` counter rising | The host is too slow for the frame rate. Lower the number of channels or use fewer adapters. |

---

## Development

```bash
# run tests inside the image
docker build -t yolo . && docker run --rm -v "$PWD/tests:/app/tests" yolo \
  sh -c "pip install -q pytest && python -m pytest -q tests"

# run locally (Python 3.11+; capture needs root)
pip install -r requirements.txt
DEMO_MODE=1 DB_PATH=./data/yolo.db python -m yolo
```

Layout:

```
yolo/
  config.py     environment configuration
  wifi.py       monitor mode, channel hopping, 802.11 frame parsing
  bluetooth.py  raw HCI LE scanning / inquiry / connection tracking
  store.py      sessions, samples, events, SQLite persistence
  web.py        FastAPI JSON API
  demo.py       synthetic data generator
  static/       single-page UI (vanilla JS + Chart.js)
tests/          parser and session-logic tests
```

---

## Legal

Passively receiving radio traffic is legal in many places, but recording and keeping identifiers of other people's devices can fall under privacy law (e.g. the GDPR in the EU). Only monitor environments you are responsible for, keep retention short, and don't use this to track individuals.
