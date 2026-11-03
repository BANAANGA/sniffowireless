# yolo

A self-hosted Wi-Fi and Bluetooth monitor that runs as a single Docker container. It works like a small Kismet, with one difference: it is built to track **how devices connect over time**. It records which Wi-Fi client was associated with which access point and when. It also records when phones, wearables and other Bluetooth devices come into and leave range. You can drill into all of it from a dark, minimal web UI.

- **Wi-Fi:** passive monitor-mode capture with channel hopping across 2.4 GHz, 5 GHz and **6 GHz (Wi-Fi 6E/7)**, on one or more USB adapters
- **Bluetooth:** BLE advertising plus Classic inquiry over a raw HCI socket. No BlueZ daemon is needed inside the container.
- **Ethernet / LAN:** passive capture on a wired interface. It discovers devices via ARP, DHCP, mDNS, SSDP and LLDP, and shows per-device traffic, who each device talks to, and DNS lookups. It also detects rogue DHCP servers and ARP spoofing.
- **Connectivity history:** presence sessions ("visits") for every device, connection sessions for Wi-Fi client→AP links (including roaming between BSSIDs and deauths), and Bluetooth links to the sensor's adapter
- **Passive device identification:** brand, model, device type, OS, Wi-Fi generation and estimated age, worked out from capability elements, WPS data, Apple/Microsoft/Google Bluetooth beacons, Bluetooth class of device, names and MAC vendor. Each result shows its evidence and confidence. Probe fingerprints group randomized MACs that belong to the same model/OS.
- **Labels, groups and watch list:** name devices, mark them known, and group a person's phone, watch and earbuds (or a phone's rotating MACs, with merge suggestions) into one presence history
- **Alerts:** rules for watched or unknown devices, groups arriving/leaving and security events, with quiet hours and cooldowns, delivered via ntfy, Telegram, Discord, webhooks or email
- **Security monitoring (defensive):** evil-twin / rogue access points for your SSIDs, deauthentication floods, KARMA-style access points, and open/WEP/WPS/no-WPA3 findings on your own networks
- **Wi-Fi health:** per-channel airtime, retries and noise with channel recommendations; client health for your own networks (band use, roaming and ping-pong, sticky clients, disconnect reasons)
- **Multiple sensors and a map:** remote Raspberry Pi sensors forward to one server; each device gets a room and an approximate position on your floor plan
- **Occupancy reports:** estimated people per hour, visitors, dwell time, a printable/PDF report and a weekly email
- **Accounts and integrations:** login with admin/viewer roles, API tokens, an ignore list, and a Prometheus `/metrics` endpoint with a ready-made Grafana dashboard
- **Drill-down statistics:** overview → device type → device → sessions; SSID → APs → clients; vendor / channel / probed SSID → devices; per-device signal history, weekly presence heatmap, timeline, peers, events
- **Storage:** SQLite in a single volume, per-minute signal samples, configurable retention, CSV export, JSON API
- **Demo mode** so you can try the UI without any radios

| Overview | Device: Wi-Fi client |
|---|---|
| [![Overview](docs/screenshots/overview.png)](docs/screenshots/overview.png) | [![Wi-Fi client detail](docs/screenshots/device-client.png)](docs/screenshots/device-client.png) |
| **Statistics** | **Device: access point** |
| [![Statistics](docs/screenshots/statistics.png)](docs/screenshots/statistics.png) | [![Access point detail](docs/screenshots/device-ap.png)](docs/screenshots/device-ap.png) |

<details>
<summary>More screenshots</summary>

**Device list** (randomized MACs hidden, band and connection state per device)

![Devices](docs/screenshots/devices.png)

**Device identification** (an HP printer identified from its WPS data and Wi-Fi Direct network name)

![Identification](docs/screenshots/identification.png)

**Wi-Fi client:** signal history, weekly presence heatmap, and a timeline showing when the phone was connected to each of three mesh BSSIDs (2.4, 5 and 6 GHz) as it roamed.

**Access point:** which clients were connected when, and how many over time.

| Security | Map |
|---|---|
| [![Security](docs/screenshots/security.png)](docs/screenshots/security.png) | [![Map](docs/screenshots/map.png)](docs/screenshots/map.png) |
| **My networks** | **Channels** |
| [![My networks](docs/screenshots/mynet.png)](docs/screenshots/mynet.png) | [![Channels](docs/screenshots/channels.png)](docs/screenshots/channels.png) |
| **Occupancy report** | **Group (person)** |
| [![Reports](docs/screenshots/reports.png)](docs/screenshots/reports.png) | [![Group](docs/screenshots/group.png)](docs/screenshots/group.png) |
| **LAN (Ethernet)** | **Wired device** |
| [![LAN](docs/screenshots/lan.png)](docs/screenshots/lan.png) | [![NAS](docs/screenshots/device-lan.png)](docs/screenshots/device-lan.png) |

</details>

*Screenshots use the built-in demo mode (`DEMO_MODE=1`); all devices are synthetic.*

---

## Contents

1. [How it works](#how-it-works)
2. [Hardware](#hardware)
3. [Connecting USB Wi-Fi / Bluetooth adapters](#connecting-usb-wi-fi--bluetooth-adapters)
4. [Deploy](#deploy)
5. [Accounts & access](#accounts--access)
6. [Configuration](#configuration)
7. [Device identification](#device-identification)
8. [Using the UI](#using-the-ui)
9. [Alerts & notifications](#alerts--notifications)
10. [Security monitoring](#security-monitoring)
11. [Ethernet monitoring](#ethernet-monitoring)
12. [Multiple sensors & the map](#multiple-sensors--the-map)
13. [Prometheus & Grafana](#prometheus--grafana)
14. [API](#api)
15. [Troubleshooting](#troubleshooting)
16. [Development](#development)
17. [Legal](#legal)

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

### 6 GHz (Wi-Fi 6E / Wi-Fi 7)

To see 6 GHz networks you need a **6E-capable adapter** whose driver allows monitor mode on 6 GHz. The best-supported USB option today is the **MT7921AU** (`mt7921u`, kernel ≥ 5.18; ≥ 6.1 recommended). Some Intel AX210/BE200 PCIe cards also work in monitor mode on recent kernels.

1. **Set your regulatory domain.** Most drivers keep 6 GHz disabled until a country is configured. Set `WIFI_REGDOMAIN=NL` (your two-letter country code), or run `sudo iw reg set NL` on the host.
2. **Check the adapter can tune 6 GHz.** The command below should list frequencies from 5955 MHz upwards that are not marked `(disabled)`. `(no IR)` is fine, because monitoring is passive.
   ```bash
   iw phy "$(cat /sys/class/net/wlan1/phy80211/name)" info | grep -E "\* (59[5-9][0-9]|6[0-9]{3}|7[01][0-9]{2})"
   ```
3. **Add 6 GHz channels.** Use `WIFI_CHANNELS=default,6ghz`, or `all`, which covers 2.4 + 5 GHz + the 6 GHz Preferred Scanning Channels. 6 GHz access points always beacon on one of the 15 PSCs (5, 21, 37 … 229), so `6ghz` finds them with far fewer hops than all 59 channels (`6all`).

yolo reads each adapter's supported frequencies at startup and gives 6 GHz channels only to adapters that can tune them. A 2.4/5 GHz adapter and a 6E adapter can therefore share one channel list. 6 GHz clients nearly always use randomized MACs (WPA3 + MAC privacy are mandatory there), but connection sessions are still tracked per network.

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

Open **http://<host>:8080**. On the first visit you create the admin account (see [Accounts & access](#accounts--access)). Data is stored in `./data` (`yolo.db` plus an uploaded floor plan). Back up that folder to keep your history.

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

## Accounts & access

The web UI and API need a login.

- **First start without `WEB_USER`/`WEB_PASSWORD`:** the browser shows a *Create the admin account* page. To stop someone else on your network from claiming the admin account first, it asks for a one-time **setup code** printed in the container log:
  ```bash
  docker compose logs yolo | grep "setup code"
  ```
- **With `WEB_USER` and `WEB_PASSWORD`:** that account is created (or reset) as an admin on every start, and no setup page is shown. Its password can only be changed through the environment.
- **Roles:** *admins* can change settings, labels, groups, alert rules and the ignore list. *Viewers* can only look. Add users under **Settings → Users**.
- **API tokens** (Settings → API tokens) are sent as `Authorization: Bearer <token>`:
  - `metrics`: only `/metrics`
  - `read`: read-only API
  - `admin`: full API

  Remote sensors get their own tokens, created under Settings → Sensors.
- Passwords are stored as salted PBKDF2-SHA256 hashes. Sessions are HttpOnly cookies that expire after 14 days of inactivity. Logins are rate-limited per IP.
- **HTTPS:** put yolo behind a reverse proxy (Caddy, Traefik, nginx) for TLS when you reach it from outside your LAN. The session cookie is marked `Secure` when the proxy sets `X-Forwarded-Proto: https`.
- `AUTH_DISABLED=1` turns login off entirely. Only use it on a network where you trust everyone.

---

## Configuration

All settings are environment variables (put them in `.env`).

| Variable | Default | Description |
|---|---|---|
| `WIFI_INTERFACES` | *(empty)* | Comma-separated Wi-Fi adapters to capture on, e.g. `wlan1,wlan2`. Empty disables Wi-Fi. |
| `WIFI_CHANNELS` | `default` | Comma-separated presets and channels (see below). With several adapters the list is split between them, and each channel only goes to adapters that support it. |
| `WIFI_CHANNELS_<iface>` | – | Per-adapter channel list, e.g. `WIFI_CHANNELS_wlan1=1,6,11` or `WIFI_CHANNELS_wlan2=6ghz`. A single channel locks the adapter (no hopping). |
| `WIFI_REGDOMAIN` | – | Two-letter country code applied with `iw reg set` at startup (e.g. `NL`, `US`, `DE`). Usually required for 6 GHz. |
| `WIFI_HOP_INTERVAL` | `0.5` | Seconds spent on each channel. |
| `WIFI_SET_MONITOR` | `1` | Put interfaces in monitor mode automatically. |
| `BT_DEVICES` | *(empty)* | Bluetooth adapters, e.g. `hci0`. Empty disables Bluetooth. |
| `ETH_INTERFACES` | *(empty)* | Wired interfaces to capture on, e.g. `eth1` or `enp3s0`. Empty disables Ethernet capture. |
| `ETH_PROMISC` | `1` | Put the Ethernet interface in promiscuous mode (needed on a mirror/SPAN port). |
| `LAN_SESSION_TIMEOUT` | `900` | Seconds without traffic before a LAN device counts as offline. |
| `BT_ACTIVE_SCAN` | `1` | Active LE scanning (sends scan requests, which gets device names). `0` is fully passive. |
| `BT_INQUIRY` | `1` | Periodic Bluetooth Classic inquiry (finds *discoverable* classic devices). |
| `BT_INQUIRY_INTERVAL` | `60` | Seconds between inquiries. |
| `BT_RESOLVE_NAMES` | `1` | Ask newly found classic devices for their name. |
| `WIFI_SESSION_TIMEOUT` | `300` | Seconds of silence before a Wi-Fi visit or connection is closed. |
| `BT_SESSION_TIMEOUT` | `180` | Same for Bluetooth. |
| `ACTIVE_WINDOW` | `300` | "Active now" window used by the overview cards. |
| `RETENTION_DAYS` | `30` | Samples, sessions, events and devices older than this are pruned hourly. |
| `EVENTS_FOR_RANDOMIZED` | `0` | Also log arrive/leave/new-device events for randomized addresses. |
| `IGNORE_MACS` | – | Comma-separated addresses to ignore completely (the admin can also maintain an ignore list in the UI). |
| `WEB_PORT` | `8080` | HTTP port (on the host, because of host networking). |
| `WEB_HOST` | `0.0.0.0` | Bind address. Use `127.0.0.1` behind a reverse proxy. |
| `WEB_USER` / `WEB_PASSWORD` | – | Admin account created/reset on start. If unset, create it in the browser with the setup code from the log. |
| `AUTH_DISABLED` | `0` | `1` disables login completely (trusted networks only). |
| `YOLO_MODE` | `server` | `sensor` = capture only and forward to `SERVER_URL` (see [Multiple sensors](#multiple-sensors--the-map)). |
| `SERVER_URL` / `SENSOR_TOKEN` | – | Sensor mode: URL of the main yolo server and the token from Settings → Sensors. |
| `DB_PATH` | `/data/yolo.db` | SQLite database location. |
| `DATA_DIR` | folder of `DB_PATH` | Where uploaded files (floor plan) are kept. |
| `TZ` | `UTC` | Container time zone (logs). The UI always shows the viewer's local time. |
| `LOG_LEVEL` | `INFO` | `DEBUG` shows HCI command failures and parse errors. |
| `DEMO_MODE` | `0` | Generate synthetic devices. |
| `DEMO_BACKFILL_HOURS` | `72` | History generated on first demo start. |

**Channel syntax** for `WIFI_CHANNELS` / `WIFI_CHANNELS_<iface>`:

| Token | Meaning |
|---|---|
| `default` | 2.4 GHz 1–13 + 5 GHz 36–48, 149–165 |
| `2.4ghz` (or `2.4`), `5ghz`, `5common` | The whole band / common 5 GHz channels |
| `6ghz` | 6 GHz Preferred Scanning Channels 5, 21, 37 … 229 (15 channels) |
| `6all` | All 59 20-MHz 6 GHz channels (1–233) |
| `all` | 2.4 GHz + all 5 GHz + 6 GHz PSCs |
| `1,6,11`, `36-48` | Channel numbers: 1–14 are 2.4 GHz, higher numbers 5 GHz; ranges keep valid channels only |
| `6g:37`, `6g:1-93` | 6 GHz channels (prefix needed, because 6 GHz reuses numbers 1, 5, 9 …) |

Tokens combine, e.g. `WIFI_CHANNELS=1,6,11,5common,6ghz`. A bare `5` or `6` on its own means the whole 5 / 6 GHz band.

---

## Device identification

yolo works out what each device is purely from what it broadcasts. Nothing is sent to the device. Every clue becomes a piece of evidence with a confidence score, and for each field the best-supported value wins. The device page shows the result, a confidence badge per field and the full evidence list.

| Source | What it reveals |
|---|---|
| **Wi-Fi capability elements** (probe/association requests, beacons) | Newest Wi-Fi standard (legacy a/b/g → Wi-Fi 4/5/6/6E/7), MIMO streams, channel width |
| **WPS element** (many printers, TVs, routers, some PCs) | Manufacturer, model name/number, device name, device category |
| **Vendor-specific elements** | Apple devices, Samsung, chipset vendor (Broadcom, Qualcomm, MediaTek, Realtek…), Wi-Fi Direct, MBO, Passpoint |
| **Probe-request layout** | A *probe fingerprint* hash: the element order/capabilities are characteristic of chipset + OS build, so randomized MACs from the same kind of phone share a hash |
| **Apple Continuity (BLE)** | AirPods/Beats model and release year; iPhone/iPad/Mac activity (Handoff, Nearby), AirPlay targets, Find My accessories |
| **Microsoft CDP beacons (BLE)** | Windows desktop/laptop/tablet, Xbox, Android/iPhone running Microsoft apps |
| **BLE services / appearance** | Tile, SmartTag, Fast Pair, Eddystone, heart-rate/fitness, HID keyboards/mice, Xiaomi/BTHome sensors… |
| **Bluetooth class of device** | Phone, laptop, headphones, car audio, speaker, watch, … |
| **Names / SSIDs** | “iPhone”, “Galaxy Watch5”, “DESKTOP-XXXXXXX” (Windows), “[TV] Samsung…”, “DIRECT-xx-HP…” printers, phone hotspots, car hotspots |
| **MAC vendor (OUI)** | Brand, plus a type hint for single-purpose vendors (Espressif → IoT, Sonos → speaker, Hikvision → camera…) |

**Estimated age** comes from the newest standard a device supports (it can't predate it), or from the model's release year when that is known (AirPods/Beats). For phones, computers, TVs and routers yolo also gives an upper bound: a laptop with only Wi-Fi 5 is typically from 2013–2020. Printers and IoT devices still ship with Wi-Fi 4 today, so for those only "N or newer" is shown.

**Limits:** results are best-effort. Devices with randomized MACs and no name (most phones while idle) can often only be identified as "Apple phone, Wi-Fi 6" or "phone". Clients only reveal capabilities in probe/association frames, so a device first has to scan or (re)connect while the sensor is on its channel. When the rules improve in a new version, all stored devices are re-identified automatically on startup.

---

## Using the UI

- **Overview:** active vs. total devices per type, active devices and connected clients over time (6 h to 30 d), currently connected clients with the network they're on, sensor health (packets/s, current channel, errors), and recent events. Every card and row links deeper.
- **Devices:** a searchable, sortable list showing what each device was identified as. Filter by radio type, device type, recency or band (2.4 / 5 / 6 GHz), and hide randomized MACs. Drill-downs add filters for brand, OS, Wi-Fi generation, age and probe fingerprint. Filter chips from drill-downs (SSID, channel, probed SSID, BSSID, vendor) can be removed individually. CSV export.
- **Device detail** (click any device):
  - key facts, total time present, visits, average and longest visit, time connected
  - **identification:** brand, model, device type, OS, Wi-Fi generation and capabilities, chipset, estimated age, probe fingerprint (and how many other MACs share it), WPS info, and the evidence behind each value
  - **signal strength** chart (avg plus min–max band)
  - **weekly pattern** heatmap: when the device is usually around
  - **presence & connectivity timeline**: visits plus one lane per AP (or per client, on an AP's page) showing exactly when it was connected
  - for APs: **connected clients over time**, the client list, and other BSSIDs with the same SSID
  - for clients: the APs/networks it connected to, with session counts and total time, and the SSIDs it probes for
  - a session table (connections or visits) with duration, frames, signal and why each session ended, plus device events
- **Statistics:** device types, brands, Wi-Fi generations, estimated age, operating systems, shared probe fingerprints, activity by hour of day, new devices per day, session duration distribution, top vendors, AP channel usage per band, APs and clients per band, SSID table (BSSIDs, clients, security), most-connected clients, busiest APs, probed SSIDs, MAC-randomization ratio and event counts. Click any bar or row to jump to the matching devices or events.
- **Events:** the full, filterable event log.
- **Groups:** people or things made of several devices. A group's page shows the combined presence (when *any* of its devices was around), one timeline lane per device, and its events.
- **Map:** your floor plan with sensors and devices on it, plus a per-room device count. See [Multiple sensors & the map](#multiple-sensors--the-map).
- **Reports:** occupancy, meaning estimated people present per hour, a typical-week heatmap, unique/new/returning visitors per day and median visit length. *Print / PDF* gives a clean light-themed printout, and a weekly summary can be emailed (Settings → Weekly report). People are estimated from Wi-Fi phones present for at least 5 minutes; a "person" group counts once.
- **My networks:** add your SSIDs under Settings → My networks to see:
  - clients over time
  - band use (2.4/5/6 GHz share of connected time)
  - per-client signal, connected time, roams and **ping-pong roaming** (A→B→A within 2 minutes)
  - **sticky clients** (connected below −75 dBm while another of your APs is available)
  - clients capable of 5 GHz that sit on 2.4 GHz
  - disconnect reasons (timeouts vs. deauth reason codes)
- **Channels:** for each channel the sensor hops over:
  - estimated airtime use, retransmission rate, noise floor, frames/s and neighbouring APs
  - a ranking of the best channels per band (2.4 GHz: 1/6/11 with overlap weighting; 5 GHz: quietest 80 MHz block, non-DFS preferred; 6 GHz: PSCs)
  - a recommendation for each of your own access points

  Airtime is estimated from frame lengths and PHY rates, so treat it as relative.
- **Settings:**
  - account (password), users, my networks, ignore list, sensors
  - notification channels, weekly report, detection thresholds, API tokens

### Ignore list

Under **Settings → Ignore list** an admin can drop these before anything is stored:
- devices, by MAC
- whole vendor prefixes, e.g. a smart-plug brand
- networks, by SSID, optionally including every client connected to them

Ignored traffic never reaches the database, the UI or alerts. Tick *Also delete data already stored* to purge existing history for matching devices. The page shows how many stored devices match before you save.

### Labels, watch list and groups

On any device page an admin can set a **label** ("Sam's iPhone") and notes, and mark the device:
- **known:** excluded from "unknown device" alerts
- **watched:** included in arrive/leave alerts

A device can also be put in a **group**. *Possibly the same physical device* lists other MACs with the same probe fingerprint (or name) that were never present at the same time, which is typical of MAC rotation. One click adds them to the group.

---

## Alerts & notifications

Events (arrived, left, group arrived/left, new device, connected, roamed, moved room, rogue AP, deauth flood, …) are matched against **rules** (Alerts → Rules). Each rule has:
- the events it reacts to
- which devices it covers: any, watched, unknown, specific MACs, groups, or device types
- an optional time window (e.g. 23:00–06:00) and weekdays
- a per-device cooldown
- the notification channels to use

Three rules are created on first start and only log to the alert history until you attach a channel:
- watched devices arriving or leaving
- security alerts
- unknown devices at night

**Channels** (Settings → Notifications):

| Type | You need |
|---|---|
| ntfy | server URL (default `https://ntfy.sh`), topic, optional access token |
| Telegram | bot token (from @BotFather) and chat ID |
| Discord | channel webhook URL |
| Webhook | URL; receives `{"title", "body", "severity", "event"}` as JSON, with an optional extra auth header |
| Email | SMTP host, port, STARTTLS/SSL, login, from and to |

Use **Send test** to check a channel. Secrets are never sent back to the browser.

---

## Security monitoring

Configure **My networks** first (Settings → My networks), then mark your own access points as **trusted** (Security page, *Trust all listed* on a clean setup). yolo then reports:

| Finding | How it's detected |
|---|---|
| **Rogue / evil-twin AP** | one of your SSIDs broadcast by an untrusted BSSID; *high* when security or vendor differs from your trusted APs or the BSSID is locally administered |
| **Deauthentication flood** | ≥ 25 deauth/disassoc frames within 10 s for one BSSID (configurable) |
| **KARMA-style AP** | one BSSID advertising ≥ 4 different SSIDs within 10 minutes (configurable) |
| **Open / WEP / WPA-TKIP network** | on your own SSIDs |
| **WPS enabled** | WPS element in your AP's beacons |
| **No WPA3** | informational |

Findings can be acknowledged (no repeat alerts) or resolved (they reopen if the condition returns). All detection is passive: yolo never transmits deauths or other attack frames.

---

## Ethernet monitoring

Set `ETH_INTERFACES` to one or more wired interfaces and yolo listens passively, without sending anything.

| From | It learns |
|---|---|
| **ARP** | which MAC uses which IP, so devices appear as soon as they talk |
| **DHCP** | hostname, OS fingerprint (vendor class + requested-option order, e.g. Windows, Android 14, Apple, Linux/BusyBox) and the DHCP server and gateway |
| **mDNS / Bonjour** | services (AirPlay, Google Cast, printers, HomeKit, Sonos, Hue, Home Assistant…) and model names (`MacBookPro18,3`, `Google Nest Mini`, printer models) |
| **SSDP / UPnP** | server strings (Synology DSM, Sonos, Roku, Samsung/LG TVs, FRITZ!Box, Windows…) |
| **LLDP** | switches and access points: name, model, port |
| **IP traffic** | bytes sent and received per device over time, and every conversation (peer IP, port/service) named via DNS answers |
| **DNS queries** | which domains each device looks up (plain DNS only; DNS-over-HTTPS/TLS is invisible) |

All of this feeds the existing device list, identification, presence history, alerts and statistics. Wired-only devices appear as a new **LAN** device kind. A Wi-Fi client that is also seen on the LAN stays one device and gains an IP address, hostname and traffic. The **LAN** page shows:
- devices online
- throughput over time and top talkers
- internet destinations and traffic by service
- the most looked-up domains and the DHCP servers

Each device page gets a **Network (LAN)** panel with its traffic, peers and DNS lookups.

**Security:** trust your real DHCP server on the LAN page. Any other server answering DHCP then raises a **rogue DHCP** finding and alert; without a trusted server, a second DHCP server is flagged as *medium*. An IP address claimed by changing MACs (especially the gateway's) raises **ARP spoofing**.

### Where to plug it in

| Setup | What yolo sees |
|---|---|
| Ordinary switch port (e.g. the host's own NIC) | Discovery only: ARP, DHCP, mDNS, SSDP, LLDP broadcasts, plus the host's own traffic. Most devices still show up, with names and identification. |
| **Mirror / SPAN port** on a managed switch (UniFi, TP-Link Omada/Easy Smart, Netgear ProSafe, MikroTik, Cisco…) | Everything that crosses the mirrored ports. Mirror the port your router uplink is on to see all internet traffic. |
| **Network TAP** between router and switch (passive, e.g. a cheap 100 Mbit throwing-star or a gigabit TAP) | Everything between the LAN and the router. |
| On the router / firewall itself (Linux-based) | Everything it routes. |

Use a **dedicated** USB Ethernet adapter for the mirror port and give it no IP address, so the host doesn't use it for its own traffic:

```bash
sudo nmcli device set eth1 managed no   # keep NetworkManager away from it
sudo ip addr flush dev eth1
sudo ip link set eth1 up
# .env
ETH_INTERFACES=eth1
```

Packets are decoded in Python. Header parsing is a fast path, but a Raspberry Pi 4 handles roughly a few tens of thousands of packets per second, which is fine for home and small-office links. Watch the sensor's pkt/s and the *dropped* counter on the overview. Remote sensors (`YOLO_MODE=sensor`) support `ETH_INTERFACES` too.

**Privacy:** traffic and DNS logging reveal a lot about people's behaviour. Only monitor networks you're responsible for, tell the people using them, and keep `RETENTION_DAYS` short. Payloads are never stored; only byte counts, peers, ports and queried names are.

---

## Multiple sensors & the map

Run extra sensors, for example a Raspberry Pi with a USB Wi-Fi adapter in another room, and send everything to one server:

1. On the server: **Settings → Sensors → Add remote sensor**, then give it a name and room. You get a token and a ready-made `docker run` command.
2. On the sensor machine: connect the adapters as described above, then run that command (build or copy the image first). It's the same image with `YOLO_MODE=sensor`, `SERVER_URL` and `SENSOR_TOKEN`:
   ```bash
   docker run -d --name yolo-sensor --restart unless-stopped --network host --privileged \
     -e YOLO_MODE=sensor -e SERVER_URL=http://192.168.1.10:8080 -e SENSOR_TOKEN=yolo_... \
     -e WIFI_INTERFACES=wlan1 -e BT_DEVICES=hci0 yolo:latest
   ```
   The sensor buffers and retries if the server is unreachable, and corrects small clock differences.
3. **Map → Edit layout:** upload a floor plan (PNG, JPEG, WebP or SVG) and drag each sensor to where it really is.

Every device gets a **room** (the sensor that hears it strongest, with 4 dB hysteresis so it doesn't flicker) and a "moved" event when that changes. It also gets an approximate **position**: the signal-weighted average of the three strongest sensors. With one sensor, devices are drawn in a ring around it by signal strength. Room-level accuracy is realistic with a sensor per room. Exact positions are not; walls, bodies and phone orientation easily change the signal by 10 dB.

---

## Prometheus & Grafana

`GET /metrics` serves Prometheus metrics, including:
- devices active by kind and type
- clients per AP and per SSID
- presence and signal of watched or labelled devices, and group presence
- events per type, open findings by severity
- channel airtime and retry ratios
- sensor frames/s, and store queue/drops

Create a token with scope `metrics` and scrape with it:

```yaml
scrape_configs:
  - job_name: yolo
    authorization: { type: Bearer, credentials_file: /etc/prometheus/yolo_token }
    static_configs: [{ targets: ["yolo-host:8080"] }]
```

`contrib/monitoring/` holds a ready-to-run Prometheus + Grafana stack with a provisioned **yolo** dashboard:

```bash
echo -n "yolo_<your metrics token>" > contrib/monitoring/yolo_token
GRAFANA_PASSWORD=choose-one docker compose -f contrib/monitoring/docker-compose.monitoring.yml up -d
# Grafana: http://<host>:3000  (admin / GRAFANA_PASSWORD)
```

---

## API

Interactive docs (all endpoints) are at `/api/docs`. Every endpoint needs a login session or `Authorization: Bearer <token>`. Main read endpoints:

| Endpoint | Description |
|---|---|
| `GET /api/summary` | Counts per type, recent events |
| `GET /api/timeline?hours=24` | Active devices per type and connected clients per time bucket |
| `GET /api/devices?kind=&active=&q=&vendor=&brand=&dev_type=&os=&wifi_gen=&era=&fp=&ssid=&probe=&bssid=&channel=&band=&randomized=&connected=&sort=&order=&limit=&offset=` | Device list (`band`: `2.4`/`5`/`6`; `wifi_gen`: `3` legacy, `4`–`7`, `66` = 6E) |
| `GET /api/devices/{mac}` | Device detail, identification (`ident`), stats, peers, probes, events |
| `GET /api/devices/{mac}/rssi?hours=` | Signal history |
| `GET /api/devices/{mac}/sessions?hours=&as_peer=1` | Visits/connections (`as_peer=1`: client sessions on an AP) |
| `GET /api/devices/{mac}/clients?hours=` | Connected clients over time for an AP |
| `GET /api/devices/{mac}/heatmap?days=28&tz=` | Weekday × hour presence matrix |
| `GET /api/stats?days=7` | All statistics shown on the Statistics page |
| `GET /api/events?type=&mac=&kind=&before=` | Event log |
| `GET /api/status` | Sensor and store health |
| `GET /api/export/devices.csv`, `/api/export/sessions.csv?days=7` | CSV export |
| `GET /api/groups`, `/api/groups/{id}` | Groups and combined presence |
| `GET /api/alerts`, `/api/alert-rules` | Alert history and rules |
| `GET /api/security` | Findings, my-network BSSIDs, security events |
| `GET /api/channels?hours=24` | Channel survey and recommendations |
| `GET /api/mynet?days=7` | Health of my networks |
| `GET /api/map`, `/api/sensors` | Device rooms/positions, sensors |
| `GET /api/reports/occupancy?days=7` | Occupancy report data |
| `GET /api/lan?hours=24` | LAN overview: devices online, throughput, top talkers, destinations, services, DNS, DHCP servers |
| `GET /api/devices/{mac}/lan?hours=24` | Device traffic, peers and DNS lookups |
| `GET /metrics` | Prometheus metrics |
| `POST /api/ingest` | Remote sensors push observations here (sensor token) |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `interface wlan1 not found` | Check `iw dev` on the host, make sure the container uses `network_mode: host`, and pin the name with udev. |
| `driver refused monitor mode` | The chipset/driver doesn't support it (common for onboard Broadcom and many Realtek chips with in-kernel drivers). Use an adapter from the table above. |
| Adapter keeps leaving monitor mode | NetworkManager / wpa_supplicant is managing it. See [step 2](#2-keep-networkmanager--wpa_supplicant-away-from-it). |
| No 6 GHz networks | Set `WIFI_REGDOMAIN`, add `6ghz` to `WIFI_CHANNELS`, and check `iw phy … info` lists 6 GHz frequencies that aren't `(disabled)`. The startup log says which configured channels each adapter cannot tune. 6 GHz range is short, so move the sensor closer. |
| Only 2.4 GHz networks show up | The adapter is 2.4 GHz only (channels it can't tune are skipped automatically; see the sensor panel), or 5 GHz APs are out of range. |
| Few clients compared to APs | Clients transmit far less than APs beacon. Lock one adapter to your busiest channel(s) with `WIFI_CHANNELS_<iface>`, or add a second adapter. |
| `hci0 is blocked by rfkill` | `sudo rfkill unblock bluetooth` |
| No BLE devices, sensor shows `scanning` | Run with `LOG_LEVEL=DEBUG`. If LE commands fail with status `0x0c`, another process holds the scanner. Stop `bluetoothd` or use a dedicated dongle. |
| Classic BT devices missing | Classic devices only answer inquiries while *discoverable* (usually only in their pairing screen). Devices connected to the host are always recorded. |
| `Operation not permitted` on HCI | Run privileged (or add `NET_RAW`, `NET_ADMIN` and `seccomp=unconfined`). |
| Many short-lived "devices" | These are randomized MACs. Tick **Hide randomized MACs**. |
| Locked out of the UI | Set `WEB_USER`/`WEB_PASSWORD` and restart: that account is reset to admin with the given password. |
| "Too many failed logins" | Wait 5 minutes (per-IP limit after 8 failures). |
| Remote sensor shows offline | Check `docker logs yolo-sensor` on the sensor; `SERVER_URL` must be reachable from it and the token must match the sensor. |
| Everyone is in the same room on the map | You need at least two sensors with room names; one sensor can only tell distance. |
| LAN page shows devices but no internet traffic | The interface only sees broadcasts and its own traffic. Connect it to a mirror/SPAN port or TAP (see [Ethernet monitoring](#ethernet-monitoring)). |
| `ETH_INTERFACES` error "not found" | Use the host's interface name (`ip -br link`), and run with `network_mode: host`. |
| No DNS names | Devices use DNS-over-HTTPS/TLS (common in browsers, Android "Private DNS", iCloud Private Relay); only plain DNS on port 53 is visible. |
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
  identify.py   passive device identification rules
  store.py      sessions, samples, events, ignore rules, plugin hooks, SQLite persistence
  auth.py       accounts, sessions, API tokens, setup flow
  settings.py   admin settings (JSON in the database)
  manage.py     ignore list, my networks, labels, groups
  alerts.py     alert rules, notification channels, engine
  security.py   rogue AP / deauth / KARMA / config findings
  survey.py     channel airtime survey and recommendations
  health.py     my-network client health
  sensors.py    remote sensor forwarding, ingest, room location, floor plan
  ethernet.py   raw-socket Ethernet capture: fast header parsing + ARP/DHCP/mDNS/SSDP/LLDP/DNS decoding
  lan.py        LAN traffic, conversations, DNS log, DHCP servers, rogue-DHCP / ARP-spoof detection
  reports.py    occupancy analytics and weekly email
  metrics.py    Prometheus endpoint
  web.py        FastAPI app and device/statistics API
  demo.py       synthetic data generator
  static/       single-page UI (vanilla JS + Chart.js): app.js, views.js, lan.js, login.html
contrib/monitoring/  Prometheus + Grafana stack and dashboard
tests/          parser, session, auth, alert, security, survey, location and report tests
```

---

## Legal

Passively receiving radio traffic is legal in many places, but recording and keeping identifiers of other people's devices can fall under privacy law (e.g. the GDPR in the EU). Only monitor environments you are responsible for, keep retention short, and don't use this to track individuals.
