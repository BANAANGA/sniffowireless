# sniffowireless

A self-hosted Wi-Fi and Bluetooth monitor that runs as a single Docker container. It works like a small Kismet, with one difference: it is built to track **how devices connect over time**. It records which Wi-Fi client was associated with which access point and when. It also records when phones, wearables and other Bluetooth devices come into and leave range. You can drill into all of it from a dark, minimal web UI.

- **Wi-Fi:** passive monitor-mode capture with channel hopping across 2.4 GHz, 5 GHz and **6 GHz (Wi-Fi 6E/7)**, on one or more USB adapters
- **Bluetooth:** BLE advertising plus Classic inquiry over a raw HCI socket. No BlueZ daemon is needed inside the container.
- **Ethernet / LAN:** passive capture on a wired interface. It discovers devices via ARP, DHCP, mDNS, SSDP and LLDP, and shows per-device traffic, who each device talks to, and DNS lookups. It also detects rogue DHCP servers and ARP spoofing.
- **Zigbee / IEEE 802.15.4:** with a USB coordinator stick, finds Zigbee networks and listens passively to all 802.15.4 traffic: frames per channel, addresses, frame types, channel interference and a protocol hint. It never transmits, and encrypted contents stay hidden.
- **Connectivity history:** presence sessions ("visits") for every device, connection sessions for Wi-Fi client→AP links (including roaming between BSSIDs and deauths), and Bluetooth links to the sensor's adapter
- **Passive device identification:** brand, model, device type, OS, Wi-Fi generation and estimated age, worked out from capability elements, WPS data, Apple/Microsoft/Google Bluetooth beacons, Bluetooth class of device, names and MAC vendor. Each result shows its evidence and confidence. Probe fingerprints group randomized MACs that belong to the same model/OS.
- **Labels, groups and watch list:** name devices, mark them known, and group a person's phone, watch and earbuds (or a phone's rotating MACs, with merge suggestions) into one presence history
- **Alerts:** rules for watched or unknown devices, groups arriving/leaving and security events, with quiet hours and cooldowns, delivered via ntfy, Telegram, Discord, webhooks or email
- **Security monitoring (defensive):** evil-twin / rogue access points for your SSIDs, deauthentication floods, KARMA-style access points, and open/WEP/WPS/no-WPA3 findings on your own networks
- **Interference detection:** non-Wi-Fi interference episodes (microwave ovens, video senders, baby monitors, radar) found from noise-floor and retry anomalies against each channel's baseline
- **DFS / radar detection:** passively spots access points that announce a channel switch or leave a 5 GHz DFS channel (52–144) because of radar, per channel, with alerts for your own networks
- **Unknown tracker detection:** AirTags/Find My, Tiles and SmartTags that move with a person ("possibly following") raise a high-severity alert
- **Backup & restore:** configuration export/import, full backups of all data (manual or scheduled), and restore of everything or only the parts you choose
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
12. [Zigbee & 802.15.4](#zigbee--802154)
13. [Multiple sensors & the map](#multiple-sensors--the-map)
14. [Backup & restore](#backup--restore)
15. [Prometheus & Grafana](#prometheus--grafana)
16. [API](#api)
17. [Troubleshooting](#troubleshooting)
18. [Development](#development)
19. [Legal](#legal)

---

## How it works

```
 USB Wi-Fi (monitor mode) ──► scapy sniffer + channel hopper ─┐
                                                              ├─► queue ─► store (SQLite, WAL) ◄── FastAPI ◄── browser UI
 USB / onboard Bluetooth ───► raw HCI socket: LE scan + inquiry┤
 USB Zigbee stick ──────────► serial: network scan + capture ──┘
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

1. **Set your regulatory domain.** Most drivers keep 6 GHz disabled until a country is configured. Set `WIFI_REGDOMAIN=NL` (your two-letter country code), or run `sudo iw reg set NL` on the host. The host also needs the **`wireless-regdb`** package (`regulatory.db`): without it the kernel can't apply any country, and stays on `00` ("world" rules, which have no 6 GHz). `./scripts/configure.sh` checks all of this and offers to fix it. To run only that check later:

   ```bash
   ./scripts/configure.sh --regdomain
   ```

   If the country is still `00` when sniffowireless starts with 6 GHz channels configured, sniffowireless says so in the log and on the Sensors panel. `iw reg get` should list `country NL` (or yours) under `global`; a separate `phy#…` entry is the adapter's own country code, which the kernel combines with the global one.
2. **Check the adapter can tune 6 GHz.** The command below should list frequencies from 5955 MHz upwards that are not marked `(disabled)`. `(no IR)` is fine, because monitoring is passive.
   ```bash
   iw phy "$(cat /sys/class/net/wlan1/phy80211/name)" info | grep -E "\* (59[5-9][0-9]|6[0-9]{3}|7[01][0-9]{2})"
   ```
3. **Add 6 GHz channels.** Use `WIFI_CHANNELS=default,6ghz` (or set it under [Settings → Wi-Fi channels](#wi-fi-channels-from-the-web-ui), also for remote sensors), or `all`, which covers 2.4 + 5 GHz + the 6 GHz Preferred Scanning Channels. 6 GHz access points always beacon on one of the 15 PSCs (5, 21, 37 … 229), so `6ghz` finds them with far fewer hops than all 59 channels (`6all`).

sniffowireless reads each adapter's supported frequencies at startup and gives 6 GHz channels only to adapters that can tune them. A 2.4/5 GHz adapter and a 6E adapter can therefore share one channel list. 6 GHz clients nearly always use randomized MACs (WPA3 + MAC privacy are mandatory there), but connection sessions are still tracked per network.

**Channel tunes but no 6 GHz networks show up?** The Sensors panel on the Overview lists the frames received per band (`frames 2.4G … · 5G … · 6G …`). Then run the diagnostic on the machine with the adapter. It tunes each 6 GHz channel, listens for a few seconds, and prints frames, beacons, access points, SSIDs and the frequency the driver reported:

```bash
docker compose stop sniffowireless
docker compose run --rm sniffowireless python -m sniffowireless.diag            # 6 GHz PSCs on the first WIFI_INTERFACES adapter
docker compose run --rm sniffowireless python -m sniffowireless.diag wlan1 --channels 6g:37 --dwell 10
docker compose start sniffowireless
```

- **0 frames everywhere:** the driver or firmware doesn't receive on 6 GHz in monitor mode. Update the kernel (≥ 6.1) and `linux-firmware`, and check the antennas.
- **Frames but the driver reports another band:** some mt76 builds label 6 GHz frames as 5 GHz (channel 37 → 5185 MHz). sniffowireless now uses the tuned frequency in that case, and the Sensors panel counts the corrected frames.
- **Beacons on one channel only:** normal. An access point beacons on its primary 20 MHz channel only, even at 160/320 MHz.

> **Don't use the adapter your host relies on for its own network.** Putting it in monitor mode disconnects it. Use a dedicated USB adapter. Two adapters (for example one locked to 2.4 GHz and one hopping 5 GHz) give much better coverage than one adapter that hops across everything.

### Bluetooth adapters

Any adapter the Linux kernel exposes as `hciX` works: an onboard controller, or a USB dongle such as CSR8510 A10, Realtek RTL8761B (BT 5.0) or Intel AX200/AX210 combo cards. For BLE range, a dongle with an external antenna helps a lot. Ubertooth / nRF sniffers are not supported. They capture differently.

### Zigbee sticks

Optional. See [Zigbee & 802.15.4](#zigbee--802154) for what each kind of stick can do. A Silicon Labs stick such as the Sonoff ZBDongle-E does the most.

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

# permanent: /etc/NetworkManager/conf.d/99-sniffowireless.conf
[keyfile]
unmanaged-devices=interface-name:wlan1;mac:00:c0:ca:12:34:56
```

then run `sudo systemctl reload NetworkManager`. If you use plain `wpa_supplicant`/`dhcpcd`, exclude the interface there (`denyinterfaces wlan1` in `/etc/dhcpcd.conf` on Raspberry Pi OS).

### 3. Give it a stable name (recommended)

USB adapters can be renamed between boots (`wlan1` ↔ `wlan2`, or `wlx…`). Pin a name with a udev rule. Use the adapter's MAC from `ip link`:

```bash
# /etc/udev/rules.d/70-sniffowireless-wifi.rules
SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="00:c0:ca:12:34:56", NAME="wlmon0"
```

Run `sudo udevadm control --reload && sudo udevadm trigger` (or replug) and set `WIFI_INTERFACES=wlmon0`.

### 4. Unblock radios

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

### Bluetooth and the host's `bluetoothd`

sniffowireless talks to the adapter over a raw HCI socket. It can run **alongside** the host's BlueZ daemon. It enables LE scanning and periodic inquiry and listens to all controller events, so devices the host connects to (headphones, keyboards) show up as Bluetooth connections. If you want sniffowireless to have the adapter to itself (best results on a dedicated dongle), stop BlueZ from using it: `sudo systemctl disable --now bluetooth`. Alternatively, give sniffowireless a second dongle (`BT_DEVICES=hci1`).

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

### 1. Get the code

```bash
git clone https://github.com/BANAANGA/sniffowireless.git
```

```bash
cd sniffowireless
```

### 2. Tell sniffowireless which adapters to use

sniffowireless reads its settings from a file called `.env` in the `sniffowireless` folder. The easiest way to create it is the helper script. It lists the adapters it finds and asks which ones to use:

```bash
./scripts/configure.sh
```

```
Wi-Fi adapters found:
    wlan0            e0:8f:4c:..  driver=iwlwifi <- this machine's own network connection
    wlan1            00:c0:ca:..  driver=mt76x2u
  Use a dedicated adapter: monitor mode disconnects it from any network.
WIFI_INTERFACES (comma-separated, empty = no Wi-Fi) [wlan1]:
...
Saved to /home/you/sniffowireless/.env:
    WIFI_INTERFACES=wlan1
    BT_DEVICES=hci0
```

Press Enter to accept a suggestion in `[brackets]`, or type your own (e.g. `wlan1,wlan2`). Run it again whenever you add or swap an adapter.

**Or do it by hand.** First find your adapter names:

```bash
iw dev                 # Wi-Fi adapters: the "Interface" lines, e.g. wlan1 or wlx00c0ca123456
```

```bash
ip -br link            # all network adapters, incl. wired ones (eth1, enp3s0, enx…)
```

```bash
ls /sys/class/bluetooth   # Bluetooth adapters: hci0, hci1 …
```

Then copy the example file and open it in an editor:

```bash
cp .env.example .env
```

```bash
nano .env
```

`cp` prints nothing when it works. Files starting with a dot are hidden, so use `ls -a` to see `.env`. In the editor, change these lines to your adapter names, then save (in nano: Ctrl+O, Enter, Ctrl+X):

```ini
WIFI_INTERFACES=wlan1      # comma-separated Wi-Fi adapters to capture on; empty = no Wi-Fi
BT_DEVICES=hci0            # Bluetooth adapters; empty = no Bluetooth
TZ=Europe/Amsterdam
```

Don't pick the adapter your machine uses for its own network connection (the one with an IP address in `ip -br addr`): monitor mode takes it offline. You can leave everything empty and start with `DEMO_MODE=1` to just look around.

### 3. Start it

```bash
docker compose up -d --build
```

```bash
docker compose logs -f
```

The log should show a line like `Wi-Fi sensor on wlan1` for each adapter, and the setup code for the admin account. Press Ctrl+C to stop following the log; sniffowireless keeps running.

To change adapters later, edit `.env` (or run `./scripts/configure.sh` again) and apply it with:

```bash
docker compose up -d
```

Open **http://<host>:8080**. On the first visit you create the admin account (see [Accounts & access](#accounts--access)). Data is stored in `./data` (`sniffowireless.db` plus an uploaded floor plan). Back up that folder to keep your history.

Try it without hardware:

```bash
DEMO_MODE=1 docker compose up -d --build
```

Demo mode backfills 72 h of synthetic history and keeps generating live data. For a clean real deployment afterwards, delete `./data/sniffowireless.db`.

### Without compose

```bash
docker build -t sniffowireless .
docker run -d --name sniffowireless --restart unless-stopped \
  --network host --privileged \
  -v "$PWD/data:/data" \
  -e WIFI_INTERFACES=wlan1 -e BT_DEVICES=hci0 -e TZ=Europe/Amsterdam \
  sniffowireless
```

### Deploying with Arcane

[Arcane](https://getarcane.app) is a web UI for managing Docker and Compose projects. sniffowireless can run as an Arcane project. Arcane can pull the [published image](#prebuilt-image) straight from the registry, or run an image you built from source on the Docker host.

> Arcane's documentation doesn't mention `network_mode: host` or `privileged: true` containers, and these steps haven't been verified on a real Arcane install yet. If your Arcane behaves differently, the plain [`docker compose`](#3-start-it) route above always works.

**1. Install Arcane** by following its [installation guide](https://getarcane.app/docs/get-started/installation.html). Two things from that guide are worth repeating:
- set your own `ENCRYPTION_KEY` (for example from `openssl rand -hex 32`) instead of relying on the development default;
- sign in with the default login the guide lists and change the password when Arcane asks. Arcane controls Docker through its socket, so treat access to it like root access to the host.

Arcane uses port 3552, so it doesn't clash with sniffowireless on 8080.

**2. Prepare the adapters on the host** as described in [Connecting USB Wi-Fi / Bluetooth adapters](#connecting-usb-wi-fi--bluetooth-adapters). Arcane doesn't change anything on the host's network side.

**3. Get the image.** Nothing to do for the published image: Arcane pulls it when you deploy in step 5. To build from source instead, on the Docker host (the machine Arcane manages):

```bash
git clone https://github.com/BANAANGA/sniffowireless.git
```

```bash
cd sniffowireless && docker build -t sniffowireless:latest .
```

and use `image: sniffowireless:latest` in the compose file below.

**4. Create the project in Arcane.** Open **Projects → Create Project**, name it `sniffowireless`, paste this compose file, and fill in the **Environment Configuration (.env)** editor with your adapters:

```yaml
services:
  sniffowireless:
    image: ghcr.io/banaanga/sniffowireless:latest
    container_name: sniffowireless
    restart: unless-stopped
    network_mode: host
    privileged: true
    env_file:
      - path: .env
        required: false
    environment:
      WIFI_INTERFACES: ${WIFI_INTERFACES:-}
      WIFI_CHANNELS: ${WIFI_CHANNELS:-}
      WIFI_REGDOMAIN: ${WIFI_REGDOMAIN:-}
      BT_DEVICES: ${BT_DEVICES:-}
      ETH_INTERFACES: ${ETH_INTERFACES:-}
      ZIGBEE_DEVICES: ${ZIGBEE_DEVICES:-}
      WEB_PORT: ${WEB_PORT:-8080}
      WEB_USER: ${WEB_USER:-}
      WEB_PASSWORD: ${WEB_PASSWORD:-}
      ALLOWED_HOSTS: ${ALLOWED_HOSTS:-}
      TRUSTED_PROXIES: ${TRUSTED_PROXIES:-127.0.0.1}
      TZ: ${TZ:-UTC}
    volumes:
      - /opt/sniffowireless/data:/data
```

For example, in the `.env` editor:

```
WIFI_INTERFACES=wlan1
BT_DEVICES=hci0
TZ=Europe/Amsterdam
```

The data folder is an absolute host path on purpose, so you know exactly what to back up (it holds the database, floor plan and handshake captures) no matter where Arcane keeps its project files. Change `/opt/sniffowireless/data` if you like. The other settings in [Configuration](#configuration) go in the same `.env` editor.

**5. Deploy** the project from its page, then open `http://<host>:8080`. Don't close the *Watch output* window while a deploy is running: Arcane's documentation warns that doing so stops the project. The first sign-in asks for a one-time setup code, which is in the container's log:

```bash
docker logs sniffowireless
```

**Updating.** With the published image, click **Redeploy** on the project: Arcane pulls the latest image and restarts it. If you built the image yourself, rebuild it on the host:

```bash
cd sniffowireless && git pull && docker build -t sniffowireless:latest .
```

then recreate the container from Arcane's **Deploy** options, with *force recreate* ticked and a pull policy that doesn't pull. That image only exists on the host, so *Redeploy*, which pulls the latest images first, isn't what you want there.

**Alternative: build inside Arcane from Git.** Arcane can also create a project straight from this repository. Add the repository under **Customization → Git Repositories**, then **Projects → From Git Repo → Pull** with branch `main`, **Compose File Path** `docker-compose.yml`, and **Sync Files** on, so the `Dockerfile` is next to the compose file. Set your adapters in the project's `.env` editor (the compose file of a Pull project is read-only), then use **Build & Deploy**, which Arcane offers for services that have a `build:` section. Use **Auto Sync** to pick up new versions. This is the less proven route; if the build doesn't start, use the steps above.

### Prebuilt image

Released versions are published to the GitHub Container Registry for `linux/amd64` and `linux/arm64` (so also a Raspberry Pi), which saves building on the host:

```bash
docker pull ghcr.io/banaanga/sniffowireless:latest
```

The tags are `latest` (the newest release that isn't a pre-release), the release's own tag (for example `11`), `sha-<commit>`, and `edge` (a manual build of a branch). To use it with compose, replace the `build: .` and `image:` lines of `docker-compose.yml` with `image: ghcr.io/banaanga/sniffowireless:latest`, then:

```bash
docker compose pull && docker compose up -d
```

With plain `docker run` (see above), use the same image name instead of `sniffowireless`.

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
  docker compose logs sniffowireless | grep "setup code"
  ```
- **With `WEB_USER` and `WEB_PASSWORD`:** that account is created (or reset) as an admin on every start, and no setup page is shown. Its password can only be changed through the environment.
- **Roles:** *admins* can change settings, labels, groups, alert rules and the ignore list. *Viewers* can only look. Add users under **Settings → Users**.
- **API tokens** (Settings → API tokens) are sent as `Authorization: Bearer <token>`:
  - `metrics`: only `/metrics`
  - `read`: read-only API
  - `admin`: full API

  Remote sensors get their own tokens, created under Settings → Sensors.
- Passwords are stored as salted PBKDF2-SHA256 hashes. Sessions are HttpOnly cookies that expire after 14 days of inactivity. Logins are rate-limited per IP.
- **HTTPS:** put sniffowireless behind a reverse proxy (Caddy, Traefik, nginx) for TLS when you reach it from outside your LAN. The session cookie is marked `Secure` when the proxy sets `X-Forwarded-Proto: https`.
- `AUTH_DISABLED=1` turns login off entirely. Only use it on a network where you trust everyone, and set `ALLOWED_HOSTS` then; see below.

### Security hardening

sniffowireless treats everything it receives as untrusted. Device names and SSIDs are chosen by whoever is nearby, and remote sensors and API clients send data too.

- **Input validation:**
  - every API field has a type, a format (MACs, IPs, times, e-mail addresses, enums) and a length limit
  - names, SSIDs, labels and notification titles are stripped of control characters, which blocks newline/header injection and Unicode direction tricks
  - data pushed by remote sensors is re-validated field by field; unknown record types are refused and gzip bombs are capped
- **Output encoding:** the UI escapes every value it inserts into a page. A strict **Content-Security-Policy** (no inline or third-party scripts except the pinned Chart.js CDN fallback) stops script injection even if something slipped through.
- **Uploads:** floor plans are checked by content (PNG, JPEG, WebP or SVG), SVGs are stripped of scripts and event handlers, and the image is served sandboxed. Backups are verified (format, safe paths, database integrity) before restore.
- **Requests:** CSRF protection (custom header plus an Origin check, `SameSite` cookies), body size limits, limits on time ranges and page sizes, and security headers (`nosniff`, `DENY` framing, `no-referrer`, `no-store` for API responses, HSTS over HTTPS).
- **Login:**
  - salted PBKDF2 hashes
  - lockout per IP and per account after repeated failures
  - equal response times for unknown users, so usernames can't be probed
  - a rate-limited setup code
  - minimum password rules
- **Exports:** CSV cells that start with `=`, `+`, `-` or `@` are prefixed so spreadsheets don't run them as formulas.
- **Proxies and hosts:**
  - `TRUSTED_PROXIES` (default `127.0.0.1`): only these addresses may set `X-Forwarded-For`/`-Proto`, so clients can't fake their IP to dodge the lockout. Set it to your reverse proxy's address.
  - `ALLOWED_HOSTS` (e.g. `sniffowireless.lan,192.168.1.10`): refuses requests for any other host name, which protects against DNS-rebinding attacks from malicious websites, especially with `AUTH_DISABLED=1`.

The container needs `privileged`/host networking to capture, so run it on a machine you control and don't expose port 8080 to the internet; use a VPN or an authenticating reverse proxy with TLS for remote access.

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
| `ZIGBEE_DEVICES` | *(empty)* | USB Zigbee sticks, ideally by stable path under `/dev/serial/by-id/`. Empty disables Zigbee / 802.15.4 monitoring. |
| `ZIGBEE_CHANNELS` | all (`11-26`) | Channels to listen on, e.g. `15,20-25`. One channel catches brief traffic best. |
| `ZIGBEE_HOP_INTERVAL` | `2` | Seconds spent on each channel when listening to more than one. |
| `ZIGBEE_SCAN_INTERVAL` | `600` | Seconds between network scans (minimum 30). |
| `ZIGBEE_SNIFF` | `1` | `0` turns passive listening off, leaving only network scans. |
| `ETH_PROMISC` | `1` | Put the Ethernet interface in promiscuous mode (needed on a mirror/SPAN port). |
| `LAN_SESSION_TIMEOUT` | `900` | Seconds without traffic before a LAN device counts as offline. |
| `BT_ACTIVE_SCAN` | `1` | Active LE scanning (sends scan requests, which gets device names). `0` is fully passive. |
| `BT_INQUIRY` | `1` | Periodic Bluetooth Classic inquiry (finds *discoverable* classic devices). |
| `BT_INQUIRY_INTERVAL` | `60` | Seconds between inquiries. |
| `BT_RESOLVE_NAMES` | `1` | Ask newly found classic devices for their name. |
| `WIFI_SESSION_TIMEOUT` | `300` | Seconds of silence before a Wi-Fi visit or connection is closed. |
| `BT_SESSION_TIMEOUT` | `180` | Same for Bluetooth. |
| `ACTIVE_WINDOW` | `300` | "Active now" window used by the overview cards. |
| `DB_CACHE_MB` | `16` | Page cache SQLite gives each database query (statistics and timeline pages are faster with more). `0` = SQLite's default of 2 MB. |
| `DB_MMAP_MB` | `256` | Size of the memory map over the database file. `0` disables it. Both can be switched off together at runtime in Settings → Performance (for low-memory machines). |
| `RETENTION_DAYS` | `30` | Samples, sessions, events and devices older than this are pruned hourly. |
| `EVENTS_FOR_RANDOMIZED` | `0` | Also log arrive/leave/new-device events for randomized addresses. |
| `IGNORE_MACS` | – | Comma-separated addresses to ignore completely (the admin can also maintain an ignore list in the UI). |
| `WEB_PORT` | `8080` | HTTP port (on the host, because of host networking). |
| `WEB_HOST` | `0.0.0.0` | Bind address. Use `127.0.0.1` behind a reverse proxy. |
| `WEB_USER` / `WEB_PASSWORD` | – | Admin account created/reset on start. If unset, create it in the browser with the setup code from the log. |
| `AUTH_DISABLED` | `0` | `1` disables login completely (trusted networks only). |
| `ALLOWED_HOSTS` | – | Comma-separated host names/IPs the UI may be reached as (DNS-rebinding protection). Empty = any. |
| `TRUSTED_PROXIES` | `127.0.0.1` | Addresses whose `X-Forwarded-*` headers are trusted (your reverse proxy). |
| `SNIFFOWIRELESS_MODE` | `server` | `sensor` = capture only and forward to `SERVER_URL` (see [Multiple sensors](#multiple-sensors--the-map)). |
| `SERVER_URL` / `SENSOR_TOKEN` | – | Sensor mode: URL of the main sniffowireless server and the token from Settings → Sensors. |
| `DB_PATH` | `/data/sniffowireless.db` | SQLite database location. |
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

sniffowireless works out what each device is purely from what it broadcasts. Nothing is sent to the device. Every clue becomes a piece of evidence with a confidence score, and for each field the best-supported value wins. The device page shows the result, a confidence badge per field and the full evidence list.

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
| **Bikes** | Bluetooth "Cycling" appearance or cycling speed/cadence/power services, and names such as VanMoof `ES3-…`/`EX3-…` or Cowboy → *Bike / e-bike* |
| **Names / SSIDs** | “iPhone”, “Galaxy Watch5”, “DESKTOP-XXXXXXX” (Windows), “[TV] Samsung…”, “DIRECT-xx-HP…” printers, phone hotspots, car hotspots |
| **MAC vendor (OUI)** | Brand, plus a type hint for single-purpose vendors (Espressif → IoT, Sonos → speaker, Hikvision → camera…) |

**Estimated age** comes from the newest standard a device supports (it can't predate it), or from the model's release year when that is known (AirPods/Beats). For phones, computers, TVs and routers sniffowireless also gives an upper bound: a laptop with only Wi-Fi 5 is typically from 2013–2020. Printers and IoT devices still ship with Wi-Fi 4 today, so for those only "N or newer" is shown.

**Limits:** results are best-effort. Devices with randomized MACs and no name (most phones while idle) can often only be identified as "Apple phone, Wi-Fi 6" or "phone". Clients only reveal capabilities in probe/association frames, so a device first has to scan or (re)connect while the sensor is on its channel. When the rules improve in a new version, all stored devices are re-identified automatically on startup.

---

## Using the UI

- **Search** (box at the top of the sidebar; press <kbd>/</kbd> to jump to it): searches every record. That covers:
  - devices: MAC (with or without separators), IP, name, label, notes, SSID, vendor, brand, model
  - groups, networks and probed network names
  - DNS lookups, events, alerts, security findings and sensors

  Results appear as you type; use the arrow keys and Enter to open one, or press Enter for the full results page with a filter per record type.
- **Overview:** active vs. total devices per type, active devices and connected clients over time (6 h to 30 d) — *By band* shows 2.4, 5 and 6 GHz side by side on the same scale (access points, active and connected clients per band, plus Bluetooth & LAN), *By type* shows all device types in one chart, currently connected clients with the network they're on, a **System** panel (host CPU use and load average, memory use, database size and free space on the data disk, plus sniffowireless's own CPU and memory), sensor health (packets/s, current channel, errors), and recent events. Every card and row links deeper.
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
- **Statistics:** a **Breakdown** of doughnut charts per radio type (BLE by default; also Wi-Fi clients, Bluetooth classic, access points, LAN). Each shows device type, vendor, brand and OS, and for BLE also the address type (public, random static, private) and the Bluetooth company. The top five values get a slice each, the rest is folded into a gray *Other*. Every slice and legend row has its count and share, and clicking one opens the matching devices. Below that: device types, brands, Wi-Fi generations, estimated age, operating systems, shared probe fingerprints, activity by hour of day, new devices per day, session duration distribution, top vendors, AP channel usage per band, APs and clients per band, SSID table (the 20 most recently seen networks, expandable to 100; BSSIDs, clients, security, last seen), most-connected clients, busiest APs, probed SSIDs, MAC-randomization ratio and event counts. Click any bar or row to jump to the matching devices or events.
- **Events:** the full, filterable event log.
- **Logs** (admins only): the application log, live. New lines stream in as they happen. You can:
  - filter by level, source module or text, pause, follow or wrap lines
  - download what's shown
  - switch the log level to **Debug** without restarting, e.g. to see why an adapter misbehaves; set it back to Info afterwards

  The last 5,000 lines are kept in memory, and the setup code and API tokens are masked.
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
  - **DFS / radar:** radar hits per DFS channel, channels closed right now, every channel switch seen and the access points currently on DFS channels (see [DFS / radar](#dfs--radar))

  Airtime is estimated from frame lengths and PHY rates, so treat it as relative.
- **Settings:**
  - account (password), users, my networks, ignore list, sensors
  - notification channels, weekly report, detection thresholds, API tokens

### Tables and phones

Every table can be sorted by clicking a column header (click again to reverse); the choice is remembered while you stay on the page, also when the table refreshes. The device list sorts on the server, so it sorts all devices, not just the visible page.

On a phone the sidebar becomes a top bar with search and a menu button, cards sit two per row, wide tables scroll sideways and dialogs use the full width.

### Appearance

Admins can change the look under **Settings → Appearance**: the app name, the default **time format** (automatic from the browser language, 24-hour or 12-hour; also used in notifications and the weekly report), the icon (a few built-in glyphs or an uploaded square PNG/JPEG/WebP up to 256 kB, also used as the browser-tab icon) and the colours of surfaces, text, device types and status. Presets (*Slate*, *Forest*, *High contrast*) are a starting point; changes preview immediately and apply to everyone, including the sign-in page, once saved. *Reset to default* brings back the stock dark palette. The appearance is part of configuration backups; an uploaded icon is included in full backups.

Each user can override the time format for their own browser under **Settings → Account → Display**.

### Ignore list

Under **Settings → Ignore list** an admin can drop these before anything is stored:
- devices, by MAC
- whole vendor prefixes, e.g. a smart-plug brand
- networks, by SSID, optionally including every client connected to them

Ignored traffic never reaches the database, the UI or alerts. Tick *Also delete data already stored* to purge existing history for matching devices. The page shows how many stored devices match before you save.

### Choosing networks

The **My networks**, **Investigations** and **Ignore list** settings share a network picker (*Choose networks…*). It lists every SSID sniffowireless has seen in the last 90 days with:
- its access points, connected clients and the devices that looked for it
- security and when it was last seen
- whether it is already one of yours, ignored or under investigation

Search it, tick networks and apply. Networks that are only *looked for* by devices (never broadcast nearby) can be included with a checkbox, and a name that hasn't been seen yet can be typed in.

### Networks

**Networks** (sidebar under Wi-Fi) lists every SSID seen: broadcast nearby, only looked for by devices, or both. Each shows its access points, clients, devices looking for it, security, bands, best signal and last seen, plus tags if it's yours, ignored or investigated. Click a network for its dossier: a timeline, every access point broadcasting it, connected devices, devices that looked for it, and events. It's the same view as for investigated networks, and **Investigate** adds it to that list.

### Bluetooth ↔ Wi-Fi matching

Phones, tablets and laptops have both radios, so sniffowireless sees them twice. **Matching** (sidebar under Devices) guesses which Bluetooth address belongs to which Wi-Fi address from the last 7 days. It weighs:
- being present at the same minutes, and arriving and leaving together
- signal strength rising and falling together
- adjacent hardware addresses (vendors usually allocate both next to each other)
- similar names, e.g. Bluetooth "Sam's iPhone" and DHCP hostname `Sams-iPhone`
- the brand: the same brand counts for a pair, a different known brand counts strongly against

Earbuds, watches, tags and bikes are left out: they move with a phone but are separate devices. Click **Link** to confirm a pair, or **Not the same** to hide it for good. Linked devices share their group and "known" status. Each phone, tablet or laptop page also has a **Same device, other radio** panel with its link or best candidates. Phones rotate their Bluetooth addresses, so a link may need renewing.

### Networks under investigation

Put SSIDs you want to keep an eye on under **Settings → Investigations**: an unknown network that appeared nearby, a suspected rogue hotspot, or a network one of your devices keeps joining. Add a note on why. You can also click **Investigate** on any network's dossier; open one from search or from an access point's page (*dossier →*). sniffowireless then records:

| Event | When |
|---|---|
| *Investigated network on the air* | an access point starts broadcasting the name, including a KARMA-style hotspot that rotates through names |
| *Device joined an investigated network* | a device connects to it |
| *Device looked for an investigated network* | a device probes for it (at most once per device per 6 h) |

These events feed the alert rule *Networks under investigation*, which is created automatically; attach a notification channel to it under Alerts → Rules. The **Investigations** page (under Wi-Fi) shows one card per network. Each network's **dossier** has:
- a timeline of when its access points were on the air and when devices were connected
- every access point that broadcast it (vendor, channel, security, signal, room)
- the devices that connected to it and those that looked for it
- all related events

### Labels, watch list and groups

On any device page an admin can set a **label** ("Sam's iPhone") and notes, and mark the device:
- **known:** excluded from "unknown device" alerts
- **watched:** included in arrive/leave alerts

A device can also be put in a **group**. *Possibly the same physical device* lists other MACs with the same probe fingerprint (or name) that were never present at the same time, which is typical of MAC rotation. One click adds them to the group.

---

## Alerts & notifications

Events (arrived, left, group arrived/left, new device, connected, roamed, moved room, rogue AP, deauth flood, …) are matched against **rules** (Alerts → Rules). Each rule has:
- the events it reacts to
- which devices it covers: any, watched, unknown, specific MACs, groups, device types, or my networks' access points
- an optional time window (e.g. 23:00–06:00) and weekdays
- a per-device cooldown
- the notification channels to use

These rules are created on first start and only log to the alert history until you attach a channel:
- watched devices arriving or leaving
- security alerts
- unknown devices at night
- networks under investigation
- radar (DFS) on my networks

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

Configure **My networks** first (Settings → My networks), then mark your own access points as **trusted** (Security page, *Trust all listed* on a clean setup). sniffowireless then reports:

| Finding | How it's detected |
|---|---|
| **Rogue / evil-twin AP** | one of your SSIDs broadcast by an untrusted BSSID; *high* when security or vendor differs from your trusted APs or the BSSID is locally administered |
| **Deauthentication flood** | ≥ 25 deauth/disassoc frames within 10 s for one BSSID (configurable) |
| **KARMA-style AP** | one BSSID advertising ≥ 4 different SSIDs within 10 minutes (configurable) |
| **Open / WEP / WPA-TKIP network** | on your own SSIDs |
| **WPS enabled** | WPS element in your AP's beacons |
| **No WPA3** | informational |

| **Unknown tracker following someone** | an AirTag/Find My device, Tile or SmartTag not marked as yours that is present ≥ 80 % of its time together with one person (a "person" group or a known phone) and arrived or left with them at least twice |

Findings can be acknowledged (no repeat alerts) or resolved (they reopen if the condition returns). All detection is passive: sniffowireless never transmits deauths or other attack frames.

### Bluetooth trackers

The Security page lists every tracker tag seen in the last 3 days:
- its type (AirTag / Find My, Tile, SmartTag)
- who it moves with, what share of its time it spends with them, and how often they arrived or left together
- its status: yours, unknown, or **possibly following**

Click **It's mine** for your own tags (keys, bags, the car) and they're ignored from then on. A separated AirTag keeps its Bluetooth address for up to about 24 hours, so a planted tag shows up as "following" within a day of moving with someone. Phones' built-in unknown-tracker alerts complement this, but sniffowireless also covers people without a smartphone and tags that phones don't report.

### Interference

While the sensor hops channels it records each channel's noise floor and retransmission rate. Every 5 minutes, sniffowireless compares the last 10 minutes, minute by minute, with that channel's own 24-hour baseline. Two or more minutes of **+6 dB noise**, or retries ≥ 30 % and double the normal rate while the channel isn't busy, open an **interference episode**. The episode is classified as:
- *Microwave oven likely:* a short burst centred on channels 6–13
- *Broadband*, *narrowband* or *persistent* 2.4 GHz interferer (video senders, baby monitors, cordless phones, faulty power supplies)
- *Non-Wi-Fi interference on 5 GHz:* radar, video links

Episodes are listed on the **Channels** page and can trigger alerts (event type *Radio interference episode*). Detection needs a day of measurements as a baseline. Adapters that don't report a noise level are judged on retransmissions only.

### DFS / radar

5 GHz channels 52–144 are shared with weather, airport and military radar. An access point on one of these **DFS** channels has to listen for radar; when it hears it, it must leave the channel within seconds and stay away for 30 minutes. Most access points warn their clients first with a **Channel Switch Announcement** (CSA) in their beacons. sniffowireless reads these from every beacon it hears, along with each access point's channel, and records:

| Event | When |
|---|---|
| *Access point announced a channel switch* | a beacon carries a (extended) CSA |
| *Access point changed channel* | an access point is seen on a new channel several times in a row |
| *Radar on a DFS channel* | the switch or move is away from a DFS channel: radar is the likely cause |

Neighbours' access points count too: radar is a property of the location, so their hits tell you which channels to avoid. The **Channels** page shows radar hits per DFS channel, channels that are closed right now, the switch history and the access points currently on DFS channels. The alert rule *Radar (DFS) on my networks* is created automatically; it fires for your own access points (Settings → My networks). If your own access point keeps getting pushed off a DFS channel, pick a non-DFS channel (36–48 or 149–165) or one without hits.

Requires a sensor that hops over (or sits on) the DFS channels in `WIFI_CHANNELS`. A move is only seen while sniffowireless hears the access point both before and after it.

---

## Ethernet monitoring

Set `ETH_INTERFACES` to one or more wired interfaces and sniffowireless listens passively, without sending anything.

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

| Setup | What sniffowireless sees |
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

Packets are decoded in Python. Header parsing is a fast path, but a Raspberry Pi 4 handles roughly a few tens of thousands of packets per second, which is fine for home and small-office links. Watch the sensor's pkt/s and the *dropped* counter on the overview. Remote sensors (`SNIFFOWIRELESS_MODE=sensor`) support `ETH_INTERFACES` too.

**Privacy:** traffic and DNS logging reveal a lot about people's behaviour. Only monitor networks you're responsible for, tell the people using them, and keep `RETENTION_DAYS` short. Payloads are never stored; only byte counts, peers, ports and queried names are.

---

## Zigbee & 802.15.4

Set `ZIGBEE_DEVICES` to a USB coordinator stick and sniffowireless adds a **Zigbee & 802.15.4** page. sniffowireless works out the firmware by asking the stick, since the USB chip doesn't reveal it.

```bash
ls /dev/serial/by-id/          # find the stick's stable path
ZIGBEE_DEVICES=/dev/serial/by-id/usb-...
```

| Firmware | Example sticks | Network scan | Channel interference | Passive listening |
|---|---|---|---|---|
| Silicon Labs EZSP | Sonoff ZBDongle-E, Home Assistant SkyConnect / ZBT-1 | Yes | Yes | If the firmware includes `mfglib` |
| TI Z-Stack | Sonoff ZBDongle-P, CC2652, CC2531 | Yes | No | No |
| deCONZ | ConBee II | No | No | No |

**Passive listening** runs between network scans. It uses the firmware's manufacturing test library (`mfglib`) in receive-only mode, so no reflashing is needed if the firmware includes it; if it doesn't, the sensor shows a warning and keeps scanning. It hears other 802.15.4 systems as well as Zigbee, and shows frames per channel, PAN IDs, short and long addresses, frame types, signal strength and whether frames are encrypted at the radio layer.

**The stick is left as it was.** sniffowireless never transmits a frame of its own and never writes the stick's stored settings. Silicon Labs sticks do get a firmware restart around each listening period, which keeps their stored data. Z-Stack tools usually widen a stick's channel list by rewriting it; sniffowireless doesn't, so a stick set to specific channels may miss networks elsewhere, and the sensor says so.

**Limits:**

- Protocol labels ("Looks like Zigbee", "Looks like Thread / 6LoWPAN") are guesses from unencrypted fields. Anything else stays "Unknown protocol" or "Encrypted, protocol unknown". There are no labels for specific products, such as Aperio locks, because no verified signature for them is built in.
- Encrypted contents stay hidden, and frames with radio errors are dropped.
- A network scan only reaches routers and coordinators. Battery devices appear only if they transmit while the stick is on their channel, so a hopping sensor easily misses them: set `ZIGBEE_CHANNELS` to one channel to watch them.
- A short address only means something within its PAN, and it can change if a device rejoins.
- A vendor shown with a question mark comes from a long address or extended PAN ID, and many coordinators pick those at random.
- This has only been run against simulated sticks so far. Real USB behaviour, and whether a given firmware includes `mfglib`, are unproven.

**Connecting the stick:**

- Only one program can use a stick at a time. Stop Zigbee2MQTT, ZHA or similar first; that network is offline while the stick is here. If you have a spare stick, use that.
- `privileged: true` exposes the devices present when the container starts, so restart the container after plugging the stick in or replugging it.
- With [less privilege](#less-privilege), pass it explicitly with `--device /dev/serial/by-id/usb-...`.
- On Ubuntu, `brltty` can claim CP210x and CH340 sticks, making the port vanish. Remove it if the stick doesn't show up.

Remote sensors (`SNIFFOWIRELESS_MODE=sensor`) support `ZIGBEE_DEVICES` too.

---

## Multiple sensors & the map

Run extra sensors, for example a Raspberry Pi with a USB Wi-Fi adapter in another room, and send everything to one server:

1. On the server: **Settings → Sensors → Add remote sensor**, then give it a name and room. You get a token and a ready-made `docker run` command.
2. On the sensor machine: connect the adapters as described above, then run that command (build or copy the image first). It's the same image with `SNIFFOWIRELESS_MODE=sensor`, `SERVER_URL` and `SENSOR_TOKEN`:
   ```bash
   docker run -d --name sniffowireless-sensor --restart unless-stopped --network host --privileged \
     -e SNIFFOWIRELESS_MODE=sensor -e SERVER_URL=http://192.168.1.10:8080 -e SENSOR_TOKEN=sniffowireless_... \
     -e WIFI_INTERFACES=wlan1 -e BT_DEVICES=hci0 sniffowireless:latest
   ```
   The sensor buffers and retries if the server is unreachable, and corrects small clock differences.
3. **Map → Edit layout:** upload a floor plan (PNG, JPEG, WebP or SVG) and drag each sensor to where it really is.

Every device gets a **room** (the sensor that hears it strongest, with 4 dB hysteresis so it doesn't flicker) and a "moved" event when that changes. It also gets an approximate **position**: the signal-weighted average of the three strongest sensors. With one sensor, devices are drawn in a ring around it by signal strength. Room-level accuracy is realistic with a sensor per room. Exact positions are not; walls, bodies and phone orientation easily change the signal by 10 dB.

### Wi-Fi channels from the web UI

**Settings → Wi-Fi channels** (admin) lists this server and every remote sensor with its Wi-Fi adapters, which bands each can tune, and the channels it listens on right now. Per sensor you can set:

- **Channels:** the same syntax as `WIFI_CHANNELS`, with buttons for the presets (default, 2.4 GHz, 5 GHz common / all, 6 GHz, everything). With several adapters the list is split between them, and each channel only goes to an adapter that can tune it.
- **Per adapter:** a list for just one adapter (a single channel locks it to that channel, with no hopping).
- **Regulatory domain** (needed for 6 GHz) and the **time on each channel**.

Saving applies **at once** on this server, with no restart. A remote sensor gets the settings back in the answer to its next upload (a few seconds), applies them while it runs, and reports which version it runs, so the page shows *waiting for the sensor…* and then *applied*. If a sensor is offline, the settings are kept and applied when it reconnects.

Anything left empty stays as that sensor's own configuration (`WIFI_CHANNELS`, `WIFI_CHANNELS_<iface>`, `WIFI_REGDOMAIN`, `WIFI_HOP_INTERVAL`) says, and **Back to the sensor's own settings** removes everything you set. A saved setting wins over the environment, until you remove it. A bare `5` or `6` on its own means that whole band, so write `2g:6` for 2.4 GHz channel 6.

The sensor itself must run a version that has this feature; the page says *sensor software too old* for one that doesn't, and its channels then keep coming from its environment.

---

## Backup & restore

**Settings → Backup**:

- **Configuration backup (JSON):** includes:
  - settings, my networks and the ignore list
  - labels, groups and alert rules
  - notification channels (secrets only if you tick the box)
  - sensors, without their tokens: re-create those
  - users, as password hashes

  It contains no measurement history and is small. When you restore it you **choose which parts** to bring back (a list with how much of each the file holds); those replace what is set now and apply immediately, which makes it handy for moving to a new server or putting a configuration under version control.
- **Full backup (`.tar.gz`):** all data: the whole database (history, sessions, traffic, settings, users, API tokens), the floor plan and icon, and the handshake captures. It's taken with SQLite's online backup, so it's consistent while sniffowireless keeps capturing. *Back up now* writes one to `data/backups/`, and **daily scheduled backups** with retention can be switched on.
- **Restore a full backup:** pick one from the list or upload a file. sniffowireless checks the archive (format, safe paths, database integrity), shows what it holds, and asks what to restore:
  - **Everything** replaces the whole database with the backup's.
  - **Only what I choose** restores just the parts you tick and leaves the rest as it is: settings, device labels & links, groups, alert rules, notification channels, remote sensors, users, API tokens, device history, security findings & alert log, LAN / Zigbee / channel data, floor plan & icon, and handshake captures. Labels and groups, and alert rules and notification channels, refer to each other, so restore them together (links to anything left out are cleared rather than left dangling), and restoring *Users* never leaves you without an account.

  Either way it stages the restore and restarts; on startup it applies it, keeping the previous database as `data/backups/pre-restore-….db`. The restart relies on Docker's restart policy, which the compose file and the `docker run` example set (`restart: unless-stopped`).

Copy `data/backups` off the machine as well, e.g. with a nightly `rsync`, since a backup on the same disk doesn't survive a dead disk.

---

## Prometheus & Grafana

`GET /metrics` serves Prometheus metrics, including:
- devices active by kind and type
- clients per AP and per SSID
- presence and signal of watched or labelled devices, and group presence
- events per type, open findings by severity
- channel airtime and retry ratios, radar hits per DFS channel (`sniffowireless_dfs_radar_24h`) and DFS events (`sniffowireless_dfs_events_total`)
- sensor frames/s, and store queue/drops

Create a token with scope `metrics` and scrape with it:

```yaml
scrape_configs:
  - job_name: sniffowireless
    authorization: { type: Bearer, credentials_file: /etc/prometheus/sniffowireless_token }
    static_configs: [{ targets: ["sniffowireless-host:8080"] }]
```

`contrib/monitoring/` holds a ready-to-run Prometheus + Grafana stack with a provisioned **sniffowireless** dashboard:

```bash
echo -n "sniffowireless_<your metrics token>" > contrib/monitoring/sniffowireless_token
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
| `GET /api/status` | Sensor and store health, host CPU / memory, database and disk size |
| `GET /api/appearance` · `PUT /api/appearance` · `POST`/`DELETE /api/appearance/icon` | App name, icon and colours (read without login; changes admin only) |
| `GET /api/export/devices.csv`, `/api/export/sessions.csv?days=7` | CSV export |
| `GET /api/search?q=&section=&limit=` | Search all records (devices, groups, networks, probes, dns, events, alerts, findings, sensors) |
| `GET /api/matching` · `GET /api/devices/{mac}/matches` · `POST /api/links` · `DELETE /api/links/{a}/{b}` | Bluetooth↔Wi-Fi match suggestions, per-device matches, and confirming/rejecting/removing a link (admin) |
| `GET /api/ssids?q=` | All seen SSIDs with access points, clients, devices looking for them, and mine/ignored/investigated flags |
| `GET /api/investigations` · `GET /api/investigations/{ssid}` · `PUT /api/settings/investigate` | Networks under investigation, per-network dossier, and the list itself (admin) |
| `GET /api/groups`, `/api/groups/{id}` | Groups and combined presence |
| `GET /api/alerts`, `/api/alert-rules` | Alert history and rules |
| `GET /api/security` | Findings, my-network BSSIDs, security events |
| `GET /api/channels?hours=24` | Channel survey and recommendations |
| `GET /api/mynet?days=7` | Health of my networks |
| `GET /api/map`, `/api/sensors` | Device rooms/positions, sensors |
| `GET /api/reports/occupancy?days=7` | Occupancy report data |
| `GET /api/lan?hours=24` | LAN overview: devices online, throughput, top talkers, destinations, services, DNS, DHCP servers |
| `GET /api/devices/{mac}/lan?hours=24` | Device traffic, peers and DNS lookups |
| `GET /api/interference?days=7` | Interference episodes |
| `GET /api/dfs?days=7` | Radar hits per DFS channel, channel switch history and access points on DFS channels |
| `GET /api/trackers` | Tracker tags and who they move with |
| `GET /api/backup/config` · `POST /api/backup/config` | Download / restore the configuration (admin); `POST /api/backup/config/inspect` lists what a file holds, and `?sections=a,b` restores only those parts |
| `POST /api/backup/full` · `GET /api/backup/list` · `GET /api/backup/files/{name}` | Create, list and download full backups (admin) |
| `GET /api/backup/files/{name}/sections` · `POST /api/backup/inspect` | List what a stored / uploaded full backup holds, per section (admin) |
| `POST /api/backup/restore-selected` | Restore a stored (`source`: its name) or just-inspected (`"upload"`) backup, all (`"sections": "all"`) or only the listed sections, then restart (admin) |
| `GET /api/channel-settings` · `PUT` / `DELETE /api/channel-settings/{target}` | Wi-Fi channel settings of this server (`local`) or a remote sensor (its id), with the adapters each reports (admin) |
| `POST /api/backup/files/{name}/restore` · `POST /api/backup/restore` | Restore a whole stored / uploaded full backup, then restart (admin) |
| `GET /api/logs?after=` · `GET /api/logs/stream` · `PUT /api/logs/level` | Recent log lines, live log stream (Server-Sent Events) and runtime log level (admin) |
| `GET /metrics` | Prometheus metrics |
| `POST /api/ingest` | Remote sensors push observations here (sensor token) |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `cp .env.example .env` seems to do nothing | It worked: `cp` is silent and `.env` is hidden. Check with `ls -a` or `cat .env`. |
| Settings in `.env` are ignored | `.env` must be in the `sniffowireless` folder next to `docker-compose.yml`, and you have to run `docker compose up -d` again after editing it. `docker compose config` shows the values compose actually uses. |
| `interface wlan1 not found` | Check `iw dev` on the host, make sure the container uses `network_mode: host`, and pin the name with udev. |
| `driver refused monitor mode` | The chipset/driver doesn't support it (common for onboard Broadcom and many Realtek chips with in-kernel drivers). Use an adapter from the table above. |
| `Socket … failed with '[Errno 100] Network is down'`, then the adapter shows `capture … stopped` | The interface went down while sniffowireless was listening: the adapter was reset or briefly lost its USB connection, something else took it down, or it is blocked by rfkill. The sensor reports it and retries every 10 seconds, and says why if the link can't come back up (for example `RF-kill`). Check `ip -br link`, `rfkill list` and `dmesg \| tail` on the host, and see [step 2](#2-keep-networkmanager--wpa_supplicant-away-from-it) if NetworkManager keeps touching it. |
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
| Remote sensor shows offline | Check `docker logs sniffowireless-sensor` on the sensor; `SERVER_URL` must be reachable from it and the token must match the sensor. |
| Everyone is in the same room on the map | You need at least two sensors with room names; one sensor can only tell distance. |
| LAN page shows devices but no internet traffic | The interface only sees broadcasts and its own traffic. Connect it to a mirror/SPAN port or TAP (see [Ethernet monitoring](#ethernet-monitoring)). |
| `ETH_INTERFACES` error "not found" | Use the host's interface name (`ip -br link`), and run with `network_mode: host`. |
| No DNS names | Devices use DNS-over-HTTPS/TLS (common in browsers, Android "Private DNS", iCloud Private Relay); only plain DNS on port 53 is visible. |
| No interference episodes ever | It needs ~24 h of channel measurements first. Adapters without noise reporting only detect retry anomalies. |
| My own AirTag shows as "possibly following" | Click **It's mine** on the Security page (or mark the device as known). |
| Full restore didn't come back | The container needs a restart policy (`restart: unless-stopped`); otherwise start it again. The previous database is in `data/backups/pre-restore-*.db`. |
| `dropped` counter rising | The host is too slow for the frame rate. Lower the number of channels or use fewer adapters. |

---

## Development

```bash
# run tests inside the image
docker build -t sniffowireless . && docker run --rm -v "$PWD/tests:/app/tests" sniffowireless \
  sh -c "pip install -q pytest httpx && python -m pytest -q tests"

# run locally (Python 3.11+; capture needs root)
pip install -r requirements.txt
DEMO_MODE=1 DB_PATH=./data/sniffowireless.db python -m sniffowireless
```

Layout:

```
sniffowireless/
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
  zigbee_radio.py  USB Zigbee sticks: Z-Stack and EZSP/ASH protocols, stick detection, 802.15.4 frame decoding
  zigbee.py     Zigbee sensor thread, networks / radios / channel storage and API
  interference.py  non-Wi-Fi interference episodes from the channel survey
  dfs.py        DFS / radar detection from channel switch announcements and channel changes
  trackers.py   unknown tracker-tag ("following") detection
  backup.py     configuration / full backups, staged restore, scheduler
  channels.py   Wi-Fi channel settings changed from the web UI, applied to local adapters and pushed to remote sensors
  logs.py       in-memory log buffer, live log stream, runtime log level
  appearance.py admin-customisable app name, icon and colours
  sysinfo.py    host CPU / memory, database and disk figures for the overview
  investigate.py  networks under investigation (events, dossiers) and the SSID catalogue for pickers
  matching.py   Bluetooth ↔ Wi-Fi same-device matching and links
  reports.py    occupancy analytics and weekly email
  metrics.py    Prometheus endpoint
  web.py        FastAPI app and device/statistics API
  demo.py       synthetic data generator
  static/       single-page UI (vanilla JS + Chart.js): app.js, views.js, lan.js, zigbee.js, extras.js, login.html
contrib/monitoring/  Prometheus + Grafana stack and dashboard
scripts/configure.sh  interactive helper that detects adapters and writes .env
tests/          parser, session, auth, alert, security, survey, location and report tests
```

---

## Legal

Passively receiving radio traffic is legal in many places, but recording and keeping identifiers of other people's devices can fall under privacy law (e.g. the GDPR in the EU). Only monitor environments you are responsible for, keep retention short, and don't use this to track individuals.
