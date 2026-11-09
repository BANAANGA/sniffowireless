# sniffowireless

A self-hosted radio monitor that runs as a single Docker container: **Wi-Fi, Bluetooth, Ethernet, Zigbee and LoRa**. It works like a small Kismet, with one difference: it is built to track **how devices connect over time**. It records which Wi-Fi client was associated with which access point and when, and when phones, wearables and other Bluetooth devices come into and leave range. You drill into all of it from a dark, minimal web UI.

- **Wi-Fi:** passive monitor-mode capture with channel hopping over 2.4, 5 and **6 GHz (Wi-Fi 6E/7)**, on one or more USB adapters
- **Bluetooth:** BLE advertising (including Bluetooth 5/6 extended and LE Audio broadcasts) plus Classic inquiry, over a raw HCI socket
- **Ethernet / LAN:** passive capture; finds devices through ARP, DHCP, mDNS, SSDP and LLDP, and catches rogue DHCP servers and ARP spoofing
- **Zigbee / IEEE 802.15.4:** network scans and (with the right stick) passive listening, with channel interference
- **LoRa:** Meshtastic, MeshCore and LoRaWAN traffic from a receive-only Heltec V3, including the public Meshtastic channel's messages and positions
- **Connectivity history:** presence sessions, Wi-Fi client→AP connections (roaming, deauths) and Bluetooth links, for every device
- **Device identification:** brand, model, type, OS and age from passive evidence, each result with its confidence
- **Alerts and security monitoring:** watched or unknown devices, evil twins, deauth floods, KARMA access points, unknown trackers, interference and DFS radar, delivered via ntfy, Telegram, Discord, webhooks or email
- **Several sensors and a map:** remote Raspberry Pi sensors forward to one server; each device gets a room and a position on your floor plan. Channels and bands of every sensor are set from the web UI.
- **Operations:** login with admin/viewer roles, API tokens, backups and restore, a Prometheus endpoint with a Grafana dashboard, CSV export and a JSON API
- **Demo mode** to try the UI without any radios

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

## Quick start

```bash
git clone https://github.com/BANAANGA/sniffowireless.git && cd sniffowireless
./scripts/configure.sh          # picks your adapters and writes .env (or start with DEMO_MODE=1)
docker compose up -d --build
```

Open **http://<host>:8080** and create the admin account with the setup code from `docker compose logs`. No radios yet? `DEMO_MODE=1 docker compose up -d --build` fills the UI with synthetic data. Details are in [Deploy](#deploy).

## Documentation

| | |
|---|---|
| [Connecting USB adapters](docs/adapters.md) | Wi-Fi and Bluetooth adapters on bare metal, a Pi or a VM: monitor mode, NetworkManager, udev names |
| [Other ways to deploy](docs/deploy.md) | Without compose, Arcane, the prebuilt image, running with less privilege |
| [Updating](docs/updating.md) | The server and the remote sensors |
| [Accounts & access](docs/accounts.md) | Logins, roles, API tokens, security hardening |
| [Using the UI](docs/ui.md) | Pages, tables, appearance, networks, labels, groups and the watch list |
| [Device identification](docs/identification.md) | How brand, model and type are worked out |
| [Alerts & notifications](docs/alerts.md) | Rules, quiet hours, ntfy, Telegram, Discord, webhooks, email |
| [Security monitoring](docs/security.md) | Evil twins, deauth floods, trackers, interference, DFS radar |
| [Ethernet monitoring](docs/ethernet.md) | Where to plug it in and what it learns |
| [Zigbee & 802.15.4](docs/zigbee.md) | Sticks, scanning, passive listening, choosing channels in the UI |
| [LoRa](docs/lora.md) | Meshtastic, MeshCore, LoRaWAN, the receiver firmware, choosing bands in the UI |
| [Multiple sensors & the map](docs/sensors.md) | Remote sensors, floor plan, Wi-Fi channels from the UI |
| [Backup & restore](docs/backup.md) | Manual and scheduled backups, restoring |
| [Prometheus & Grafana](docs/prometheus.md) | Metrics and the ready-made dashboard |
| [API](docs/api.md) | The JSON API and exports |
| [Troubleshooting](docs/troubleshooting.md) | Symptoms and fixes |

---

## How it works

```
 USB Wi-Fi (monitor mode) ──► scapy sniffer + channel hopper ─┐
 USB / onboard Bluetooth ───► raw HCI socket: LE scan + inquiry┤
 Wired interface ───────────► passive capture (ARP, DHCP, DNS…)┤
 USB Zigbee stick ──────────► serial: network scan + capture ──┼─► queue ─► store (SQLite, WAL) ◄── FastAPI ◄── browser UI
 Heltec V3 LoRa receiver ───► serial: packets per band/profile ┤
 Remote sensors ────────────► HTTPS upload of the same data ───┘
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
3. **Add 6 GHz channels.** Use `WIFI_CHANNELS=default,6ghz` (or set it under [Settings → Wi-Fi channels](docs/sensors.md#wi-fi-channels-from-the-web-ui), also for remote sensors), or `all`, which covers 2.4 + 5 GHz + the 6 GHz Preferred Scanning Channels. 6 GHz access points always beacon on one of the 15 PSCs (5, 21, 37 … 229), so `6ghz` finds them with far fewer hops than all 59 channels (`6all`).

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

Optional. See [Zigbee & 802.15.4](docs/zigbee.md#zigbee--802154) for what each kind of stick can do. A Silicon Labs stick such as the Sonoff ZBDongle-E does the most.

### LoRa boards

A **Heltec WiFi LoRa 32 V3** (ESP32-S3 + SX1262) flashed with the receive-only firmware in [`firmware/lora-sniffer`](firmware/lora-sniffer). See [LoRa](docs/lora.md).

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

Open **http://<host>:8080**. On the first visit you create the admin account (see [Accounts & access](docs/accounts.md#accounts--access)). Data is stored in `./data` (`sniffowireless.db` plus an uploaded floor plan). Back up that folder to keep your history.

Try it without hardware:

```bash
DEMO_MODE=1 docker compose up -d --build
```

Demo mode backfills 72 h of synthetic history and keeps generating live data. For a clean real deployment afterwards, delete `./data/sniffowireless.db`.

More: [other ways to deploy](docs/deploy.md) (no compose, Arcane, prebuilt image, less privilege), [updating](docs/updating.md), [accounts & access](docs/accounts.md) and [remote sensors](docs/sensors.md).

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
| `LORA_DEVICES` | *(empty)* | Heltec V3 LoRa receivers flashed with `firmware/lora-sniffer`, by stable path under `/dev/serial/by-id/`. Empty disables LoRa monitoring. |
| `LORA_REGION` | `EU868` | `EU868`, `US915` or `ANZ`: picks the default listening profiles. |
| `LORA_PROFILES` | *(region default)* | Profiles to listen on, see [LoRa](docs/lora.md#lora-meshtastic-meshcore-lorawan). |
| `LORA_HOP_INTERVAL` | `5` | Seconds spent on each profile when there is more than one (minimum 0.5). |
| `LORA_DECODE_PUBLIC` | `1` | Read messages, positions, node names and telemetry on the public Meshtastic channel (`0` keeps addresses and signal only). Also a switch under **Settings → LoRa bands**. |
| `ETH_PROMISC` | `1` | Put the Ethernet interface in promiscuous mode (needed on a mirror/SPAN port). |
| `LAN_SESSION_TIMEOUT` | `900` | Seconds without traffic before a LAN device counts as offline. |
| `BT_ACTIVE_SCAN` | `1` | Active LE scanning (sends scan requests, which gets device names). `0` is fully passive. |
| `BT_EXTENDED_SCAN` | `1` | Use LE extended scanning (and the Coded PHY) when the adapter supports it, so Bluetooth 5 and 6 advertisements and LE Audio broadcasts are seen. `0` forces the legacy scan commands. |
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
| `RESET_2FA_USER` | – | Remove this user's two-factor login at start (lost phone). Remove the variable afterwards. |
| `WEB_USER` / `WEB_PASSWORD` | – | Admin account created/reset on start. If unset, create it in the browser with the setup code from the log. |
| `AUTH_DISABLED` | `0` | `1` disables login completely (trusted networks only). |
| `ALLOWED_HOSTS` | – | Comma-separated host names/IPs the UI may be reached as (DNS-rebinding protection). Empty = any. |
| `TRUSTED_PROXIES` | `127.0.0.1` | Addresses whose `X-Forwarded-*` headers are trusted (your reverse proxy). |
| `SNIFFOWIRELESS_MODE` | `server` | `sensor` = capture only and forward to `SERVER_URL` (see [Multiple sensors](docs/sensors.md#multiple-sensors--the-map)). |
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

More on the Zigbee and LoRa settings: see the [Zigbee](docs/zigbee.md) and [LoRa](docs/lora.md) pages.

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
