[← Back to the README](../README.md)

# Troubleshooting

| Symptom | Fix |
|---|---|
| `cp .env.example .env` seems to do nothing | It worked: `cp` is silent and `.env` is hidden. Check with `ls -a` or `cat .env`. |
| Settings in `.env` are ignored | `.env` must be in the `sniffowireless` folder next to `docker-compose.yml`, and you have to run `docker compose up -d` again after editing it. `docker compose config` shows the values compose actually uses. |
| `interface wlan1 not found` | Check `iw dev` on the host, make sure the container uses `network_mode: host`, and pin the name with udev. |
| `no matching manifest for linux/arm/v7` when pulling | The image you pulled was published before 32-bit ARM (Raspberry Pi OS 32-bit) was added: pull a newer release or `edge`, or build it on the Pi itself (`docker build -t sniffowireless:latest .`, see [Without compose](deploy.md#without-compose)). A very old Pi (Zero / 1, `armv6l`) is not supported by the image; use a 64-bit OS on a Pi 3 or newer if you can. |
| `driver refused monitor mode` | The chipset/driver doesn't support it (common for onboard Broadcom and many Realtek chips with in-kernel drivers). Use an adapter from the table above. |
| `Socket … failed with '[Errno 100] Network is down'`, then the adapter shows `capture … stopped` | The interface went down while sniffowireless was listening: the adapter was reset or briefly lost its USB connection, something else took it down, or it is blocked by rfkill. The sensor reports it and retries every 10 seconds, and says why if the link can't come back up (for example `RF-kill`). Check `ip -br link`, `rfkill list` and `dmesg \| tail` on the host, and see [step 2](adapters.md#2-keep-networkmanager--wpa_supplicant-away-from-it) if NetworkManager keeps touching it. |
| Adapter keeps leaving monitor mode | NetworkManager / wpa_supplicant is managing it. See [step 2](adapters.md#2-keep-networkmanager--wpa_supplicant-away-from-it). |
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
| Remote sensor shows offline | It is shown as offline after 90 seconds without an upload. Check `docker logs sniffowireless-sensor` on the sensor; `SERVER_URL` must be reachable from it and the token must match the sensor. |
| Everyone is in the same room on the map | You need at least two sensors with room names; one sensor can only tell distance. |
| LAN page shows devices but no internet traffic | The interface only sees broadcasts and its own traffic. Connect it to a mirror/SPAN port or TAP (see [Ethernet monitoring](ethernet.md#ethernet-monitoring)). |
| `ETH_INTERFACES` error "not found" | Use the host's interface name (`ip -br link`), and run with `network_mode: host`. |
| No DNS names | Devices use DNS-over-HTTPS/TLS (common in browsers, Android "Private DNS", iCloud Private Relay); only plain DNS on port 53 is visible. |
| No interference episodes ever | It needs ~24 h of channel measurements first. Adapters without noise reporting only detect retry anomalies. |
| My own AirTag shows as "possibly following" | Click **It's mine** on the Security page (or mark the device as known). |
| Full restore didn't come back | The container needs a restart policy (`restart: unless-stopped`); otherwise start it again. The previous database is in `data/backups/pre-restore-*.db`. |
| `dropped` counter rising | The host is too slow for the frame rate. Lower the number of channels or use fewer adapters. |
| `could not open port /dev/serial/by-id/…: No such file or directory` (Zigbee or LoRa) | Inside a container the `by-id` names are often missing. Find the plain name on the host (`ls -l /dev/serial/by-id/` shows the `ttyUSB0` it points to), set `ZIGBEE_DEVICES=/dev/ttyUSB0` (or `LORA_DEVICES`) and pass the device in (`--device /dev/ttyUSB0`, or `devices:` in compose). With `privileged: true`, restart the container after plugging the stick in. |
| Zigbee page lists networks but no radios or frames | The stick runs Z-Stack firmware (Sonoff ZBDongle-P, CC2652, CC2531), which can scan but not listen passively. A Silicon Labs stick such as the ZBDongle-E can. See [Zigbee](zigbee.md). |
| Zigbee note "This stick is configured for channel …, so networks on other channels may be missed" | The stick has a narrower channel list stored than 11-26, and sniffowireless never rewrites a stick's settings. Harmless; scans may just miss networks elsewhere. |
| Settings → Zigbee or LoRa bands says *sensor software too old* | That remote sensor runs an image from before the feature. Update it as described in [Updating](updating.md#remote-sensors). |
| LoRa page only ever shows Meshtastic or MeshCore | LoRaWAN needs its profiles in the list: choose your region in Settings → LoRa bands (or set `LORA_REGION`). A board hears one channel and spreading factor at a time, so LoRaWAN uplinks show up slowly. See [LoRa](lora.md). |
