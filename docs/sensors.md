[← Back to the README](../README.md)

# Multiple sensors & the map

Run extra sensors, for example a Raspberry Pi with a USB Wi-Fi adapter in another room, and send everything to one server:

1. On the server: **Settings → Sensors → Add remote sensor**, then give it a name and room. You get a token and a ready-made `docker run` command.
2. On the sensor machine: connect the adapters as described above, then run that command (it pulls the [published image](deploy.md#prebuilt-image); to build it yourself instead, use `sniffowireless:latest` as the image). It's the same image with `SNIFFOWIRELESS_MODE=sensor`, `SERVER_URL` and `SENSOR_TOKEN`:
   ```bash
   docker run -d --name sniffowireless-sensor --restart unless-stopped --network host --privileged \
     -e SNIFFOWIRELESS_MODE=sensor -e SERVER_URL=http://192.168.1.10:8080 -e SENSOR_TOKEN=sniffowireless_... \
     -e WIFI_INTERFACES=wlan1 -e BT_DEVICES=hci0 ghcr.io/banaanga/sniffowireless:latest
   ```
   The sensor buffers and retries if the server is unreachable, and corrects small clock differences.

   A sensor with Wi-Fi, Bluetooth and a [LoRa](lora.md#lora-meshtastic-meshcore-lorawan) receiver (a Heltec V3 flashed with the LoRa firmware) looks like this. Pass the LoRa board with `--device` and the plain device name; pull the image first, as an older cached `latest` has no LoRa support. Mind that no line in a multi-line command may be empty or end in spaces after the `\`:
   ```bash
   docker pull ghcr.io/banaanga/sniffowireless:latest
   docker run -d --name sniffowireless-sensor --restart unless-stopped --network host --privileged \
     -e SNIFFOWIRELESS_MODE=sensor -e SERVER_URL=http://192.168.1.10:8080 -e SENSOR_TOKEN=sniffowireless_... \
     -e WIFI_INTERFACES=wlan1 -e BT_DEVICES=hci0 -e WIFI_CHANNELS=default,6ghz \
     --device /dev/ttyUSB0 -e LORA_DEVICES=/dev/ttyUSB0 -e LORA_REGION=EU868 \
     ghcr.io/banaanga/sniffowireless:latest
   ```
   `docker logs sniffowireless-sensor` should show `sniffer answered (PONG)`.
3. **Map → Edit layout:** upload a floor plan (PNG, JPEG, WebP or SVG) and drag each sensor to where it really is.

The **Sensors** panel on the Overview lists every interface of this server and of each remote sensor with a status dot: green *working*, amber *needs attention* (a warning, such as 6 GHz being blocked by the regulatory domain, or an error the sensor is already retrying), red *error*, and grey *offline*. A **Sensor load** panel below it shows the load average (per core) and the memory in use of each remote sensor's machine, with a bar that turns amber from 80% and red from 95%, plus the CPU use, the memory sniffowireless itself uses and the free disk space; the same figures are on *Settings → Sensors* (*Load · memory*). They come with every upload, so a silent sensor shows *offline* instead of its last values. A badge in the panel header sums it up, and the pill at the bottom of the menu follows it. What you see is what the sensor reported in its latest upload, so an error disappears as soon as the sensor reports that it is gone. A sensor that has sent nothing for 90 seconds shows as *offline* with how long it has been quiet, and counts as down in the Prometheus `sniffowireless_sensor_up` metric.

Every device gets a **room** (the sensor that hears it strongest, with 4 dB hysteresis so it doesn't flicker) and a "moved" event when that changes. It also gets an approximate **position**: the signal-weighted average of the three strongest sensors. With one sensor, devices are drawn in a ring around it by signal strength. Room-level accuracy is realistic with a sensor per room. Exact positions are not; walls, bodies and phone orientation easily change the signal by 10 dB.

## Wi-Fi channels from the web UI

**Settings → Wi-Fi channels** (admin) lists this server and every remote sensor with its Wi-Fi adapters, which bands each can tune, and the channels it listens on right now. Per sensor you can set:

- **Channels:** the same syntax as `WIFI_CHANNELS`, with buttons for the presets (default, 2.4 GHz, 5 GHz common / all, 6 GHz, everything). With several adapters the list is split between them, and each channel only goes to an adapter that can tune it.
- **Per adapter:** a list for just one adapter (a single channel locks it to that channel, with no hopping).
- **Regulatory domain** (needed for 6 GHz) and the **time on each channel**.

Saving applies **at once** on this server, with no restart. A remote sensor gets the settings back in the answer to its next upload (a few seconds), applies them while it runs, and reports which version it runs, so the page shows *waiting for the sensor…* and then *applied*. If a sensor is offline, the settings are kept and applied when it reconnects.

Anything left empty stays as that sensor's own configuration (`WIFI_CHANNELS`, `WIFI_CHANNELS_<iface>`, `WIFI_REGDOMAIN`, `WIFI_HOP_INTERVAL`) says, and **Back to the sensor's own settings** removes everything you set. A saved setting wins over the environment, until you remove it. A bare `5` or `6` on its own means that whole band, so write `2g:6` for 2.4 GHz channel 6.

The sensor itself must run a version that has this feature; the page says *sensor software too old* for one that doesn't, and its channels then keep coming from its environment.

### LoRa bands and Zigbee channels from the web UI

**Settings → LoRa bands** and **Settings → Zigbee** work the same way as Wi-Fi channels: they list this server and every remote sensor with its boards or sticks, apply at once on the server, reach a remote sensor with its next upload (*waiting for the sensor…*, then *applied*), keep what is left empty at the sensor's own environment settings, and say *sensor software too old* for a sensor that needs updating. See [LoRa](lora.md) and [Zigbee](zigbee.md) for what each page lets you choose.

### Logs of remote sensors

**Logs** (admin) has a tab for *This server* and one per remote sensor. A sensor sends the log lines it has not sent yet with every upload (up to 200 at a time) and the server keeps the last 2,000 per sensor in memory, so they are gone after a server restart and are removed with the sensor. A dot shows whether the sensor is online. The sensor's log level is its own `LOG_LEVEL` (the level selector only exists on the server's tab); the lines are the same ones `docker logs sniffowireless-sensor` shows. Like the server's own log they can contain device names and SSIDs, and the usual redaction of tokens and setup codes applies on both ends. A sensor needs the image from the release that added this before its tab fills up.
