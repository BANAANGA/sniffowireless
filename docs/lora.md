[← Back to the README](../README.md)

# LoRa: Meshtastic, MeshCore, LoRaWAN

A **Heltec WiFi LoRa 32 V3** (ESP32-S3 + SX1262) flashed with the receive-only firmware in [`firmware/lora-sniffer`](../firmware/lora-sniffer) listens on LoRa bands and the server works out what it heard. The **LoRa** page shows packets per protocol over time, every node address heard, and the latest packets with their type, hop count and signal.

**What it recognises** (from the unencrypted headers; the one thing it decrypts is the public Meshtastic channel, see below):

| Protocol | What you see |
|---|---|
| **Meshtastic** | Sender and destination node IDs, hop count, relay, MQTT gateway flag, channel hash; on the public channel also text messages, positions, node names and telemetry |
| **MeshCore** | Packet type (advert, text, ack, path, …), route, hops, and for adverts the node name and type (chat, repeater, room, sensor) |
| **LoRaWAN** | Message type, device address, frame counter; join requests show the device EUI |
| **LoRa APRS** | Callsigns and packet type |
| anything else | Shown as *Unidentified LoRa* with size and a "looks like text / random" hint |

Each packet carries a confidence (*sure*, *likely*, *a guess*). A LoRa receiver only hears packets whose **sync word** and **spreading factor / bandwidth** match its settings, so the radio **hops between profiles** (frequency, bandwidth, SF, sync word). Hopping means each profile is heard only part of the time, and a quiet profile is not proof of silence. With a single profile the radio stays put and misses nothing on it. Protocols not in this list (for example IoTNet) show up as unidentified for now; the classifier in `sniffowireless/lora_protocols.py` is built to take more.

**Public Meshtastic channel.** Every Meshtastic device ships with the same published default key (the `AQ==` channel, "LongFast" and the other presets), and channels can also be set up without any encryption. What is sent on those is broadcast to everyone in range by design, so it is **read**: text messages, positions, node names (which name the node in the list), telemetry and waypoints appear on the LoRa page (*Public messages*, a *Position* column with a map link, and a *Detail* column on the latest packets). Only that one published key is tried. Channels with their own key and direct messages (public-key encrypted) stay unreadable and are reported as before. The decoder is `sniffowireless/meshtastic.py` (AES-128-CTR written out in Python, no extra dependency; protobuf `Data`, `Position`, `User`, `Telemetry`, `Waypoint`); the other ports (routing, admin, traceroute, …) are only named.

**Privacy:** apart from the public Meshtastic channel above, only metadata is stored (addresses, types, signal, size): message bodies, raw bytes and shared coordinates of everything else are never written to the database. What was read from the public channel is stored with the packets in the `info` column, follows the LoRa retention setting, is removed by *Settings → Clear data*, and is not included in the CSV exports. Switch it off with **Settings → LoRa bands** or `LORA_DECODE_PUBLIC=0`; new frames are then stored as metadata only (rows already stored stay until they expire or are cleared).

**Choosing what to listen to.** **Settings → LoRa bands** works like *Wi-Fi channels*: per LoRa board of this server and of every remote sensor, pick the profiles to hop over with the buttons (or type the list) and set the time on each profile. Saving applies at once on this server; a remote sensor picks it up with its next upload (status *applied* / *waiting for the sensor*), and what is left empty stays as the sensor's own `LORA_REGION` / `LORA_PROFILES` says. A profile is a frequency, bandwidth, spreading factor, coding rate and sync word. In the list (the same syntax as `LORA_PROFILES`):

- a profile name from the buttons, for example `meshtastic-eu868`, `meshcore-eu868`, `lora-aprs-433`;
- `meshtastic:<EU868|US|ANZ|EU433|ANZ433>[:<preset>]`, for example `meshtastic:eu868:ShortFast`;
- `lorawan:<EU868|EU433|US915|AU915|AS923|IN865|KR920>[:<sf or range>]`, the region's default uplink channels at that spreading factor: `lorawan:eu868` is 868.1, 868.3 and 868.5 MHz at SF7, `lorawan:eu868:7-12` all 18 combinations;
- your own `name=freq/bw/sf/cr/sync[/preamble]`, for example `mine=868.3/125/9/5/0x34`.

**LoRaWAN.** A LoRaWAN device sends on one of its region's channels at the spreading factor its network chose, and the sniffer's radio hears **one channel at one spreading factor at a time**, only uplinks (downlinks use inverted signals and are not heard). The defaults therefore listen to the three EU868 channels (and the first sub-band of US915 / AU915) at SF7, which is where most devices near a gateway are; devices far from their gateway use SF9-SF12, so add `lorawan:eu868:7-12` (18 profiles, one round takes 90 seconds at the default 5 s per profile) when you want to see them, or pick a few. A frame is only called LoRaWAN when it was heard with the public sync word `0x34` and its header fits the specification (message type, version, frame counter, exact join request / accept sizes). Nothing is decrypted: you see message type, device address, frame counter, FPort and, for join requests, the device EUI.

**Setup:**

1. Flash the firmware. This replaces whatever is on the board. Easiest is **Settings → LoRa flasher**: plug the board into the computer you browse from and click *Select board and flash* (it can save a copy of the current firmware first). It needs a Chromium based browser and a secure page, so `https://` or `http://localhost` (for example via `ssh -L 8080:localhost:8080 your-server`). Or build and flash from a terminal, see [`firmware/lora-sniffer/README.md`](../firmware/lora-sniffer/README.md).
2. Plug the board into the machine that runs the container and note its path: `ls /dev/serial/by-id`.
3. Set `LORA_DEVICES` to the board and `LORA_REGION=EU868` (or `US915`, `ANZ`), then restart the container. `privileged: true` only exposes the devices present when the container starts, so restart it after plugging the board in. **Inside a container the `/dev/serial/by-id/...` names may be missing** even though they exist on the host (the error is `could not open port ... No such file or directory`). Pass the board explicitly with `--device` and use the plain name: `--device /dev/ttyUSB0` and `LORA_DEVICES=/dev/ttyUSB0` (`ls -l /dev/serial/by-id/` on the host shows which `ttyUSB` number the board is). That name can change if you replug the board or add another USB serial device. With docker compose, add `devices: ["/dev/ttyUSB0"]` to the service.

Remote sensors (`SNIFFOWIRELESS_MODE=sensor`) support `LORA_DEVICES` too; see the example under [Multiple sensors & the map](sensors.md#multiple-sensors--the-map).

**Names and watches.** On the LoRa and Zigbee pages an admin can give a node or radio a name (the ☆ button) and **watch** it: when it has not been heard for the number of minutes chosen (default 60), the event *Watched LoRa node / Zigbee radio went silent* is raised, and *is back* when it returns. A rule for both is created (without notification channels: add one under Alerts → Rules). The radio hops between profiles and hears a node only part of the time, so choose a time well above how often the node transmits. A node never heard raises nothing. **Exports:** the LoRa and Zigbee pages have CSV buttons (nodes and packets / radios and networks, no message contents).

**Channel use.** For each listening profile the LoRa page shows the airtime of the frames heard and an estimate of how busy the channel is: airtime heard divided by the time the radio listened on that profile (a hopping radio listens to each profile `1/N` of the time, so the figure is an estimate, and other senders you can't hear add to it). Airtime is calculated from the frame size, spreading factor and bandwidth (Semtech's formula) with the coding rate of the profile and the preamble Meshtastic and MeshCore send (16).

**Firmware version.** The board reports its firmware version; the LoRa page says when it is older than the version this server ships, and *Settings → LoRa flasher* updates it. Boards flashed before this existed count as version 1.

**Updating a board without a browser.** For a board that is plugged into the server or into a remote sensor, use **Update firmware…** next to the board in the overview's *Sensors* panel or on **Settings → Sensors** (admins only). The server or sensor writes the firmware it ships straight over the board's USB serial port: the DTR/RTS lines put the board into its bootloader, the image is written and checked by MD5, and the board restarts and is picked up again. It takes about a minute, and capture on that board stops meanwhile. A remote sensor downloads the image from the server with its own token and starts with its next upload, so the sensor needs this version of sniffowireless; older sensors ignore the request. It works for the Heltec V3 (and boards wired the same); the container needs access to the serial device, as for capturing. If an update fails the board stays in its bootloader and can simply be flashed again, from here or with the web flasher.

**Notifications and monitoring.** LoRa and Zigbee numbers are in the weekly report, in Prometheus (`sniffowireless_lora_nodes_active`, `sniffowireless_lora_packets_1h`, `sniffowireless_lora_airtime_seconds_1h`, `sniffowireless_zigbee_radios_active`, …) and, when MQTT is on (Settings → MQTT), the events above are published under `<prefix>/radio/<event type>` (not retained). **Settings → Sensors → Add remote sensor** has an optional LoRa board field that adds the `--device` and `LORA_*` options to the command it generates.

**Profiles.** `LORA_REGION` picks sensible defaults (EU868: Meshtastic LongFast on 869.525 MHz and MeshCore on 869.618 MHz; US915: Meshtastic LongFast on 906.875 MHz; ANZ: Meshtastic and MeshCore narrow). Override with `LORA_PROFILES`, a comma separated list of:

- built-in names: `meshtastic-eu868`, `meshtastic-us`, `meshtastic-anz`, `meshtastic-eu433`, `meshcore-eu868`, `meshcore-au-narrow`, `meshcore-nz-narrow`, `lorawan-eu868`, `lorawan-us915-sb2`, `lora-aprs-433`
- `meshtastic:<region>[:<preset>]` for another Meshtastic region or preset, for example `meshtastic:EU868:MediumFast`
- your own: `name=freq/bw/sf/cr/sync[/preamble]`, for example `mynet=868.1/125/7/5/0x12`

The V3 board covers 863–928 MHz; 433 MHz profiles need a 433 MHz board.

Receive-only: the firmware has no transmit code.
