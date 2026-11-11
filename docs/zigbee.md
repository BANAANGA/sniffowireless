[← Back to the README](../README.md)

# Zigbee & 802.15.4

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
- A vendor shown with a question mark comes from a radio's 64-bit (IEEE) address, whose first bytes name the maker. It is a hint. A network's extended PAN ID is **not** used for this: the coordinator chooses it and many (Zigbee2MQTT, ZHA) pick random bytes, so a maker name taken from it would usually be a coincidence. (Versions before 30.5 showed one; it is cleared at the next start.)
- This has only been run against simulated sticks so far. Real USB behaviour, and whether a given firmware includes `mfglib`, are unproven.

**Connecting the stick:**

- Only one program can use a stick at a time. Stop Zigbee2MQTT, ZHA or similar first; that network is offline while the stick is here. If you have a spare stick, use that.
- `privileged: true` exposes the devices present when the container starts, so restart the container after plugging the stick in or replugging it.
- With [less privilege](deploy.md#less-privilege), pass it explicitly with `--device`. Inside a container the `/dev/serial/by-id/...` names may be missing; if the stick isn't found, use the plain name (`--device /dev/ttyUSB0`, `ZIGBEE_DEVICES=/dev/ttyUSB0`) as described for [LoRa](lora.md#lora-meshtastic-meshcore-lorawan).
- On Ubuntu, `brltty` can claim CP210x and CH340 sticks, making the port vanish. Remove it if the stick doesn't show up.

Remote sensors (`SNIFFOWIRELESS_MODE=sensor`) support `ZIGBEE_DEVICES` too.

**Choosing channels in the web UI.** **Settings → Zigbee** works like *Wi-Fi channels* and *LoRa bands*: for this server and for every remote sensor, pick the channels to listen on (11-26) with the buttons or by typing a list like `15,20-25`, set the time on each channel and the time between network scans, or switch passive listening off to keep only network scans. Saving applies at once on this server, within a second or two; a remote sensor picks it up with its next upload (status *applied* / *waiting for the sensor*). Whatever is left empty stays as the sensor's own `ZIGBEE_CHANNELS`, `ZIGBEE_HOP_INTERVAL`, `ZIGBEE_SCAN_INTERVAL` and `ZIGBEE_SNIFF` say, and *Back to the sensor's own settings* removes the override. The stick's device path (`ZIGBEE_DEVICES`) stays an environment setting, and the stick itself is never reconfigured. A remote sensor needs an image with this feature (it reports *sensor software too old* otherwise).
