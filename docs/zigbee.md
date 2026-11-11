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
- Tested on real hardware with one stick: a Sonoff Zigbee 3.0 USB Dongle Plus V2 (EmberZNet 7.4.4.0, EZSP v13): firmware detection, scanning, passive listening and changing the channels from the web interface all worked. Z-Stack and the other firmware have only been run against simulated sticks, and whether a given firmware includes `mfglib` is still something to check on yours.

**Thread (and Matter).** Thread is the IPv6 mesh that many Matter devices use. It runs on the same 802.15.4 radio, so the stick hears it too. What can be seen, and how:

- **Thread-likely frames.** Thread secures every frame at the MAC layer with *security level 5* (encryption plus a 32-bit integrity check) and key mode 1 (data) or 2 (its MLE messages); OpenThread accepts nothing else. Zigbee does not use MAC-layer security at all. So a MAC-secured data or command frame at level 5 with key mode 1 or 2 is labelled *Looks like Thread*; other secured frames stay *Encrypted, protocol unknown*. Unsecured 6LoWPAN frames are labelled Thread as before. It is a strong sign, not proof: another stack could use the same settings.
- **Thread beacons.** A Thread router answers a beacon request with a beacon whose payload is in the clear: protocol ID 3, flags (protocol version, "native commissioner", **joining permitted**), the **network name** (16 bytes) and the **extended PAN ID** (8 bytes), in the layout from OpenThread's source (`mac_beacon.hpp`). When one is heard, the network appears in the Networks table with its name, protocol version and joining flag, a *new network* event is raised, and a network that is accepting new devices raises the same event as an open Zigbee network. The extended PAN ID is shown in the order it is sent (as OpenThread prints it), not reversed like an address.
- **Why beacons are rare.** The stick only listens, so a Thread beacon is heard only when something else (a person joining a device, another scanner) sends a beacon request on that channel. The stick's own network scan reports Zigbee networks only, not Thread ones. So most Thread networks show up as *radios* grouped by PAN, labelled Thread-likely, without a name.
- **What stays hidden.** The contents are encrypted with the network key: no addresses of devices behind a router, no Matter traffic, no names beyond the beacon. Remote sensors report Thread networks too.

On the stick used for testing, 4.5 minutes on all channels gave two Thread-likely secured frames (level 5, key mode 1) and two unsecured 6LoWPAN frames, and no beacon.

**Connecting the stick:**

- Only one program can use a stick at a time. Stop Zigbee2MQTT, ZHA or similar first; that network is offline while the stick is here. If you have a spare stick, use that.
- `privileged: true` exposes the devices present when the container starts, so restart the container after plugging the stick in or replugging it.
- With [less privilege](deploy.md#less-privilege), pass it explicitly with `--device`. Inside a container the `/dev/serial/by-id/...` names may be missing; if the stick isn't found, use the plain name (`--device /dev/ttyUSB0`, `ZIGBEE_DEVICES=/dev/ttyUSB0`) as described for [LoRa](lora.md#lora-meshtastic-meshcore-lorawan).
- On Ubuntu, `brltty` can claim CP210x and CH340 sticks, making the port vanish. Remove it if the stick doesn't show up.

Remote sensors (`SNIFFOWIRELESS_MODE=sensor`) support `ZIGBEE_DEVICES` too.

**Choosing channels in the web UI.** **Settings → Zigbee** works like *Wi-Fi channels* and *LoRa bands*: for this server and for every remote sensor, pick the channels to listen on (11-26) with the buttons or by typing a list like `15,20-25`, set the time on each channel and the time between network scans, or switch passive listening off to keep only network scans. Saving applies at once on this server, within a second or two; a remote sensor picks it up with its next upload (status *applied* / *waiting for the sensor*). Whatever is left empty stays as the sensor's own `ZIGBEE_CHANNELS`, `ZIGBEE_HOP_INTERVAL`, `ZIGBEE_SCAN_INTERVAL` and `ZIGBEE_SNIFF` say, and *Back to the sensor's own settings* removes the override. The stick's device path (`ZIGBEE_DEVICES`) stays an environment setting, and the stick itself is never reconfigured. A remote sensor needs an image with this feature (it reports *sensor software too old* otherwise).

## What the radios list tells you about each radio

Payloads are encrypted, but headers are not, and the radios list uses them:

- **Role (*router* / *end device*).** Judged from behaviour: a radio that **relays frames of others** (the last hop differs from the originator in the Zigbee network header), **sends beacons**, **broadcasts to all routers**, or **answers polls** is a router (or the coordinator). A radio that **polls a parent** (an end device asking for waiting data) and does nothing a router does is a sleepy end device. Hover the tag to see why. Thread encrypts its polls, so there a poll is recognised by its size (a command frame with a 5-byte payload): less certain. A radio that has not been heard doing either shows no role.
- **64-bit address and maker.** The Zigbee network header of a secured frame carries the sender's 64-bit IEEE address in the clear. It is shown under the short address, and its first three bytes name the maker (with a question mark, like other hints; this needs the OUI list, see `MANUF_PATH`). Radios that only ever send frames without that header (end devices that are polled, most Thread traffic) have none.
- **Thread border routers.** A border router (a HomePod, Nest Hub, Apple TV, Home Assistant …) announces its Thread network on the LAN (`_meshcop._udp` over mDNS): network name, extended PAN ID, its own maker and model. When that extended PAN ID matches a network found on the radio, the **Border router** column of the Networks table shows that device (with a link), and the network gets its name if the beacon had none. The border router's maker is not the maker of the network's other devices. The LAN device's page has a *Thread border router* row. Needs the Ethernet sensor to hear mDNS on that network.
- **Matter.** A Matter device waiting to be set up advertises itself over Bluetooth (service `FFF6`): it is shown as a smart-home device with its vendor ID, product ID and discriminator (the numbers are the manufacturer's own, from the Matter registry; no names are looked up). Matter over Wi-Fi and Ethernet shows up through its `_matter._tcp` / `_matterc._udp` mDNS services. A Matter device waiting to be set up cannot be tied to a particular Thread network passively: that link only exists once the device has joined and is encrypted.

What this cannot do: name the maker of a radio that never reveals its 64-bit address; read the cluster or device type (that is inside the encrypted payload); tell a Zigbee light from a Zigbee sensor.
