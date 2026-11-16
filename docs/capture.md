# Recording and replaying raw frames

Identification rules are written from published frame layouts. To check them against real devices, and to keep samples that later
changes can be tested against, you can record what the radios hear and play it back through the parsers.

## Recording

**Settings → Frame recording** (admins only). Choose the radios and how long, and start. It stops by itself after that time or at
64 MB, whichever comes first; the longest is one hour. Finished recordings are listed there to download or delete (at most 20).

What is recorded, per frame, exactly as the radio delivered it:

| Radio | Recorded |
|---|---|
| Wi-Fi | The frame with its radiotap header. Of **data frames only the headers** are kept, never their contents. |
| Bluetooth | The HCI event from the controller (advertisements, inquiry results). |
| Zigbee / Thread | The 802.15.4 frame, with channel and signal. |
| LoRa | The line the sniffer board printed for a received frame. |

A recording holds **real addresses and device names**, whatever the privacy settings are:

- Recording is refused while MAC address privacy is on.
- Only share a file with people who may see which devices were near you.

**Record on** chooses the radios of this server or those of a remote sensor (the choice appears once there are remote sensors).
A remote sensor hears of the request with its next batch, within a few seconds, and records its own radios. While it records,
it reports how many frames it has; when it is done it sends the file to the server with its own token. The file is listed with
the sensor's name under **From**, and its name ends in the sensor's id (`capture-20261116-101500-office.jsonl.gz`). The
server checks what arrives and writes it again, keeping only what a recording holds. A sensor can only send a recording that
was asked of it.

This needs the sensor to run version 33.2 or newer. An older sensor does not answer the request, and after a minute and a half
the page says so. On such a sensor, or to record from the moment a sensor starts, set `CAPTURE_AT_START=<seconds>` in its
environment instead. That recording stays in `captures/` in the sensor's own data directory; copy it to the server's
`captures/` folder to open it there.

## Inspecting a recording

**Frames** in the menu (admins only), or **Open** next to a recording under Settings → Frame recording. The page is laid out like
Wireshark's:

- **The frame list:** number, time since the first frame, source, destination, protocol, length, signal, channel and a one-line
  summary. Each kind of frame has its own colour: beacons, probes, deauthentications (red), Wi-Fi data, control frames, BLE
  advertisements, Bluetooth classic, Zigbee, Thread and LoRa. It loads more as you scroll; the arrow keys, Page Up/Down,
  Home and End move through it.
- **The decoded fields** of the chosen frame, as a tree you can fold open. The first entry is about the frame itself: when it
  was heard, on which interface, channel and signal. Then each layer:
  - **Wi-Fi:** the radiotap header, the 802.11 header and the tagged elements. Examples are the SSID, rates, RSN (ciphers and
    key management), HT/VHT/HE capabilities and operation, country, BSS load, vendor elements, WMM and WPS (device name, maker,
    model). A frame check sequence is verified when the frame has one.
  - **Bluetooth:** the HCI event. That includes LE advertising reports (legacy and extended) with every AD structure, Apple's
    advertisement types and iBeacon, inquiry results with class of device and the extended inquiry response, and command
    replies.
  - **Zigbee / Thread:** the 802.15.4 MAC header with its security header. Then the Zigbee and Thread beacons (extended PAN
    ID, stack profile, network name), MAC commands, the Zigbee network header and its security header (the payload itself is
    encrypted), and 6LoWPAN.
  - **LoRa:** the sniffer's radio settings. Then the Meshtastic header, LoRaWAN (MHDR, DevAddr, FCtrl, FCnt, FPort, MIC),
    MeshCore and LoRa APRS.
- **The bytes**, in hex and as text. Choosing a field highlights the bytes it was read from. Clicking a byte chooses the
  smallest field that holds it. For LoRa the bytes are the received frame, not the text line the board printed.

**The display filter** works like Wireshark's, with a smaller set of fields. Use a bare word for a radio or a kind of frame:
`wifi`, `ble`, `zigbee`, `thread`, `lora`, `beacon`, `probe`. Compare fields with `==`, `!=`, `>`, `<`, `>=`, `<=` and
`contains`, and combine them with `&&` / `and`, `||` / `or`, `!` / `not` and parentheses. For example:

```text
beacon && rssi > -60
addr == aa:bb:cc:dd:ee:ff
ssid contains "home"
(ble || zigbee) && !ack
channel == 6 && !beacon
```

The fields are `no`, `time`, `radio`, `proto`, `type`, `src`, `dst`, `addr` (source, destination or BSSID), `bssid`,
`info`, `len`, `rssi`, `channel`, `ssid`, `name`, `company`, `sensor`, `pan`, `epid` and `network`. A filter with a mistake
turns red and says what is wrong. The buttons under it are ready-made filters. **Filter** next to the source of a frame shows
only the frames to or from that address.

A big recording is read in the background. The page shows how far reading has got, which can take a minute for the largest
ones on a Raspberry Pi. At most 200,000 frames of one recording are shown.

The page shows the real addresses and bytes, so it cannot be used while MAC address privacy or the anonymised view is on.
Download the file instead, or switch those off first. In demo mode there is a sample recording with one of each kind of frame.

## Replaying

```bash
python -m sniffowireless replay capture-20261112-231500.jsonl.gz
```

Every frame goes through the same parsers and the same store as live capture, into a temporary database that is thrown away
afterwards. It prints how many frames were read per radio and what was found: each device with its identification, each Zigbee /
Thread radio with protocol, role and probable device, and each LoRa node. `--json` prints the same as JSON, for comparing two runs.

Nothing is transmitted and the real database is not touched. The frames are replayed as if heard now, in their recorded order;
the recorded times are not used, so results that depend on time passing (sessions, movement, address-rotation timing) are not
reproduced.

## File format

A gzip file of JSON lines, one per frame: `{"ts", "radio", "src", "raw", ...}`. `raw` is the frame in hex; Wi-Fi lines also carry
`tuned` (the frequency the adapter was on), Zigbee lines `channel`, `rssi` and `lqi`.
