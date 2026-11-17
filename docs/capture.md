# Recording and replaying raw frames

Identification rules are written from published frame layouts. To check them against real devices, and to keep samples that later
changes can be tested against, you can record what the radios hear and play it back through the parsers.

## Recording

**Settings → Frame recording** (admins only). Choose the radios and how long (one minute unless you choose otherwise, one hour at most), and start. It
stops by itself after that time or at 64 MB, whichever comes first. Finished recordings are listed there to download or delete (at most 20).

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

The **Android app** (sniffowireless-mobile 1.3.0 or newer) records the same way. It can only record its USB adapters: the
MT7921U for Wi-Fi, a USB Bluetooth adapter, a Zigbee stick and a LoRa board. The phone's own Wi-Fi and Bluetooth only pass
on what Android already decoded, not the frames.

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

## Live frames

**Frames → Live** shows what the radios hear right now, as it is heard, in the same three panes and with the same display
filter as a recording.

- **Radios of:** this server, or a remote sensor.
- **Which radios** to show, and **for how long:** one minute unless you choose longer, and an hour at most. The capture
  stops by itself when that time is up.
- **It also stops** about half a minute after the page is closed, or when its tab is in the background, because the page
  stops asking for frames. **Stop** ends it straight away.
- **Follow the newest** keeps the list scrolled to the newest frames. Scroll up to look at one and following pauses; scroll
  back to the end to resume.
- **Save as recording** keeps what was heard as a recording. It is listed with the others and opens like them.

The page keeps the newest 5,000 frames and the server the newest 20,000. Of Wi-Fi data frames only the headers are shown,
as in a recording.

A remote sensor sends its frames with its next uploads, every 2 seconds, so they arrive in small bursts. It sends at most
3,000 frames per upload. When a busy channel produces more, the rest are dropped, and the page says how many. Live frames
from a remote sensor need version 33.3 or newer on that sensor, or the Android app 1.4.0 or newer (its USB adapters only, as
for recordings).

Like inspecting a recording, live frames show the real addresses and bytes, so they are not available while MAC address
privacy or the anonymised view is on.

**Delete all…** (on the Frames page and under Settings → Frame recording) deletes every recording at once, except one that is
being made right now.

## Recording automatically

**Settings → Frame recording → Record automatically** starts a recording by itself when an event happens, so you get the frames of a
problem without being there when it happens. Choose:

- **When:** the events. For example:
  - a client failed to connect to your network
  - a slow roam
  - a deauthentication flood or a broadcast deauthentication
  - a handshake-capture attack, a rogue or KARMA access point
  - interference, radar
  - an access point restart, a disconnect, a cloned address, a scanner
- **On:** this server and remote sensors.
- **The radios.**
- **Seconds before** (up to 120), **seconds after** (10–600), and how long to **wait** before the next one (at least a minute).

While it is on, the chosen sensors keep the last seconds of frames of those radios in memory (Wi-Fi data frames with their
headers only, as in a recording). A remote sensor is told so with each reply to its uploads, and lets go a minute after the
server stops saying so. When a chosen event happens, each sensor writes those seconds to a new recording and goes on recording
for the seconds after. A remote sensor sends the file here when it is done, as for any recording. The recording is listed with
the others, with the event that started it. *Recently* shows the last events that started one, and what was recorded or why not.

Like any recording, nothing is kept or recorded while MAC address privacy is on, and nothing is started when there are 20
recordings already. Remote sensors need release 34.1 for the seconds before, the Android app 1.6.0.

## Wireshark: pcapng export and import

**pcapng** (next to Download, on the Frames page and under Settings → Frame recording) saves a recording as a pcapng file that
Wireshark, tshark and other pcap tools open. On the Frames page, with a display filter applied, it saves only the frames that
pass the filter. In Live mode it saves what the page holds (the newest 20,000 frames, filtered the same way).

Each radio gets the link type Wireshark decodes, and each interface a frame came from becomes an interface in the file, under
its own name (`wifi:wlan0mon`, `bt:hci0`, ...):

| Radio | Link type | What is in it |
|---|---|---|
| Wi-Fi | 127 `IEEE802_11_RADIOTAP` | The frame with its radiotap header, as recorded (data frames: headers only) |
| Bluetooth | 201 `BLUETOOTH_HCI_H4_WITH_PHDR` | The HCI event, marked as received |
| Zigbee / Thread | 283 `IEEE802_15_4_TAP` | The 802.15.4 frame, with channel, signal and LQI in the TAP header |
| LoRa | 270 `LORATAP` | The LoRa payload, with frequency, bandwidth, spreading factor, RSSI, SNR and sync word in the LoRaTap header. Wireshark decodes LoRaWAN (sync word 0x34); Meshtastic and MeshCore show as data |

**Import pcap…** works the other way round: it takes a pcap or pcapng file made elsewhere (Wireshark, tcpdump, airodump-ng,
Kismet's pcapng export, an nRF or Zigbee sniffer), gzipped or not and up to 64 MB, and keeps it as a recording. It shows up as
*Imported file* and opens in the inspector like any other. Besides the four link types above it reads 105 `IEEE802_11` (no
radiotap), 187 `BLUETOOTH_HCI_H4`, 195 `IEEE802_15_4_WITHFCS` and 230 `IEEE802_15_4_NOFCS`. Other packets (Ethernet, USB,
Bluetooth ACL data, ...) are left out, and the message after the import says how many and why. Wi-Fi data frames are cut to their
headers, as in a recording. A file exported here comes back with its interface names.

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
