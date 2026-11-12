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

The page records the radios of the server itself. On a **remote sensor**, set `CAPTURE_AT_START=<seconds>` in its environment: it
then records from the moment it starts, into `captures/` in its data directory on that machine.

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
