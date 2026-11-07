# lora-sniffer

Receive-only LoRa firmware for the **Heltec WiFi LoRa 32 V3** (ESP32-S3 + SX1262). It has no transmit code. It listens on the settings the sniffowireless server asks for and prints every frame with a good CRC to the USB serial port. The server hops between profiles and does all the decoding.

## Flash

Flashing **replaces whatever firmware is on the board** (for example Meshtastic). To keep a copy first: `esptool.py --port /dev/ttyUSB0 read_flash 0 0x800000 backup.bin`.

```bash
pip install platformio
cd firmware/lora-sniffer
pio run -t upload --upload-port /dev/ttyUSB0
```

The board shows up as a CP2102 serial port. On Linux you need access to it (your user in the `uucp` or `dialout` group, depending on the distribution). If upload does not start, hold **PRG**, tap **RST**, release **PRG**, then retry.

## Serial protocol (115200 baud, one line each)

Device to host:

| Line | Meaning |
|---|---|
| `READY,lora-sniffer,1,heltec_v3,sx1262` | Sent at boot |
| `RX,<ms>,<MHz>,<kHz>,<sf>,0x<sync>,<rssi>,<snr>,<ferr Hz>,<len>,<hex>` | A frame, with the settings it was heard on |
| `OK,CFG,...` / `ERR,CFG,<code>` | Answer to a settings change |
| `STAT,<ms>,<packets>,<crc errors>` | Every 10 s |
| `PONG`, `INFO,...` | Answers to `PING`, `INFO` |

Host to device: `CFG,<MHz>,<kHz>,<sf>,<cr 5-8>,<sync 0x..>,<preamble>`, `PING`, `INFO`.

Sync word is the byte as in the protocol (Meshtastic `0x2B`, MeshCore `0x12`, LoRaWAN public `0x34`); the firmware converts it for the SX126x.

## Notes

- The Heltec V3 radio covers 863–928 MHz. Use a 433 MHz board for 433 MHz profiles.
- Use the antenna that came with the board. Transmitting without one can damage a radio; this firmware never transmits, but other firmware you flash later might.
