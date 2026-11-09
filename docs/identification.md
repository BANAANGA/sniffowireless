[← Back to the README](../README.md)

# Device identification

sniffowireless works out what each device is purely from what it broadcasts. Nothing is sent to the device. Every clue becomes a piece of evidence with a confidence score, and for each field the best-supported value wins. The device page shows the result, a confidence badge per field and the full evidence list.

| Source | What it reveals |
|---|---|
| **Wi-Fi capability elements** (probe/association requests, beacons) | Newest Wi-Fi standard (legacy a/b/g → Wi-Fi 4/5/6/6E/7), MIMO streams, channel width |
| **WPS element** (many printers, TVs, routers, some PCs) | Manufacturer, model name/number, device name, device category |
| **Vendor-specific elements** | Apple devices, Samsung, chipset vendor (Broadcom, Qualcomm, MediaTek, Realtek…), Wi-Fi Direct, MBO, Passpoint |
| **Probe-request layout** | A *probe fingerprint* hash: the element order/capabilities are characteristic of chipset + OS build, so randomized MACs from the same kind of phone share a hash |
| **Apple Continuity (BLE)** | AirPods/Beats model and release year; iPhone/iPad/Mac activity (Handoff, Nearby), AirPlay targets, Find My accessories |
| **Microsoft CDP beacons (BLE)** | Windows desktop/laptop/tablet, Xbox, Android/iPhone running Microsoft apps |
| **BLE services / appearance** | Tile, SmartTag, Fast Pair, Eddystone, heart-rate/fitness, HID keyboards/mice, Xiaomi/BTHome sensors… |
| **Bluetooth class of device** | Phone, laptop, headphones, car audio, speaker, watch, … |
| **Bikes** | Bluetooth "Cycling" appearance or cycling speed/cadence/power services, and names such as VanMoof `ES3-…`/`EX3-…` or Cowboy → *Bike / e-bike* |
| **Names / SSIDs** | “iPhone”, “Galaxy Watch5”, “DESKTOP-XXXXXXX” (Windows), “[TV] Samsung…”, “DIRECT-xx-HP…” printers, phone hotspots, car hotspots |
| **MAC vendor (OUI)** | Brand, plus a type hint for single-purpose vendors (Espressif → IoT, Sonos → speaker, Hikvision → camera…) |

**Estimated age** comes from the newest standard a device supports (it can't predate it), or from the model's release year when that is known (AirPods/Beats). For phones, computers, TVs and routers sniffowireless also gives an upper bound: a laptop with only Wi-Fi 5 is typically from 2013–2020. Printers and IoT devices still ship with Wi-Fi 4 today, so for those only "N or newer" is shown.

**Limits:** results are best-effort. Devices with randomized MACs and no name (most phones while idle) can often only be identified as "Apple phone, Wi-Fi 6" or "phone". Clients only reveal capabilities in probe/association frames, so a device first has to scan or (re)connect while the sensor is on its channel. When the rules improve in a new version, all stored devices are re-identified automatically on startup.
