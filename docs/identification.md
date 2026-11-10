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

**Samsung phones and Google Pixels.** Android phones are the hardest to tell apart, because they randomize their address and say little. What is used:

- **Names with hyphens or underscores.** A router's client list and DHCP hostnames cannot hold spaces, so `Galaxy-S23-Ultra`, `Pixel-7-Pro` or `Pixel_8a` are recognised like `Galaxy S23 Ultra` (and a lowercase hostname gets its capitals back). Galaxy S, A, M and Note phones with Ultra / FE / Plus / 5G, Z Flip and Z Fold, Tab, Watch and Buds, and Pixel phones with Pro / XL / Fold, Pixel Fold, Tablet, Watch and Buds are covered.
- **Samsung model numbers** such as `SM-S918B`, as they appear in the WPS element of Wi-Fi frames or in a device or Bluetooth name. The line letter says what kind of device it is (`S`, `G`, `A`, `N`, `F`, `M`, `J` phones; `T`, `X`, `P` tablets). The marketing name and release year are filled in for the models whose numbers are confirmed: Galaxy S21 to S24 (all three sizes of each), Z Flip6 and Z Fold5. Any other number is shown as it is.
- What does **not** work: Android 11 and newer usually send no DHCP hostname, a phone that only probes with a random address shows no name, and I found no published way to tell a Pixel from a Samsung by its Wi-Fi capabilities alone. Such a phone stays "Android phone, Wi-Fi 6". Labelling it on its device page and grouping it with the person's other devices still helps.

**Estimated age** comes from the newest standard a device supports (it can't predate it), or from the model's release year when that is known (AirPods/Beats). For phones, computers, TVs and routers sniffowireless also gives an upper bound: a laptop with only Wi-Fi 5 is typically from 2013–2020. Printers and IoT devices still ship with Wi-Fi 4 today, so for those only "N or newer" is shown.

**Limits:** results are best-effort. Devices with randomized MACs and no name (most phones while idle) can often only be identified as "Apple phone, Wi-Fi 6" or "phone". Clients only reveal capabilities in probe/association frames, so a device first has to scan or (re)connect while the sensor is on its channel. When the rules improve in a new version, all stored devices are re-identified automatically on startup.
