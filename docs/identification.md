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

**Access points from TP-Link, Ubiquiti and HPE Aruba.** What an access point says about itself in its beacons is read, and a model is only claimed when the text matches the maker's own naming:

- **Vendor "AP name" elements.** Ubiquiti (vendor element `00:15:6d`, type 1) and Aruba (`00:0b:86`, subtype 3) access points broadcast a name; the byte layouts are the ones Wireshark decodes. The name is shown on the access point's page (*AP name*), and the presence of either maker's element alone makes the brand *Ubiquiti* or *HPE Aruba*, even behind another MAC vendor. Aruba's other elements (ARM, mesh, auto mesh, CAC, ...) are listed as features. Aruba's GPS element is deliberately not decoded.
- **Model names** are recognised in that name, in the WPS model / model number / device name of routers that broadcast WPS (many TP-Link units do), and, as weak evidence, in the network name: Ubiquiti `U6-Pro`, `U7 Pro Max`, `UAP-AC-Pro`, `nanoHD`, `FlexHD`, `NanoStation`, `LiteBeam`...; TP-Link `Archer C7`, `Archer AX55`, `TL-WR841N`, `EAP225-Outdoor`, `Deco X20`...; Aruba `AP-515`, `IAP-305`... Only Aruba model numbers on Aruba's published list count, so an administrator's room number such as `AP-101` is not taken for a model.
- **The name has to agree with the beacons.** Where a model's Wi-Fi generation is certain (the `U6` line is Wi-Fi 6, `U7` Wi-Fi 7, `nanoHD` Wi-Fi 5, an `Archer AX` Wi-Fi 6, Aruba's 5xx and 6xx Wi-Fi 6 / 6E), an access point whose beacons show another generation is not reported as that model; the page says so instead.
- **Confidence** is higher for a name a vendor element carried or a router reported by WPS (and higher still when the MAC vendor is the same maker) than for a network name, which anyone can choose. A name is still only a name: an administrator can call an access point anything.

What is **not** detected: the exact model of an access point that announces no name and no WPS information (most TP-Link Omada and many UniFi beacons carry nothing more than capabilities, which only say *Wi-Fi 6, 4×4, 160 MHz*), and anything from Aruba's LLDP text, whose format I could not confirm. The rules are written from the makers' public model names and Wireshark's element layouts and have not been tried against captures from real access points.

**Estimated age** comes from the newest standard a device supports (it can't predate it), or from the model's release year when that is known (AirPods/Beats). For phones, computers, TVs and routers sniffowireless also gives an upper bound: a laptop with only Wi-Fi 5 is typically from 2013–2020. Printers and IoT devices still ship with Wi-Fi 4 today, so for those only "N or newer" is shown.

**Limits:** results are best-effort. Devices with randomized MACs and no name (most phones while idle) can often only be identified as "Apple phone, Wi-Fi 6" or "phone". Clients only reveal capabilities in probe/association frames, so a device first has to scan or (re)connect while the sensor is on its channel. When the rules improve in a new version, all stored devices are re-identified automatically on startup.
