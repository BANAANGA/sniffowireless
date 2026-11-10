[← Back to the README](../README.md)

# Using the UI

- **Search** (box at the top of the sidebar; press <kbd>/</kbd> to jump to it): searches every record. That covers:
  - devices: MAC (with or without separators), IP, name, label, notes, SSID, vendor, brand, model
  - groups, networks and probed network names
  - DNS lookups, events, alerts, security findings and sensors

  Results appear as you type; use the arrow keys and Enter to open one, or press Enter for the full results page with a filter per record type.
- **Overview:** active vs. total devices per type, active devices and connected clients over time (6 h to 30 d) — *By band* shows 2.4, 5 and 6 GHz side by side on the same scale (access points, active and connected clients per band, plus Bluetooth & LAN), *By type* shows all device types in one chart, currently connected clients with the network they're on, a **System** panel (host CPU use and load average, memory use, database size and free space on the data disk, plus sniffowireless's own CPU and memory), sensor health (packets/s, current channel, errors), and recent events. Every card and row links deeper.
- **Devices:** a searchable, sortable list showing what each device was identified as. Filter by radio type, device type, recency or band (2.4 / 5 / 6 GHz), and hide randomized MACs. Drill-downs add filters for brand, OS, Wi-Fi generation, age and probe fingerprint. Filter chips from drill-downs (SSID, channel, probed SSID, BSSID, vendor) can be removed individually. CSV export.
- **Device detail** (click any device):
  - key facts, total time present, visits, average and longest visit, time connected
  - **identification:** brand, model, device type, OS, Wi-Fi generation and capabilities, chipset, estimated age, probe fingerprint (and how many other MACs share it), WPS info, and the evidence behind each value
  - **signal strength** chart (avg plus min–max band)
  - **weekly pattern** heatmap: when the device is usually around
  - **presence & connectivity timeline**: visits plus one lane per AP (or per client, on an AP's page) showing exactly when it was connected
  - for APs: **connected clients over time**, the client list, and other BSSIDs with the same SSID
  - for clients: the APs/networks it connected to, with session counts and total time, and the SSIDs it probes for
  - a session table (connections or visits) with duration, frames, signal and why each session ended, plus device events
- **Statistics:** a **Breakdown** of doughnut charts per radio type (BLE by default; also Wi-Fi clients, Bluetooth classic, access points, LAN). Each shows device type, vendor, brand and OS, and for BLE also the address type (public, random static, private) and the Bluetooth company. The top five values get a slice each, the rest is folded into a gray *Other*. Every slice and legend row has its count and share, and clicking one opens the matching devices. Below that: device types, brands, Wi-Fi generations, estimated age, operating systems, shared probe fingerprints, activity by hour of day, new devices per day, session duration distribution, top vendors, AP channel usage per band, APs and clients per band, SSID table (the 20 most recently seen networks, expandable to 100; BSSIDs, clients, security, last seen), most-connected clients, busiest APs, probed SSIDs, MAC-randomization ratio and event counts. Click any bar or row to jump to the matching devices or events.
- **Events:** the full, filterable event log.
- **Logs** (admins only): the application log, live, with a tab for every remote sensor's own log (see [Logs of remote sensors](sensors.md#logs-of-remote-sensors)). New lines stream in as they happen. You can:
  - filter by level, source module or text, pause, follow or wrap lines
  - download what's shown
  - switch the log level to **Debug** without restarting, e.g. to see why an adapter misbehaves; set it back to Info afterwards

  The last 5,000 lines are kept in memory, and the setup code and API tokens are masked.
- **Groups:** people or things made of several devices. A group's page shows the combined presence (when *any* of its devices was around), one timeline lane per device, and its events.
- **Map:** your floor plan with sensors and devices on it, plus a per-room device count. See [Multiple sensors & the map](sensors.md#multiple-sensors--the-map).
- **Reports:** occupancy, meaning estimated people present per hour, a typical-week heatmap, unique/new/returning visitors per day and median visit length. *Print / PDF* gives a clean light-themed printout, and a weekly summary can be emailed (Settings → Weekly report). People are estimated from Wi-Fi phones present for at least 5 minutes; a "person" group counts once.
- **My networks:** add your SSIDs under Settings → My networks to see:
  - clients over time
  - band use (2.4/5/6 GHz share of connected time)
  - per-client signal, connected time, roams and **ping-pong roaming** (A→B→A within 2 minutes)
  - **sticky clients** (connected below −75 dBm while another of your APs is available)
  - clients capable of 5 GHz that sit on 2.4 GHz
  - disconnect reasons (timeouts vs. deauth reason codes)
- **Channels:** for each channel the sensor hops over:
  - estimated airtime use, retransmission rate, noise floor, frames/s and neighbouring APs
  - a ranking of the best channels per band (2.4 GHz: 1/6/11 with overlap weighting; 5 GHz: quietest 80 MHz block, non-DFS preferred; 6 GHz: PSCs)
  - a recommendation for each of your own access points
  - **DFS / radar:** radar hits per DFS channel, channels closed right now, every channel switch seen and the access points currently on DFS channels (see [DFS / radar](security.md#dfs--radar))

  Airtime is estimated from frame lengths and PHY rates, so treat it as relative.
- **Settings:**
  - account (password), users, my networks, ignore list, sensors
  - notification channels, weekly report, detection thresholds, API tokens

## Tables and phones

Every table can be sorted by clicking a column header (click again to reverse); the choice is remembered while you stay on the page, also when the table refreshes. The device list sorts on the server, so it sorts all devices, not just the visible page.

On a phone the sidebar becomes a top bar with search and a menu button, cards sit two per row, wide tables scroll sideways and dialogs use the full width.

## Appearance

Admins can hide what an installation doesn't use under **Settings → Modules**: Wi-Fi, Bluetooth, Ethernet / LAN, Zigbee and LoRa. A hidden kind disappears from the menu, the overview (cards, charts, sensor list, discovery panels) and the statistics. Each row says whether anything of that kind is configured or has been seen, and *Hide the unused* switches off all that aren't in use. This only changes what is shown: nothing is deleted and capture still follows the environment variables, so switching a kind back on brings everything back. LAN, Zigbee and LoRa can also **keep their data for their own number of days** (an empty field follows `RETENTION_DAYS`): LoRa packets pile up fast, so a week is often enough there. The overview also lists the latest discovered **Zigbee** networks and radios and **LoRa** nodes.

**Clear data.** Under **Settings → Clear data** an admin can delete what is stored for one kind of radio (Wi-Fi, Bluetooth, Ethernet / LAN, Zigbee or LoRa), or just its events and alert history, or the in-memory application log. The page shows what each button would delete. Clearing a module's entries removes its devices with their sessions, signal history, probes and events, and its own tables (channel survey, DFS and interference history, security findings, LAN traffic / DNS / flows, Zigbee and LoRa data). Labels, notes, groups and watch flags, alert rules, notification channels, settings, users, sensors and downloaded handshake captures are kept, and capture goes on, so new data appears as it is heard. It cannot be undone: make a backup first.

**Anonymised view.** Under **Settings → Privacy** an admin can show pseudonyms instead of real MAC addresses and / or SSIDs, to everyone, in every page, export (CSV / JSON), the log view and the Prometheus labels. A MAC keeps its vendor part (`a4:83:e7:5c:21:0b` becomes `a4:83:e7:9f:3e:61`, so vendors and the randomized flag still make sense), an SSID becomes `Network-1a2b3c`, and multicast and broadcast addresses are left alone. The same value always gets the same pseudonym (also after a restart), and links, searches and forms keep working: pseudonyms in a request are turned back into the real values before anything is looked up. It is a display setting only: the database, backups, notifications sent out (ntfy, e-mail, …), handshake captures and the sensors' uploads keep the real values, and a MAC or SSID written in free text (a label, a note) is not recognised. A pill in the menu says when it is on.

Admins can change the look under **Settings → Appearance**: the app name, the default **time format** (automatic from the browser language, 24-hour or 12-hour; also used in notifications and the weekly report), the icon (a few built-in glyphs or an uploaded square PNG/JPEG/WebP up to 256 kB, also used as the browser-tab icon) and the colours of surfaces, text, device types and status. Presets (*Slate*, *Forest*, *High contrast*) are a starting point; changes preview immediately and apply to everyone, including the sign-in page, once saved. *Reset to default* brings back the stock dark palette. The appearance is part of configuration backups; an uploaded icon is included in full backups.

Each user can override the time format for their own browser under **Settings → Account → Display**.

## Ignore list

Under **Settings → Ignore list** an admin can drop these before anything is stored:
- devices, by MAC
- whole vendor prefixes, e.g. a smart-plug brand
- networks, by SSID, optionally including every client connected to them

Ignored traffic never reaches the database, the UI or alerts. Tick *Also delete data already stored* to purge existing history for matching devices. The page shows how many stored devices match before you save.

## Choosing networks

The **My networks**, **Investigations** and **Ignore list** settings share a network picker (*Choose networks…*). It lists every SSID sniffowireless has seen in the last 90 days with:
- its access points, connected clients and the devices that looked for it
- security and when it was last seen
- whether it is already one of yours, ignored or under investigation

Search it, tick networks and apply. Networks that are only *looked for* by devices (never broadcast nearby) can be included with a checkbox, and a name that hasn't been seen yet can be typed in.

## Networks

**Networks** (sidebar under Wi-Fi) lists every SSID seen: broadcast nearby, only looked for by devices, or both. Each shows its access points, clients, devices looking for it, security, bands, best signal and last seen, plus tags if it's yours, ignored or investigated. Click a network for its dossier: a timeline, every access point broadcasting it, connected devices, devices that looked for it, and events. It's the same view as for investigated networks, and **Investigate** adds it to that list.

**Bluetooth services.** On a Bluetooth LE device's page the *Services* row names each advertised service (for example `180f Battery`) and explains it in a tooltip when you hover or focus it. A few services that have a history of weak configurations (file and contact access, serial ports, keyboards, firmware update, mesh provisioning) carry a ⚠ and a *Worth a look* note. The scan only sees what a device advertises, not whether it requires pairing, so the note means "this service exists here", not "this device is vulnerable". Standard services come from the Bluetooth SIG list; numbers in the `fc00`–`ffff` range belong to member companies, and the tooltip says when the app doesn't know which one.

**Bluetooth advertisement details.** Besides the services, a Bluetooth LE device's page shows what its advertisements say about it, all heard passively: the *Advertised flags* (discoverable mode and whether it is LE only or also classic Bluetooth), the *Preferred connection interval* it asks for, an *Advertising interval* estimated from how often the device was heard (a rounded estimate: the scanner hears one of three channels at a time, so it can be off for devices that advertise slowly or that were heard rarely), and *iBeacon* UUID, major and minor. Services now include 128-bit (vendor-specific) and 32-bit UUIDs; the standard 16-bit ones are listed first and at most 16 are kept. Remote sensors need the newest image to report these.

## Bluetooth ↔ Wi-Fi matching

Phones, tablets and laptops have both radios, so sniffowireless sees them twice. **Matching** (sidebar under Devices) guesses which Bluetooth address belongs to which Wi-Fi address from the last 7 days. It weighs:
- being present at the same minutes, and arriving and leaving together
- signal strength rising and falling together
- adjacent hardware addresses (vendors usually allocate both next to each other)
- similar names, e.g. Bluetooth "Sam's iPhone" and DHCP hostname `Sams-iPhone`
- the brand: the same brand counts for a pair, a different known brand counts strongly against

Earbuds, watches, tags and bikes are left out: they move with a phone but are separate devices. Click **Link** to confirm a pair, or **Not the same** to hide it for good. Linked devices share their group and "known" status. Each phone, tablet or laptop page also has a **Same device, other radio** panel with its link or best candidates. Phones rotate their Bluetooth addresses, so a link may need renewing.

## Networks under investigation

Put SSIDs you want to keep an eye on under **Settings → Investigations**: an unknown network that appeared nearby, a suspected rogue hotspot, or a network one of your devices keeps joining. Add a note on why. You can also click **Investigate** on any network's dossier; open one from search or from an access point's page (*dossier →*). sniffowireless then records:

| Event | When |
|---|---|
| *Investigated network on the air* | an access point starts broadcasting the name, including a KARMA-style hotspot that rotates through names |
| *Device joined an investigated network* | a device connects to it |
| *Device looked for an investigated network* | a device probes for it (at most once per device per 6 h) |

These events feed the alert rule *Networks under investigation*, which is created automatically; attach a notification channel to it under Alerts → Rules. The **Investigations** page (under Wi-Fi) shows one card per network. Each network's **dossier** has:
- a timeline of when its access points were on the air and when devices were connected
- every access point that broadcast it (vendor, channel, security, signal, room)
- the devices that connected to it and those that looked for it
- all related events

## Labels, watch list and groups

On any device page an admin can set a **label** ("Sam's iPhone") and notes, and mark the device:
- **known:** excluded from "unknown device" alerts
- **watched:** included in arrive/leave alerts

A device can also be put in a **group**. *Possibly the same physical device* lists other MACs with the same probe fingerprint (or name) that were never present at the same time, which is typical of MAC rotation. One click adds them to the group.
