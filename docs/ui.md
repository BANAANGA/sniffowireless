[← Back to the README](../README.md)

# Using the UI

- **Search** (box at the top of the sidebar; press <kbd>/</kbd> to jump to it): searches every record. That covers:
  - devices: MAC (with or without separators), IP, name, label, notes, SSID, vendor, brand, model
  - groups, networks and probed network names
  - DNS lookups, events, alerts, security findings and sensors

  Results appear as you type; use the arrow keys and Enter to open one, or press Enter for the full results page with a filter per record type.
- **Overview:** active vs. total devices per type, active devices and connected clients over time (6 h to 30 d) — *By band* shows 2.4, 5 and 6 GHz side by side on the same scale (access points, active and connected clients per band), *By type* shows all device types in one chart, currently connected clients with the network they're on, a **System** panel (host CPU use and load average, memory use, database size and free space on the data disk, plus sniffowireless's own CPU and memory), sensor health (packets/s, current channel, errors), and recent events. Bluetooth, Zigbee / Thread / 802.15.4 and LoRa each have a graph of their own over the same time range: Bluetooth separates devices with **random** addresses (phones and wearables that change address) from **static** ones and classic Bluetooth; the 802.15.4 graph separates **Zigbee**, **Thread** and **other** radios (by what their own frames and their network showed; a radio whose protocol cannot be told counts as other); LoRa is split by protocol (Meshtastic, MeshCore, LoRaWAN…). Every card and row links deeper. The layout keeps things level: the stat cards fill even rows (all in one row when they fit, otherwise split evenly, e.g. 4 + 3), the three band graphs sit exactly above the Bluetooth, 802.15.4 and LoRa graphs, graphs in one row share their baseline, System, Sensors and Interface activity form one row, and recent events take the height of the connected-clients table next to them and scroll.
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
- **Sensors:** every sensor (this server and the remote ones) with its online state, version, load and battery (phones, laptops, UPS), and each of its interfaces: status, hardware (maker and product, driver, bus and speed, USB ID, Bluetooth version, chip and LE features, firmware of Zigbee sticks and LoRa boards) and what it listens on. Below that, frames per second per interface and the **signal comparison**: pick up to 8 devices (search, *Strongest now* or *Watched*) and see every signal reading of each, per sensor, live over the last 2, 5 or 15 minutes, with a table of now, average, weakest and strongest. *Strongest sensor* draws one line per device. Readings are gathered while the page is open and kept for 15 minutes; nothing extra is stored. Hardware details need a sensor running this version or newer.
- **Frame recording** (Settings, admins): record what the radios hear to a file and replay it through the parsers.
- **Frames** (admins only): open a recording and go through it frame by frame, laid out like Wireshark: a frame list with a display filter and colours per kind of frame, the decoded fields of the chosen frame, and its bytes. Choosing a field highlights its bytes; clicking a byte chooses its field. See [Inspecting a recording](capture.md#inspecting-a-recording). **Live** shows the frames of this server's or a remote sensor's radios as they are heard, for a minute unless you choose longer (an hour at most); see [Live frames](capture.md#live-frames). **Delete all…** removes every recording.
- **People nearby:** a card on the overview and a graph on Statistics with an estimated range of people in range, counted from phones per 5 minutes. See [occupancy.md](occupancy.md).
- **Statistics:** a **Breakdown** of doughnut charts per radio type (BLE by default; also Wi-Fi clients, Bluetooth classic, access points, LAN, Zigbee & Thread, and LoRa). Each shows device type, vendor, brand and OS, and for BLE also the address type (public, random static, private) and the Bluetooth company. The top five values get a slice each, the rest is folded into a gray *Other*. Every slice and legend row has its count and share, and clicking one opens the matching devices. For Zigbee & Thread and LoRa that is the Zigbee or LoRa page, filtered the same way; both pages have the filters (protocol, role, probable device, power, vendor; protocol, node type, radio settings, position) as dropdowns above their list. Activity by hour, the weekly pattern and new devices per day count Zigbee radios and LoRa nodes too. **Channels and airtime:** access points or clients per Wi-Fi channel; *Airtime per channel* (per band, the share of the time a sensor listened on a channel that frames were on the air, with retries, noise and frames per second in the tooltip); *Airtime by band* over the period; Zigbee frames per channel; and LoRa time on the air per listening profile, by protocol. Airtime comes from the channel survey of Wi-Fi sensors that hop channels: a sensor hears one channel at a time, so each figure is a sample of its listening time. Below that: device types, brands, Wi-Fi generations, estimated age, operating systems, shared probe fingerprints, activity by hour of day, new devices per day, session duration distribution, top vendors, AP channel usage per band, APs and clients per band, SSID table (the 20 most recently seen networks, expandable to 100; BSSIDs, clients, security, last seen), most-connected clients, busiest APs, probed SSIDs, MAC-randomization ratio and event counts. Click any bar or row to jump to the matching devices or events.
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
  - **client readiness:** what your clients can do, and who switching to WPA3 only, dropping 2.4 GHz, requiring PMF or dropping 802.11b rates would leave behind (see [Client readiness](#client-readiness))
  - **connections & roaming:** failed connection attempts by cause, and every roam with its method and duration (see [Connections and roaming](#connections-and-roaming))

  - **link quality:** the clients of your access points whose data frames point to a problem (see [Link quality](#link-quality))
- **Audit report:** everything about your networks on one page to hand over, findings first (see [Audit report](#audit-report))
- **Channels:** for each channel the sensor hops over:
  - estimated airtime use, retransmission rate, noise floor, frames/s and neighbouring APs
  - a ranking of the best channels per band (2.4 GHz: 1/6/11 with overlap weighting; 5 GHz: quietest 80 MHz block, non-DFS preferred; 6 GHz: PSCs)
  - a recommendation for each of your own access points
  - **who uses the airtime:** per channel, the share each client and access point takes with its data frames, and the slow ones (see [Who uses the airtime](#who-uses-the-airtime))
  - **BSS colours and channel widths:** Wi-Fi 6 networks with the same colour on one channel, and widths that do more harm than good (see [BSS colours and channel widths](#bss-colours-and-channel-widths))
  - **co-channel interference** between your own access points, and a channel plan for all of them (see [Co-channel interference](#co-channel-interference))

  - **Beacon overhead:** per channel, the share of the airtime beacons alone take, with the number of BSSIDs, SSIDs, radios and beacons per second; a row opens the access points behind it (see [Beacon overhead](#beacon-overhead))
  - **DFS / radar:** radar hits per DFS channel, channels closed right now, every channel switch seen and the access points currently on DFS channels (see [DFS / radar](security.md#dfs--radar))

  Airtime is estimated from frame lengths and PHY rates, so treat it as relative.
- **Settings:** grouped in the left-hand list, each page with an icon and a one-line description at the top. *Find a setting…* filters the list by name, description and related words (e.g. *email*, *2fa*, *home assistant*); Enter opens the first match. On a phone the list becomes a drop-down.
  - **You:** account (password, two-factor login, display on this browser)
  - **Monitoring:** my networks, investigations, ignore list, detection thresholds
  - **Radios & sensors:** sensors, modules, Wi-Fi channels, LoRa bands, Zigbee, LoRa flasher
  - **Alerts & integrations:** notification channels, scheduled report (daily or weekly), MQTT, API tokens
  - **Data & privacy:** privacy, clear data, backup
  - **System:** users, appearance, performance, about

  Viewers see account, my networks, investigations, ignore list and about; pages of hidden modules are left out.

## Tables and phones

Every table can be sorted by clicking a column header (click again to reverse); the choice is remembered while you stay on the page, also when the table refreshes. The device list sorts on the server, so it sorts all devices, not just the visible page.

On a phone the sidebar becomes a top bar with search and a menu button, cards sit two per row, wide tables scroll sideways and dialogs use the full width.

## Appearance

Admins can hide what an installation doesn't use under **Settings → Modules**: Wi-Fi, Bluetooth, Ethernet / LAN, Zigbee and LoRa. A hidden kind disappears from the menu, the overview (cards, charts, sensor list, discovery panels) and the statistics. Each row says whether anything of that kind is configured or has been seen, and *Hide the unused* switches off all that aren't in use. This only changes what is shown: nothing is deleted and capture still follows the environment variables, so switching a kind back on brings everything back. LAN, Zigbee and LoRa can also **keep their data for their own number of days** (an empty field follows `RETENTION_DAYS`): LoRa packets pile up fast, so a week is often enough there. The overview also lists the latest discovered **Zigbee** networks and radios and **LoRa** nodes.

**Clear data.** Under **Settings → Clear data** an admin can delete what is stored for one kind of radio (Wi-Fi, Bluetooth, Ethernet / LAN, Zigbee or LoRa), or just its events and alert history, or the in-memory application log. The page shows what each button would delete. Clearing a module's entries removes its devices with their sessions, signal history, probes and events, and its own tables (channel survey, DFS and interference history, security findings, LAN traffic / DNS / flows, Zigbee and LoRa data). Labels, notes, groups and watch flags, alert rules, notification channels, settings, users, sensors and downloaded handshake captures are kept, and capture goes on, so new data appears as it is heard. It cannot be undone: make a backup first.

**Hashed storage and retention.** The same tab (Settings → Privacy) has the stronger tools: **hashed storage** never keeps a full static MAC address (it is replaced by a keyed pseudonym before it is stored, also in text and settings, with a button to rewrite what is already there) and **data retention** sets how many days each kind of data is kept. See [Privacy and the law](privacy.md).

**Anonymised view.** Under **Settings → Privacy** an admin can show pseudonyms instead of real MAC addresses and / or SSIDs, to everyone, in every page, export (CSV / JSON), the log view and the Prometheus labels. A MAC keeps its vendor part (`a4:83:e7:5c:21:0b` becomes `a4:83:e7:9f:3e:61`, so vendors and the randomized flag still make sense), an SSID becomes `Network-1a2b3c`, and multicast and broadcast addresses are left alone. The same value always gets the same pseudonym (also after a restart), and links, searches and forms keep working: pseudonyms in a request are turned back into the real values before anything is looked up. It is a display setting only: the database, backups, notifications sent out (ntfy, e-mail, …), handshake captures and the sensors' uploads keep the real values, and a MAC or SSID written in free text (a label, a note) is not recognised. A pill in the menu says when it is on.

Admins can change the look under **Settings → Appearance**: the app name, the default **time format** (automatic from the browser language, 24-hour or 12-hour; also used in notifications and the weekly report), the icon (a few built-in glyphs or an uploaded square PNG/JPEG/WebP up to 256 kB, also used as the browser-tab icon) and the **font** and **text size** (a built-in choice such as system, humanist, serif or monospace, or the name of another font installed on the viewing device, with a base size from 11 to 20 px; nothing is downloaded, so a font only shows on devices that have it) and the colours of surfaces, text, device types and status. Presets (*Slate*, *Forest*, *High contrast*) are a starting point; changes preview immediately and apply to everyone, including the sign-in page, once saved. *Reset to default* brings back the stock dark palette. Everyone can also pick their own font and text size for just their browser under **Settings → Account → Display**, the same way as the time format; that choice wins over the admin default and is kept in the browser only. The appearance is part of configuration backups; an uploaded icon is included in full backups.

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

**Hover explanations on the device page.** Hover (or focus) a row label with a dotted underline, a security name (`WPA2/PSK`, `WPA3/SAE`, `OPN`), the channel, the Wi-Fi standard or a capability tag, and a tooltip says in plain language what it means: signal strength in dBm, DFS channels, what the Wi-Fi generation and the streams / channel width mean, 802.11k / v / r, PMF, beacon interval and so on. The texts are in `static/devicehelp.js`.

**Bluetooth services.** On a Bluetooth LE device's page the *Services* row names each advertised service (for example `180f Battery`) and explains it in a tooltip when you hover or focus it. A few services that have a history of weak configurations (file and contact access, serial ports, keyboards, firmware update, mesh provisioning) carry a ⚠ and a *Worth a look* note. The scan only sees what a device advertises, not whether it requires pairing, so the note means "this service exists here", not "this device is vulnerable". Every 16-bit number the Bluetooth SIG has assigned gets its name (standard services, Classic profiles and the 700+ numbers registered to member companies, so `fef3` shows as *Google LLC*); a number that is in none of those lists says so. The data file `static/btnumbers.js` is generated by `scripts/update_bt_numbers.py` from the SIG's published Assigned Numbers and can be refreshed with it. Standard services come from the Bluetooth SIG list; numbers in the `fc00`–`ffff` range belong to member companies, and the tooltip says when the app doesn't know which one.

**Bluetooth advertisement details.** Besides the services, a Bluetooth LE device's page shows what its advertisements say about it, all heard passively: the *Advertised flags* (discoverable mode and whether it is LE only or also classic Bluetooth), the *Preferred connection interval* it asks for, an *Advertising interval* estimated from how often the device was heard (a rounded estimate: the scanner hears one of three channels at a time, so it can be off for devices that advertise slowly or that were heard rarely), and *iBeacon* UUID, major and minor. Services now include 128-bit (vendor-specific) and 32-bit UUIDs; the standard 16-bit ones are listed first and at most 16 are kept. Remote sensors need the newest image to report these.

**Company IDs and raw manufacturer data.** The *Manufacturer data* row names the company behind the ID a device advertises (the full Bluetooth SIG list is bundled). A number that is far beyond the highest registered ID is shown as *Unregistered 0x…*: it is not a company, the device just uses those bytes for its own format, and it is not used as the device's vendor or brand. *Raw manufacturer data* shows the first 32 bytes as sent, company field first (Apple's rotating data is decoded instead and not kept). Remote sensors need the newest image to send it.

**Wi-Fi details.** Everything here is read passively from frames the radio already hears; remote sensors need the newest image to report it. An **access point's** page can show:
- *Up for*, estimated from the timestamp in its beacons (the AP's own timer). Some access points reset that timer without restarting, so treat it as an estimate. When the timer starts over, an *Access point restarted* event is recorded (you can build an alert rule on it).
- *Security details*: the key-management suites (PSK, SAE, OWE, 802.1X ...), ciphers and **protected management frames** (required, optional or off). A network that offers WPA3 and WPA2 together is marked *transition*, because clients that connect with WPA2 get no WPA3 protection, and TKIP or old WPA 1 are flagged.
- *Load* (connected clients and how busy the channel is, as the AP reports it), beacon interval, country, roaming support (802.11k / v / r), Wi-Fi 6 BSS colour, Wi-Fi 7 multi-link, multiple BSSID, mesh ID, WPS state, and *Neighbouring APs* the AP announces in its beacons (often its own other bands).

A **client's** page shows *Link rate* (up and down, from the last data frames; the driver must report it) with the noise floor when available, and the identification section lists *what it says it can do* (802.11k / v / r, beamforming, supported channels, whether it still offers 802.11b rates...). The details are refreshed every minute (access points) or 30 seconds (link rate), not for every frame.

**Linking randomised addresses (off by default).** Set `WIFI_SEQ_LINK=1` to let the server guess that two randomised MAC addresses are one device because the second carries on the 802.11 frame counter of the first within a few seconds. It only proposes a link when exactly one earlier address fits, shows it on both pages as *Possibly the same device*, and never merges anything. It is a heuristic: other devices can match by chance, and some devices do not carry the counter over. Because it defeats the privacy a randomised address is meant to give, it is opt-in. Sensors always send the counter of randomised senders; only the server option decides whether it is used.

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

## Beacon overhead

Every access point sends a beacon for each SSID it offers, about ten times a second, at its lowest basic rate so that every client
can decode it. On 2.4 GHz that is often still 1 Mb/s, where one beacon of 300 bytes takes 2.6 ms: about 2.5 % of the channel, per
SSID, per access point. Many SSIDs on many access points sharing a channel leave less airtime for traffic.

The Channels page adds this up per channel from the access points heard in the last hour. Each beacon's interval, lowest basic rate
and size come from the beacons themselves. A sensor older than release 34 does not report rate and size; then 1 Mb/s (2.4 GHz)
or 6 Mb/s (5 / 6 GHz) and 300 bytes are assumed, marked with a `?`. Access points weaker than -82 dBm are not counted: below that
level a radio does not detect their preamble and does not wait for them. The figure is the time the frames are on the air,
without the gaps and backoff around them, so the real overhead is a little higher.

Under 10 % is fine, 10–20 % is high, and over 20 % is a problem. Above the table, tips for your own networks (those under
*My networks*):

- **A beacon rate of 1 or 2 Mb/s on 2.4 GHz.** It shows what the beacons would take with 12 Mb/s as the lowest basic rate.
  Only clients that can do nothing but 802.11b would no longer join.
- **One radio with four SSIDs or more.** BSSIDs that differ only in the last digit count as one radio. It shows what each SSID
  costs.
- **A beacon interval below 100 TU.**

## Link quality

A Wi-Fi sensor reads the radiotap header and frame control of every data frame between a client and its access point, in
both directions. Once a minute it reports per client and direction:

- how many data frames it heard (null frames left out)
- how many of them had the retry bit set: sent before and not acknowledged
- how many went at each PHY rate and at each MCS, with the number of spatial streams and the channel width
- for the client's own frames, the average signal

HT, VHT and HE rates are worked out from MCS, streams, width and guard interval. The server adds the minutes up per hour.

A **client's** device page shows its *Link quality* for the last 24 hours, each way: data frames, retries, median rate and MCS,
PHY (Wi-Fi 4/5/6, streams, width) and signal, with a bar chart of the frames per MCS. An **access point's** page lists its
clients, the worst first, and *My networks* lists the clients of your access points that have a problem. Each direction gets a
verdict:

| Verdict | What it looks like | What it usually means |
|---|---|---|
| *interference* | 25 % retries or more while the median MCS stays at 5 or higher | The signal is fine but frames get lost: interference, a hidden node, a busy channel |
| *weak and lossy* | 25 % retries or more at a low MCS | Too far away, with losses on top |
| *weak signal* | median MCS 3 or lower, few retries | The link slowed down to what the distance allows; a closer access point would help |
| *legacy rates* | no MCS, only 802.11a/b/g rates | An old radio, or a driver that reports no MCS. 802.11b rates (1–11 Mb/s) only: a very old radio or a very weak link |
| *some retries* | 10–25 % retries | More than the usual few percent |
| *healthy* | a good rate, few retries | |

Fewer than 50 data frames is too little to judge. A sensor hears a client only while it is tuned to that channel, so the
figures are a sample. Frames the sensor did not hear (too weak where it stands) are not counted. Remote sensors need release
34 or newer. The Android app does not report link quality yet.

## Connections and roaming

"Why can't this device connect?" Before a client can send data it goes through a fixed sequence of frames. All of them are sent
before the keys are in place, so a sensor nearby can read them:

1. **Authentication:** Open, SAE (WPA3) or Fast BSS Transition (802.11r)
2. **(Re)association:** with a status code in the response
3. **802.1X / EAP** on enterprise networks: the EAP method, then EAP-Success or EAP-Failure
4. **4-way handshake:** EAPOL-Key messages 1 to 4

Deauthentication and disassociation (with their reason codes), 802.11v BSS transition requests and responses, and 802.11k
neighbour reports are read too. A Wi-Fi sensor picks these steps out of every frame it hears; only the step, the addresses, the
codes and the time are kept, nothing of the keys. At most 60 steps per client per 10 seconds are kept, so a deauthentication
flood does not fill the database.

The server groups a client's steps into **attempts**: one connection to one access point, from the first step to the end of the
4-way handshake, or to the step that failed. The step that failed is named and explained:

| What is heard | Cause |
|---|---|
| Message 1 and 2 again and again, never message 3, then a deauthentication | **Wrong password**: the client's message 2 does not check out against the network's password |
| Message 1 again and again, no answer | The client did not answer the handshake (out of range, or its supplicant gave up) |
| Association response with status 17 | Access point full |
| Status 31 / 30 | Management frame protection (PMF) settings do not match / try again later |
| Status 13 / 43 | The client asked for an authentication or key management method the network does not offer (e.g. WPA3 on a WPA2 network) |
| EAP-Failure | 802.1X login rejected: wrong credentials, an untrusted or expired certificate, or a RADIUS policy |
| A deauthentication during the attempt | Its reason code, with an explanation |

An attempt that was only partly heard is marked *incomplete*.

A **roam** is a reassociation to another access point while the client was connected to another one less than an hour before.
Its duration is the time from the first frame to the access point it moves to, until the connection is complete. Each roam shows
its method (FT for 802.11r, else the 4-way handshake that follows the reassociation; 802.1X when a full EAP login was needed)
and whether the access point steered it with an 802.11v BSS transition request. Under 50 ms is *fast*, up to 150 ms *ok*, and
anything slower can be heard as a gap in a call.

A client's device page lists its attempts step by step (with the time of each step), its roams and its disconnects for the last
7 days. *My networks* sums them up for your access points: attempts, failures by cause, the roams and their median time.

A sensor that hops channels hears only part of a connection, because it is on another channel most of the time. Set a sensor to
the channel of the access point you are troubleshooting (Settings → Wi-Fi channels) to hear all of it. The same frame heard by two
sensors within 0.25 s is kept once. Remote sensors need release 34 or newer.

## Co-channel interference

Two of your access points on the same channel share its airtime wherever a radio hears both at -82 dBm or stronger. That is the
level at which Wi-Fi defers to another transmission, so a client there waits for either one. sniffowireless cannot hear what an
access point hears, but it knows how loud each sensor hears each access point. When one sensor hears two of your radios both at
-82 dBm or stronger, they overlap there, by the weaker of the two signals. With sensors in several rooms that shows where your
access points meet.

The Channels page shows, for your networks (Settings → My networks):

- **Where channels are shared:** at each sensor, a channel that two of your radios (or one of yours and neighbours' access
  points) use.
- **An overlap matrix per band:** how loud each pair of your radios is heard together. Red: the same channel. Amber: overlapping
  channels (on 2.4 GHz, channels less than 5 apart; on 5 and 6 GHz, the same 80 MHz block). Hover a cell to see where.
- **A channel plan** for all your radios together: 1/6/11 on 2.4 GHz, the non-DFS channels on 5 GHz (a radio already on a DFS
  channel may stay there), and the preferred scanning channels on 6 GHz. It weighs:
  - your own radios that are heard together, by how loud
  - the neighbours' access points they hear
  - the measured airtime per channel

  Each change counts as a small cost (clients reconnect), so it only suggests changes that clearly help.

The BSSIDs of one radio (one per SSID, differing in the last digit) count as one radio. The channel widths an access point uses
are not known from what is heard, which is why the same 80 MHz block counts as half a conflict. With one sensor, the overlaps
are those at that one spot.

## Who uses the airtime

One slow device can take more of a channel than all the fast ones together: a frame sent at 1 Mb/s takes a hundred times
as long as the same frame at 100 Mb/s. The Channels page shows, per channel, how much of the time a sensor listened there
each device's data frames were on the air:

- **Clients:** what they sent.
- **Access points:** what they sent to their clients, plus their beacons.

The time per frame comes from its size and the rate it went at (see [Link quality](#link-quality)), with the preamble of its
kind of PHY. The share is that time divided by the time the sensors listened on the channel. A row opens the devices of that
channel, the largest first. A device that takes 5 % or more at a median rate of 24 Mb/s or less is called **slow**, with what
the same data would take at 100 Mb/s. For a client that means a weak signal or an old radio; for an access point, clients that
are far away or old, or low basic rates.

*All airtime* is everything the sensor measured on the channel (management frames and other networks included), so the
devices' data is a part of it. Sensors before release 35 do not count frame sizes; 600 bytes per frame is assumed for their
data, marked with a `?`.

## BSS colours and channel widths

**Colours.** A Wi-Fi 6 access point gives its network a colour (1–63), announced in its beacons. A radio that hears a weak frame
of another colour on its channel may ignore it and transmit anyway (spatial reuse), so neighbouring networks on one channel share
it better. Two networks with the same colour on the same channel lose that: each takes the other's frames for its own. Access
points are meant to notice this and change colour, but many do not. The Channels page lists every colour that two networks
heard at -82 dBm or stronger share on one channel; the BSSIDs of one radio share its colour and do not count. When one of them
is yours, give it another colour.

**Widths.** The width each access point announces comes from its HT, VHT, HE (6 GHz) and EHT operation elements. Two cases are
flagged, as *yours* for your own networks and as *neighbour* for the others:

- **40 MHz on 2.4 GHz.** That takes two of the three channels that do not overlap there, and most clients fall back to 20 MHz
  anyway when anything else is around.
- **A wide channel on a busy 5 GHz band.** 160 MHz while two or more other networks are heard in the same 160 MHz, or 80 MHz
  with four or more in the same 80 MHz. A narrower channel to itself is often faster.

Below that: how many access points use each width per band, and the colour and width of each of yours. Remote sensors need
release 35 to report widths.

## Client readiness

Before you change a network you want to know who it would leave behind. Every client says what it can do in its probe and
association requests: Wi-Fi generation, spatial streams, channel width, the bands it does (its operating classes), 802.11k/v/r,
and, in an association request, the key management it chose and whether it does management frame protection (PMF). *My networks*
shows for the clients that connected to your networks (in the period chosen, at least the last 7 days):

| Change | Who it leaves behind |
|---|---|
| **WPA3 only** | Clients that chose WPA2 where WPA3 was offered too (a network in WPA3 + WPA2 transition mode). Clients that used SAE are ready. Where your networks don't offer WPA3 yet, choosing WPA2 says nothing, so turn on transition mode first to find out. |
| **No more 2.4 GHz** | Clients with no sign of 5 GHz: not Wi-Fi 5 or newer, no 5 GHz operating class, never heard on 5 or 6 GHz |
| **6 GHz** | How many could use it: Wi-Fi 6E or 7, a 6 GHz operating class, or heard on 6 GHz |
| **PMF required** (WPA3 needs it) | Clients without PMF |
| **No 802.11b rates** (12 Mb/s as the lowest basic rate) | Clients that offer nothing but 802.11b rates |

Each card opens the list of clients it would leave behind. Below: generations, streams, widths and 802.11k/v/r support, and a
table of every client. A client that never sent the element a question needs is *not known* (`?`), not a yes or a no.
Remote sensors need release 35 for the key management and PMF of a client.

## Audit report

**Audit report** (under Wi-Fi) puts together what sniffowireless found about your networks (Settings → My networks) over the
last 7, 14 or 30 days: the report a Wi-Fi consultant hands over. **Print / PDF** prints it on a light background without the
menus.

It starts with **findings**, in order of how much they matter (high, medium, low, info), each with what was found and what to
do about it:

- **Security of your networks, from their beacons:**
  - an open network, WEP, TKIP / WPA 1
  - WPS on
  - no management frame protection
  - no WPA3, or WPA3 in transition mode
- **The open findings and attacks of the Security page:** rogue and KARMA access points, deauthentication floods,
  handshake-capture attempts, a downgraded access point, rogue DHCP, ARP spoofing. Bluetooth trackers are left out.
- **Your channels:**
  - busy (on the air half of the time or more)
  - many retransmissions
  - beacon overhead and beacon settings
  - your radios sharing a channel where both are heard
  - BSS colour collisions, unsuitable widths
- **Clients:**
  - devices that take much of a channel at low rates
  - clients with a poor link
  - why connections failed
  - slow roams
- **Interference and radar.**

Then the details: every access point of your networks (channel, width, security, PMF, roaming, WPS, beacon rate, colour), how
busy their channels were, the suggested channel plan, the clients' links, connection failures and roams, client readiness,
interference and radar, and how it was measured (which sensors, where).
