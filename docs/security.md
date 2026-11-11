[← Back to the README](../README.md)

# Security monitoring

Configure **My networks** first (Settings → My networks), then mark your own access points as **trusted** (Security page, *Trust all listed* on a clean setup). sniffowireless then reports:

| Finding | How it's detected |
|---|---|
| **Rogue / evil-twin AP** | one of your SSIDs broadcast by an untrusted BSSID; *high* when security or vendor differs from your trusted APs or the BSSID is locally administered |
| **Deauthentication flood** | ≥ 25 deauth/disassoc frames within 10 s for one BSSID (configurable) |
| **KARMA-style AP** | one BSSID advertising ≥ 4 different SSIDs within 10 minutes (configurable) |
| **Open / WEP / WPA-TKIP network** | on your own SSIDs |
| **WPS enabled** | WPS element in your AP's beacons |
| **No WPA3** | informational |

| **Unknown tracker following someone** | an AirTag/Find My device, Tile or SmartTag not marked as yours that is present ≥ 80 % of its time together with one person (a "person" group or a known phone) and arrived or left with them at least twice |

Findings can be acknowledged (no repeat alerts) or resolved (they reopen if the condition returns). All detection is passive: sniffowireless never transmits deauths or other attack frames.

## Bluetooth trackers

The Security page lists every tracker tag seen in the last 3 days:
- its type (AirTag / Find My, Tile, SmartTag)
- who it moves with, what share of its time it spends with them, and how often they arrived or left together
- its status: yours, unknown, or **possibly following**

Click **It's mine** for your own tags (keys, bags, the car) and they're ignored from then on. A separated AirTag keeps its Bluetooth address for up to about 24 hours, so a planted tag shows up as "following" within a day of moving with someone. Phones' built-in unknown-tracker alerts complement this, but sniffowireless also covers people without a smartphone and tags that phones don't report.

## Interference

While the sensor hops channels it records each channel's noise floor and retransmission rate. Every 5 minutes, sniffowireless compares the last 10 minutes, minute by minute, with that channel's own 24-hour baseline. Two or more minutes of **+6 dB noise**, or retries ≥ 30 % and double the normal rate while the channel isn't busy, open an **interference episode**. The episode is classified as:
- *Microwave oven likely:* a short burst centred on channels 6–13
- *Broadband*, *narrowband* or *persistent* 2.4 GHz interferer (video senders, baby monitors, cordless phones, faulty power supplies)
- *Non-Wi-Fi interference on 5 GHz:* radar, video links

Episodes are listed on the **Channels** page and can trigger alerts (event type *Radio interference episode*). Detection needs a day of measurements as a baseline. Adapters that don't report a noise level are judged on retransmissions only.

## Cloned access-point addresses

Every beacon carries the access point's own timer. Heard over a few minutes, the timer of one access point runs on a straight line (a few parts per million fast or slow; shown as *Clock drift* on the device page). Two access points sending under the same BSSID have two timers that were started at different moments, so the readings jump back and forth. When two such lines each hold several readings and the readings alternate, the event *Two access points share one address* (`ap_clock_conflict`, high severity) is raised, at most once an hour per address. It needs about 5 minutes of beacons (one reading per 10 seconds) and is kept apart per sensor. It is a strong hint, not proof: an access point that resets its timer on its own can look the same, and a clone that copies the timer is not seen.

## DFS / radar

5 GHz channels 52–144 are shared with weather, airport and military radar. An access point on one of these **DFS** channels has to listen for radar; when it hears it, it must leave the channel within seconds and stay away for 30 minutes. Most access points warn their clients first with a **Channel Switch Announcement** (CSA) in their beacons. sniffowireless reads these from every beacon it hears, along with each access point's channel, and records:

| Event | When |
|---|---|
| *Access point announced a channel switch* | a beacon carries a (extended) CSA |
| *Access point changed channel* | an access point is seen on a new channel several times in a row |
| *Radar on a DFS channel* | the switch or move is away from a DFS channel: radar is the likely cause |

Neighbours' access points count too: radar is a property of the location, so their hits tell you which channels to avoid. The **Channels** page shows radar hits per DFS channel, channels that are closed right now, the switch history and the access points currently on DFS channels. The alert rule *Radar (DFS) on my networks* is created automatically; it fires for your own access points (Settings → My networks). If your own access point keeps getting pushed off a DFS channel, pick a non-DFS channel (36–48 or 149–165) or one without hits.

Requires a sensor that hops over (or sits on) the DFS channels in `WIFI_CHANNELS`. A move is only seen while sniffowireless hears the access point both before and after it.
