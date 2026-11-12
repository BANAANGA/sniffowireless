[← Back to the README](../README.md)

# Alerts & notifications

Events (arrived, left, group arrived/left, new device, connected, roamed, moved room, rogue AP, deauth flood, …) are matched against **rules** (Alerts → Rules). Each rule has:
- the events it reacts to
- which devices it covers: any, watched, unknown, specific MACs, groups, device types, or my networks' access points
- an optional time window (e.g. 23:00–06:00) and weekdays
- a per-device cooldown
- the notification channels to use

These rules are created on first start and only log to the alert history until you attach a channel:
- watched devices arriving or leaving
- security alerts
- unknown devices at night
- networks under investigation
- radar (DFS) on my networks
- LoRa and Zigbee security (the four events in bold below)

LoRa and Zigbee have their own events, usable in rules with the target *any* (they have no MAC address, so the device based targets don't apply): *New LoRa node*, *New Zigbee network*, **LoRa node sending unusually many frames** (40 frames in 5 minutes from one node), **LoRaWAN device repeating join requests** (8 in 10 minutes), **LoRaWAN frame counter went back** (a device restart, or replayed frames) and **Zigbee network is accepting new devices**. The thresholds are fixed and count only what the radio heard, which is part of the time when it hops between profiles.

**Channels** (Settings → Notifications):

| Type | You need |
|---|---|
| ntfy | server URL (default `https://ntfy.sh`), topic, optional access token |
| Telegram | bot token (from @BotFather) and chat ID |
| Discord | channel webhook URL |
| Webhook | URL; receives `{"title", "body", "severity", "event"}` as JSON, with an optional extra auth header |
| Email | SMTP host, port, STARTTLS/SSL, login, from and to |

Use **Send test** to check a channel. Secrets are never sent back to the browser.

## Unusual activity (baseline)

Once an hour the hour that just ended is compared with what is normal here, from the history that is already stored. Three events
can come out of that; they show in the event log, and the rule **Unusual activity** (created once, without a notification channel)
covers the first two.

| Event | Raised when |
|---|---|
| `activity_unusual` | Far more devices were heard than is usual for this hour of the day. Usual is the median of the same hour on the earlier days (up to 28); far more is above it by the largest of 3 robust standard deviations, half the median, and 10 devices. |
| `unusual_time` | A device you named, marked as known, watch, or put in a group was heard at an hour of the day at which it was never heard before, nor in the hour before or after. |
| `vendor_new` | The first device ever from a maker (real addresses only). Combine it with a schedule in a rule of your own, for example only at night. |

They stay quiet until there is enough history: 7 days for the place, and for a device 14 days in which it was heard in at least
20 different hours. Hours in which nothing at all was stored (the sensor was off) do not count as quiet hours. The limits are
rules of thumb and cannot be changed yet.

## Scheduled report

**Settings → Scheduled report** sends a summary through one of the notification channels, every week (over the last 7 days) or
every day (over the last 24 hours), at the hour you choose. Email channels get an HTML report, other channels plain text.

Besides the occupancy figures (people, new devices, alerts, open security findings, LoRa and Zigbee) it lists what needs a look,
and leaves out a heading when there is nothing under it:

- **New devices:** up to ten devices first seen in the period, with name, maker and type. Random addresses are left out.
- **Possible trackers:** the latest `tracker_following` events.
- **Security and warnings:** how often each high or medium severity event happened.
- **Sensors offline now:** remote sensors that have not reported for 10 minutes, with how long ago they last did. This is the state
  when the report is made; outages that ended before that are not listed.
