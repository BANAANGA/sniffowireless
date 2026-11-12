# People nearby

The overview has a **People nearby** card and Statistics a graph of the same figure over time. It is an estimate of how many
phones are in range, as a range, not a head count.

## Why not just count devices

One phone shows a Wi-Fi address and a Bluetooth address, and both change over time. Counting addresses over an hour can count one
phone a dozen times.

## How it is counted

- **Only phones count.** Bluetooth: devices identified as a phone. Wi-Fi: clients identified as a phone, or not identified at all
  but using a random address, which is what phones do when they look for networks.
- **Devices that never move are left out** (the *Fixed* class of the movement analysis).
- **Per 5 minutes.** Within that time an address rarely changes, so one phone is one address per radio. For periods longer than a
  day the graph shows half-hour averages of the 5-minute figures.
- **A range.** A phone usually shows on both radios, but not always. *At least* is the larger of the Wi-Fi and Bluetooth counts,
  *at most* is their sum. A Wi-Fi and a Bluetooth address that you linked on the Matches page count once.

## Limits

- People without a phone, with it switched off, or out of range are missed.
- Someone with two phones counts twice, and a laptop or tablet that is not identified and uses a random address counts as a phone.
- It is not calibrated against a real count. Use it to see the pattern (busy and quiet times), not as an exact number.
- The graph goes back at most 7 days.

## API

`GET /api/occupancy?hours=24` returns `t`, `low`, `high` (one value per bucket), `bucket`, and `now` (`low`, `high`, `wifi`,
`bluetooth`, `linked`). `GET /api/summary` carries the current range as `people`.
