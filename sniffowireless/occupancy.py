"""Roughly how many people are nearby: a count of phones, not of addresses.

Counting devices overstates people badly: one phone shows a Wi-Fi address and a Bluetooth address, and both change over time. So:

* Only **phones** count. Bluetooth: devices identified as a phone. Wi-Fi: clients identified as a phone, or not identified at all
  but using a random address (which is what phones do when they look for networks).
* Devices that the movement analysis calls **fixed** are left out (a phone-like thing that never moves is not a person).
* The count is made per **5 minutes**: within that time an address rarely changes, so one phone is one address per radio.
* A phone usually shows on both radios, but not always. So the answer is a range: **at least** the larger of the two counts (every
  Wi-Fi phone is also one of the Bluetooth phones, or the other way round), **at most** their sum, less the pairs that were linked
  by hand on the Matches page (those are known to be one device).

It is an estimate of phones heard, not a head count: people without a phone, with it switched off or out of range are missed, and
someone with two phones, or a laptop that looks like a phone, counts extra. It is not calibrated against a real count.
"""
import time

from fastapi import APIRouter, Depends

from .auth import current_user

SLOT = 300
MAX_HOURS = 7 * 24  # the per-minute samples it needs are large; a week is plenty to see a pattern
PHONES = ("SELECT mac, kind FROM devices WHERE last_seen >= ? AND ("
          "(kind IN ('ble', 'bt_classic') AND dev_type = 'phone') OR "
          "(kind = 'wifi_client' AND (dev_type = 'phone' OR (dev_type IS NULL AND randomized = 1)))) "
          "AND COALESCE(json_extract(extra, '$.mobility.c'), '') != 'fixed'")


def _phones(ctx, since):
    """{mac: 'wifi' | 'bt'} of the phone-like devices heard since, and the hand-linked pairs among them as [(wifi mac, bt mac)]."""
    radio = {r["mac"]: "wifi" if r["kind"] == "wifi_client" else "bt" for r in ctx.rows(PHONES, (since,))}
    pairs = []
    for r in ctx.rows("SELECT mac_a, mac_b FROM device_links WHERE status = 'linked'"):
        a, b = r["mac_a"], r["mac_b"]
        if radio.get(a) and radio.get(b) and radio[a] != radio[b]:
            pairs.append((a, b) if radio[a] == "wifi" else (b, a))
    return radio, pairs


def _range(macs, radio, pairs):
    wifi = sum(1 for m in macs if radio[m] == "wifi")
    bt = len(macs) - wifi
    linked = sum(1 for a, b in pairs if a in macs and b in macs)
    return {"low": max(wifi, bt), "high": wifi + bt - linked, "wifi": wifi, "bluetooth": bt, "linked": linked}


def now(ctx, at=None):
    """The range for the last 5 minutes."""
    at = at or time.time()
    radio, pairs = _phones(ctx, at - SLOT)
    # no DISTINCT: with it SQLite walks the whole table in address order instead of using the index on the minute
    macs = {r["mac"] for r in ctx.rows("SELECT mac FROM samples WHERE minute >= ?", (int(at - SLOT),)) if r["mac"] in radio}
    return _range(macs, radio, pairs)


def history(ctx, hours):
    """Per 5 minutes over the period; for more than a day the 5-minute figures are averaged per half hour (counting distinct
    addresses over a longer time would count a phone again each time its address changes)."""
    at = time.time()
    hours = max(1.0, min(float(hours), MAX_HOURS))
    since = int((at - hours * 3600) // SLOT * SLOT)
    radio, pairs = _phones(ctx, since)
    slots = {}
    for r in ctx.rows("SELECT DISTINCT (minute / ?) * ? slot, mac FROM samples WHERE minute >= ?", (SLOT, SLOT, since)):
        if r["mac"] in radio:
            slots.setdefault(r["slot"], set()).add(r["mac"])
    bucket = SLOT if hours <= 24 else 1800
    per = bucket // SLOT
    ts = list(range(since // bucket * bucket, int(at), bucket))
    low, high = [], []
    for t in ts:
        got = [_range(slots.get(t + i * SLOT, ()), radio, pairs) for i in range(per) if since <= t + i * SLOT <= at - SLOT]
        low.append(round(sum(g["low"] for g in got) / len(got), 1) if got else None)
        high.append(round(sum(g["high"] for g in got) / len(got), 1) if got else None)
    return {"t": ts, "low": low, "high": high, "bucket": bucket, "slot": SLOT, "hours": hours, "now": now(ctx, at)}


def routes(ctx):
    r = APIRouter()

    @r.get("/api/occupancy")
    def occupancy(hours: float = 24, _=Depends(current_user)):
        return history(ctx, hours)

    return r
