"""What is normal here, and events when it is not.

Once an hour, for the hour that just ended, three checks against the history that is already stored (the hourly presence roll-up):

* `activity_unusual`: far more devices were heard than is usual for this hour of the day. "Usual" is the median of the same hour
  on earlier days; "far more" is above the median by the largest of 3 robust standard deviations, half the median, and 10 devices.
* `unusual_time`: a device you named, marked as known, watch or put in a group was heard at an hour of the day at which it was never
  heard before (nor in the hour before or after).
* `vendor_new`: the first device ever from a maker (real addresses only: a random address has no maker).

All three stay quiet until there is enough history to call anything normal. They are events like any other: they show in the event
log, and an alert rule decides whether anyone is notified. The limits are rules of thumb, not tuned to a site.
"""
import logging
import statistics
import time

log = logging.getLogger("sniffowireless.baseline")

HOUR, DAY = 3600, 86400
MIN_DAYS = 7              # days of history before anything is called unusual
MIN_DEVICE_DAYS = 14      # a device's own history before its hours are called unusual
MIN_DEVICE_HOURS = 20     # ...and how many hours it must have been heard in that time
LOOK_BACK_DAYS = 28
SITE = "site"             # the "device" of an event that is about the place as a whole


def usual(counts):
    """(median, limit) of earlier counts for one hour of the day: above the limit is far more than usual."""
    med = statistics.median(counts)
    mad = statistics.median(abs(c - med) for c in counts)
    return med, med + max(3 * 1.4826 * mad, 0.5 * med, 10)


def activity(conn, hour):
    """(count, median, limit) if the hour had far more devices than the same hour on earlier days, else None."""
    count = conn.execute("SELECT COUNT(*) FROM presence_hours WHERE hour = ?", (hour,)).fetchone()[0]
    earlier = [conn.execute("SELECT COUNT(*) FROM presence_hours WHERE hour = ?", (hour - k * DAY,)).fetchone()[0]
               for k in range(1, LOOK_BACK_DAYS + 1)]
    earlier = [c for c in earlier if c]  # an hour with nothing at all is an hour the sensor was off
    if len(earlier) < MIN_DAYS:
        return None
    med, limit = usual(earlier)
    return (count, med, limit) if count > limit else None


def odd_hours(conn, hour, macs):
    """[(mac, days of history, earliest and latest usual hour of the day)] of the given devices that were heard in this hour, at an
    hour of the day (UTC) at which, and next to which, they were never heard before."""
    out, hod = [], hour // HOUR % 24
    for mac in macs:
        if not conn.execute("SELECT 1 FROM presence_hours WHERE hour = ? AND mac = ?", (hour, mac)).fetchone():
            continue
        # by address: the table is ordered by hour, so a search per device reads only that device's rows through this index
        before = [r[0] for r in conn.execute("SELECT minute / 3600 * 3600 h FROM samples WHERE mac = ? AND minute < ? AND minute >= ? "
                                             "GROUP BY h", (mac, hour, hour - LOOK_BACK_DAYS * DAY))]
        if len(before) < MIN_DEVICE_HOURS or hour - min(before) < MIN_DEVICE_DAYS * DAY:
            continue
        hods = {h // HOUR % 24 for h in before}
        if not hods & {(hod - 1) % 24, hod, (hod + 1) % 24}:
            out.append((mac, (hour - min(before)) // DAY, sorted(hods)))
    return out


def new_vendors(conn, hour):
    """[(vendor, mac)] of makers whose first device ever was first heard in this hour; nothing on a young installation."""
    oldest = conn.execute("SELECT MIN(first_seen) FROM devices").fetchone()[0]
    if oldest is None or hour - oldest < MIN_DAYS * DAY:
        return []
    return [(r[0], r[2]) for r in conn.execute(
        "SELECT vendor, MIN(first_seen) f, mac FROM devices WHERE vendor IS NOT NULL AND vendor != '' AND randomized = 0 "
        "GROUP BY vendor HAVING f >= ? AND f < ?", (hour, hour + HOUR))]


def _clock(hour_of_day_utc):
    """An hour of the day (UTC) as the server's local clock shows it."""
    t = time.localtime(hour_of_day_utc * HOUR)  # 1970-01-01 at that hour: only the offset matters
    return f"{t.tm_hour:02d}:00"


class BaselineMonitor:
    """Store plugin: checks each hour once, shortly after it ended."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.done = None

    def sweep(self, store, now):
        hour = int(now) // HOUR * HOUR - HOUR
        if self.done is None:  # after a restart: don't repeat the hour that was already checked
            row = store.conn.execute("SELECT value FROM meta WHERE key='baseline_hour'").fetchone()
            self.done = int(row[0]) if row else hour  # first run ever: start with the next hour
            if not row:
                store.conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('baseline_hour', ?)", (str(hour),))
        if hour <= self.done or now - (hour + HOUR) < 120:  # give the last samples of the hour time to be written
            return
        self.done = hour
        store.conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('baseline_hour', ?)", (str(hour),))
        try:
            self.check(store, hour, now)
        except Exception:
            log.exception("Baseline check failed")

    def check(self, store, hour, now):
        c = store.conn
        found = activity(c, hour)
        if found:
            count, med, _ = found
            store._event(now, SITE, "activity_unusual", None,
                         f"{count} devices heard between {_clock(hour // HOUR % 24)} and {_clock((hour // HOUR + 1) % 24)}; "
                         f"usual for this hour is about {round(med)}", always=True)
        for mac, days, hods in odd_hours(c, hour, sorted(store.important)):
            store._event(now, mac, "unusual_time", None,
                         f"Heard around {_clock(hour // HOUR % 24)}; in the {days} days before it was only heard at "
                         f"{', '.join(_clock(h) for h in hods[:12])}{'…' if len(hods) > 12 else ''}", always=True)
        for vendor, mac in new_vendors(c, hour):
            store._event(now, mac, "vendor_new", None, f"First device ever from {vendor}", always=True)
