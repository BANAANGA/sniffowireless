"""Fixed or mobile: how much a device's signal strength wanders over time.

A device that stays where it is has a steady signal; one that is carried around does not. From the per-minute signal samples of the
last 48 hours, the signal is averaged in 10-minute bins (which removes the minute-to-minute flutter every radio has) and the spread
(standard deviation) of those bin averages is the measure:

    up to 2.5 dB   fixed          (an appliance, an access point, a device left on a shelf)
    up to 5 dB     mostly fixed   (moves a little, or the room changes around it)
    above 5 dB     mobile         (carried about)

It needs at least 2 hours of presence (12 bins) before it says anything. Those limits are rules of thumb, not calibrated: people
and doors change the signal of a fixed device, and a phone left on a desk looks fixed. It says nothing about how important a device is.
"""
import logging
import threading

log = logging.getLogger("sniffowireless.mobility")

BIN = 600
WINDOW = 48 * 3600
MIN_BINS = 12
FIXED_STD, MOBILE_STD = 2.5, 5.0
INTERVAL = 3 * 3600
LABELS = {"fixed": "Fixed", "mostly": "Mostly fixed", "mobile": "Mobile"}
SQL = ("WITH b AS (SELECT mac, minute / ? AS bin, SUM(rssi_sum) * 1.0 / SUM(rssi_count) AS m FROM samples "
       "WHERE minute >= ? AND rssi_count > 0 GROUP BY mac, bin) "
       "SELECT mac, COUNT(*) AS bins, AVG(m) AS mean, AVG(m * m) - AVG(m) * AVG(m) AS var FROM b GROUP BY mac HAVING COUNT(*) >= ?")


def classify(std):
    return "fixed" if std <= FIXED_STD else "mostly" if std <= MOBILE_STD else "mobile"


def compute(conn, now):
    """{mac: {"c": class, "std": dB, "bins": n, "ts": now}} for every device with enough signal samples in the window."""
    out = {}
    for mac, bins, mean, var in conn.execute(SQL, (BIN, int(now - WINDOW), MIN_BINS)).fetchall():
        std = max(0.0, var or 0.0) ** 0.5
        out[mac] = {"c": classify(std), "std": round(std, 1), "bins": bins, "ts": int(now)}
    return out


class MobilityUpdater:
    """Background thread: recomputes every few hours on a read-only connection and hands the result to the writer thread."""

    def __init__(self, ctx, first_after=120):
        self.ctx, self.first_after = ctx, first_after

    def start(self, stop):
        threading.Thread(target=self._run, args=(stop,), daemon=True, name="mobility").start()

    def _run(self, stop):
        import time
        from .store import connect
        stop.wait(self.first_after)
        while not stop.is_set():
            try:
                conn = connect(self.ctx.cfg.db_path, readonly=True)
                try:
                    result = compute(conn, time.time())
                finally:
                    conn.close()
                items = list(result.items())
                for i in range(0, len(items), 2000):
                    chunk = dict(items[i:i + 2000])
                    self.ctx.store.command(lambda st, c=chunk: st.apply_mobility(c))
                self.ctx.store.command(lambda st, keep=frozenset(result): st.clear_mobility(keep))
                log.info("Fixed or mobile worked out for %d devices", len(result))
            except Exception:
                log.exception("Working out which devices are fixed or mobile failed")
            stop.wait(INTERVAL)
