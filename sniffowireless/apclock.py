"""Beacon clock drift: tells apart two access points that use the same BSSID (an evil twin or a cloned MAC address).

Every beacon carries the sender's timer (TSF, in microseconds). Compared with the time the beacon was heard, `tsf - heard` stays on
a nearly straight line for one access point: its timer runs a few parts per million fast or slow. Two different access points
sending as the same BSSID are two different timers, and their lines lie far apart (they were started at different moments). A
single access point that restarts jumps once and stays on the new line; two that share an address make the readings jump back and
forth. So: readings are grouped into lines, and when two lines each hold several readings and the readings alternate between
them, it is reported. Needs about 5 minutes of beacons (one reading per 10 seconds); with a sensor on another clock the readings
are kept apart per sensor. Not proof: an access point whose timer is reset by roaming or load balancing can look the same.
"""
SPREAD = 1.0       # seconds: readings closer than this are the same line (clock drift over minutes is a few milliseconds)
MIN_EACH = 5       # readings on each line
MIN_SWITCHES = 3   # times the readings must hop from one line to the other
KEEP = 90          # readings kept per access point
MAX_APS = 4000


class ClockWatch:
    def __init__(self):
        self.reads = {}    # (sensor, bssid) -> [(heard, offset seconds)]
        self.flagged = {}

    def feed(self, sensor, bssid, heard, tsf):
        """Add a reading. Returns a description when this access point looks like two, else None."""
        k = (sensor, bssid)
        r = self.reads.get(k)
        if r is None:
            if len(self.reads) >= MAX_APS:
                self.reads.clear()
            r = self.reads[k] = []
        r.append((heard, tsf / 1e6 - heard))
        if len(r) > KEEP:
            del r[0]
        if len(r) < 2 * MIN_EACH:
            return None
        lines = []   # [representative offset, count]
        seq = []
        for _, off in r:
            for i, ln in enumerate(lines):
                if abs(off - ln[0]) <= SPREAD:
                    ln[1] += 1
                    seq.append(i)
                    break
            else:
                lines.append([off, 1])
                seq.append(len(lines) - 1)
        big = [i for i, ln in enumerate(lines) if ln[1] >= MIN_EACH]
        if len(big) < 2:
            return None
        hops = sum(1 for a, b in zip(seq, seq[1:]) if a != b and a in big and b in big)
        if hops < MIN_SWITCHES:
            return None
        return f"two beacon timers alternate under one address ({len(big)} clocks, {hops} switches in {int(r[-1][0] - r[0][0])} s)"

    def skew_ppm(self, sensor, bssid):
        """Drift of the timer in parts per million (least-squares slope of offset over time) when there are enough readings, else None."""
        r = self.reads.get((sensor, bssid)) or []
        if len(r) < 20 or r[-1][0] - r[0][0] < 300:
            return None
        base = r[-1][1]
        pts = [(t, o) for t, o in r if abs(o - base) <= SPREAD]   # only the current line
        if len(pts) < 20 or pts[-1][0] - pts[0][0] < 300:
            return None
        n = len(pts)
        mt, mo = sum(t for t, _ in pts) / n, sum(o for _, o in pts) / n
        den = sum((t - mt) ** 2 for t, _ in pts)
        if den <= 0:
            return None
        return round(sum((t - mt) * (o - mo) for t, o in pts) / den * 1e6, 1)
