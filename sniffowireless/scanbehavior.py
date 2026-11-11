"""How a Wi-Fi client scans: the shape of its probe-request bursts.

A device looking for networks sends a burst of probe requests (one per channel), pauses, and repeats. How many frames a burst has, how
far apart they are inside it, and how long the pause is depends on the Wi-Fi driver and the operating system, not on the user, and it
stays the same when the device changes its MAC address. After three bursts a short signature is made of the three (each rounded
to a coarse step, so a little jitter gives the same signature). It is used the same way as the capability pattern: when other
devices with the same signature have a known OS, that is evidence (weaker than the capability pattern).

Limits: a sensor that hops over channels hears only part of every burst, and a busy radio hears a different part each time, so the
numbers are blurry; devices heard far away lose frames. Treat a match as a hint.
"""
import math
import statistics

BURST_GAP = 1.5     # seconds of silence that end a burst
NEEDED = 3          # finished bursts before a signature is made
MAX_DEVICES = 20000


def _bucket(x, floor=1):
    return int(round(math.log2(max(x, floor))))


def size_bucket(n):
    return n if n <= 3 else 4 if n <= 6 else 7 if n <= 12 else 13


def make_signature(sizes, gaps, periods):
    """sizes: frames per finished burst; gaps: mean seconds between frames within each burst; periods: seconds between burst starts."""
    return f"n{size_bucket(round(statistics.median(sizes)))}|g{_bucket(statistics.median(gaps) * 1000)}|p{_bucket(statistics.median(periods))}"


class ScanTracker:
    def __init__(self):
        self.state = {}

    def feed(self, mac, ts):
        """Add one probe request heard from `mac`. Returns {"sig", "bursts", "size", "gap_ms", "period"} when it is new or changed, else None."""
        s = self.state.get(mac)
        if s is None:
            if len(self.state) >= MAX_DEVICES:
                self.state.clear()
            self.state[mac] = {"last": ts, "start": ts, "n": 1, "sizes": [], "gaps": [], "starts": [], "sig": None}
            return None
        if ts < s["last"]:
            return None
        if ts - s["last"] <= BURST_GAP:
            s["n"] += 1
            s["last"] = ts
            return None
        # the previous burst is finished
        s["sizes"].append(s["n"])
        s["gaps"].append((s["last"] - s["start"]) / (s["n"] - 1) if s["n"] > 1 else 0.0)
        s["starts"].append(s["start"])
        for k in ("sizes", "gaps", "starts"):
            del s[k][:-12]
        s["start"] = s["last"] = ts
        s["n"] = 1
        if len(s["sizes"]) < NEEDED:
            return None
        multi = [g for n, g in zip(s["sizes"], s["gaps"]) if n > 1] or [0.0]
        periods = [b - a for a, b in zip(s["starts"], s["starts"][1:])]
        sig = make_signature(s["sizes"], multi, periods)
        if sig == s["sig"]:
            return None
        s["sig"] = sig
        return {"sig": sig, "bursts": len(s["sizes"]), "size": round(statistics.median(s["sizes"])),
                "gap_ms": round(statistics.median(multi) * 1000), "period": round(statistics.median(periods))}
