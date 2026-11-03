"""Unknown Bluetooth tracker detection (anti-stalking).

An AirTag / Find My accessory, Tile or SmartTag that isn't yours and that keeps showing up exactly when a
person is around (arriving and leaving with them) may have been planted on them. For every unknown tag the
detector compares its presence with each person's presence: their "person" group, or a known phone.

Note: a separated AirTag keeps its Bluetooth address for up to ~24 hours, so following is judged per address,
which needs at least two arrivals/departures together within that time.
"""
import time

from fastapi import APIRouter, Depends

from .auth import current_user

RUN_EVERY = 600
LOOKBACK = 3 * 86400
MATCH_SLACK = 600       # tracker arrival/departure within this many seconds of the person's
MIN_TOGETHER = 1800     # at least 30 minutes of shared presence
FOLLOW_RATIO = 0.8      # share of the tracker's presence that falls inside the person's presence
MIN_MATCHES = 2         # arrivals + departures that coincide


def tracker_type(d):
    fp = (((d.get("extra") or {}).get("fp") or {}).get("ble") or {})
    uuids = set(fp.get("uuids") or [])
    if 0x12 in (fp.get("apple") or []):
        return "AirTag / Find My"
    if uuids & {"feed", "feec"}:
        return "Tile"
    if "fd5a" in uuids:
        return "Samsung SmartTag"
    if "fd44" in uuids:
        return "Find My network accessory"
    return "Tracker tag"


def merge(spans, gap=60):
    out = []
    for a, b in sorted(spans):
        if out and a <= out[-1][1] + gap:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out


def overlap(xs, ys):
    total, i, j = 0.0, 0, 0
    while i < len(xs) and j < len(ys):
        lo, hi = max(xs[i][0], ys[j][0]), min(xs[i][1], ys[j][1])
        if hi > lo:
            total += hi - lo
        if xs[i][1] < ys[j][1]:
            i += 1
        else:
            j += 1
    return total


def score(tracker, person, starts=None, ends=None):
    """Compare a tracker's presence spans with a person's. `starts`/`ends` are the arrival/departure times
    of the person's individual devices (default: of the merged presence). Returns stats for 'following'."""
    t_total = sum(b - a for a, b in tracker)
    shared = overlap(tracker, person)
    starts = starts if starts is not None else [a for a, _ in person]
    ends = ends if ends is not None else [b for _, b in person]
    arrivals = sum(1 for a, _ in tracker if any(abs(a - s) <= MATCH_SLACK for s in starts))
    departures = sum(1 for _, b in tracker if any(abs(b - e) <= MATCH_SLACK for e in ends))
    ratio = shared / t_total if t_total else 0
    p_total = sum(b - a for a, b in person)
    following = shared >= MIN_TOGETHER and ratio >= FOLLOW_RATIO and arrivals + departures >= MIN_MATCHES
    return {"shared": round(shared), "ratio": round(ratio, 3), "arrivals": arrivals, "departures": departures,
            "coverage": round(shared / p_total, 3) if p_total else 0, "following": following}


class TrackerMonitor:
    """Store plugin: every 10 minutes, checks unknown tags against people's presence."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.last_run = 0
        self.pending = False

    def candidates(self, since):
        rows = self.ctx.rows(
            "SELECT d.mac, d.name, d.vendor, d.extra, d.first_seen, d.last_seen, d.room, m.known, m.label "
            "FROM devices d LEFT JOIN device_meta m ON m.mac=d.mac WHERE d.kind='ble' AND d.dev_type='tag' "
            "AND d.last_seen >= ?", (since,))
        for r in rows:
            self.ctx.jsonf(r, "extra")
            r["tracker"] = tracker_type(r)
        return rows

    def people(self, since):
        """Person groups, plus known phones that aren't in a group."""
        out = {}
        for r in self.ctx.rows("SELECT g.id, g.name, s.mac, s.start_ts, s.end_ts FROM groups g JOIN device_meta m ON "
                               "m.group_id=g.id JOIN sessions s ON s.mac=m.mac AND s.type='presence' "
                               "JOIN devices d ON d.mac=m.mac WHERE g.kind='person' AND COALESCE(d.dev_type, '') != 'tag' "
                               "AND s.end_ts >= ?", (since,)):
            p = out.setdefault(f"group:{r['id']}", {"name": r["name"], "spans": [], "per": {}})
            p["spans"].append((r["start_ts"], r["end_ts"]))
            p["per"].setdefault(r["mac"], []).append((r["start_ts"], r["end_ts"]))
        for r in self.ctx.rows("SELECT d.mac, COALESCE(m.label, d.name, d.mac) name, s.start_ts, s.end_ts FROM devices d "
                               "JOIN device_meta m ON m.mac=d.mac JOIN sessions s ON s.mac=d.mac AND s.type='presence' "
                               "WHERE m.known=1 AND m.group_id IS NULL AND d.dev_type='phone' AND s.end_ts >= ?", (since,)):
            p = out.setdefault(r["mac"], {"name": r["name"], "spans": [], "per": {}})
            p["spans"].append((r["start_ts"], r["end_ts"]))
            p["per"].setdefault(r["mac"], []).append((r["start_ts"], r["end_ts"]))
        for p in out.values():
            p["spans"] = merge(p["spans"])
            # arrivals/departures of each of the person's devices (a watch may show up before the phone)
            per = [merge(v) for v in p.pop("per").values()]
            p["starts"] = [a for spans in per for a, _ in spans]
            p["ends"] = [b for spans in per for _, b in spans]
        return out

    def evaluate(self, now):
        since = now - LOOKBACK
        people = self.people(since)
        result = []
        for t in self.candidates(since):
            spans = merge([(r["start_ts"], r["end_ts"]) for r in self.ctx.rows(
                "SELECT start_ts, end_ts FROM sessions WHERE mac=? AND type='presence' AND end_ts >= ?", (t["mac"], since))])
            t["present"] = round(sum(b - a for a, b in spans))
            t["visits"] = len(spans)
            best = None
            for key, p in people.items():
                s = score(spans, p["spans"], p["starts"], p["ends"])
                s.update(person=key, person_name=p["name"])
                # With several candidates (people arriving together), prefer coinciding arrivals/departures,
                # then the person whose time the tag covers most.
                rank = (s["following"], s["arrivals"] + s["departures"], s["coverage"])
                if best is None or rank > (best["following"], best["arrivals"] + best["departures"], best["coverage"]):
                    best = s
            t["match"] = best
            t["following"] = bool(best and best["following"] and not t["known"])
            t.pop("extra", None)
            result.append(t)
        result.sort(key=lambda x: (not x["following"], bool(x["known"]), -(x["last_seen"] or 0)))
        return result

    def sweep(self, store, now):
        if now - self.last_run < RUN_EVERY:
            return
        self.last_run = now
        for t in self.evaluate(now):
            if not t["following"]:
                continue
            m = t["match"]
            detail = (f"Unknown {t['tracker']} {t['mac']} was present {m['ratio']:.0%} of its time together with "
                      f"{m['person_name']}, arriving/leaving with them {m['arrivals'] + m['departures']}×. "
                      f"If it isn't theirs, check bags, coats and the car. Mark it as known if it is.")
            self.ctx.security.finding(store, now, f"tracker:{t['mac']}", "unknown_tracker", "high", t["mac"], None,
                                      f"Unknown {t['tracker']} following {m['person_name']}", detail,
                                      event="tracker_following")


def routes(ctx):
    r = APIRouter()

    @r.get("/api/trackers")
    def trackers(_=Depends(current_user)):
        return {"trackers": ctx.trackers.evaluate(time.time()), "lookback_days": LOOKBACK // 86400}

    return r
