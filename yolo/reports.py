"""Occupancy analytics: estimated people present per hour, visitors, dwell time, plus a weekly summary
sent through a configured notifier (HTML email or plain text)."""
import json
import logging
import statistics
import threading
import time
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException

from .alerts import send
from .appearance import time_format
from .auth import current_user, require_admin

log = logging.getLogger("yolo.reports")

MIN_VISIT = 300  # ignore presence shorter than this (rotating probe MACs, passers-by)


def person_spans(ctx, since, until):
    """Presence spans per 'person key'. Each person-group counts once; otherwise each Wi-Fi phone
    counts once. Phones carried by the same person are usually grouped by the admin."""
    rows = ctx.rows(
        "SELECT s.mac, s.start_ts, s.end_ts, m.group_id, g.kind gkind, d.first_seen, d.dev_type, d.kind "
        "FROM sessions s JOIN devices d ON d.mac=s.mac LEFT JOIN device_meta m ON m.mac=s.mac "
        "LEFT JOIN groups g ON g.id=m.group_id "
        "WHERE s.type='presence' AND s.end_ts >= ? AND s.start_ts <= ? AND s.end_ts - s.start_ts >= ? AND "
        "((g.kind = 'person') OR (m.group_id IS NULL AND d.kind='wifi_client' AND d.dev_type='phone'))",
        (since, until, MIN_VISIT))
    spans, first = defaultdict(list), {}
    for r in rows:
        key = f"g{r['group_id']}" if r["gkind"] == "person" else r["mac"]
        spans[key].append((max(r["start_ts"], since), min(r["end_ts"], until)))
        first[key] = min(first.get(key, r["first_seen"]), r["first_seen"])
    # A person's devices overlap in time (phone + watch + earbuds): merge into one presence.
    for key, lst in spans.items():
        merged = []
        for a, b in sorted(lst):
            if merged and a <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        spans[key] = [tuple(m) for m in merged]
    return spans, first


def occupancy(ctx, days=7, tz=0, end=None):
    until = end or time.time()
    since = until - days * 86400
    spans, first = person_spans(ctx, since, until)
    off = tz * 60
    bucket = 3600
    start = int((since - off) // bucket * bucket + off)
    n = int((until - start) // bucket) + 1
    hourly = [set() for _ in range(n)]
    daily, dwell = defaultdict(set), defaultdict(float)
    for key, lst in spans.items():
        for a, b in lst:
            for i in range(max(0, int((a - start) // bucket)), min(n - 1, int((b - start) // bucket)) + 1):
                hourly[i].add(key)
            # Attribute presence to each local day it overlaps (visits can span midnight).
            day = int((a - off) // 86400)
            while day * 86400 + off < b:
                lo, hi = max(a, day * 86400 + off), min(b, (day + 1) * 86400 + off)
                if hi > lo:
                    daily[day].add(key)
                    dwell[(key, day)] += hi - lo
                day += 1
    series = [len(s) for s in hourly]
    heat = [[[] for _ in range(24)] for _ in range(7)]
    for i, c in enumerate(series):
        lt = start + i * bucket - off
        heat[int((lt // 86400 + 3) % 7)][int((lt % 86400) // 3600)].append(c)
    heat = [[round(sum(v) / len(v), 1) if v else 0 for v in row] for row in heat]
    days_out = []
    for day in sorted(daily):
        keys = daily[day]
        day_start = day * 86400 + off
        new = sum(1 for k in keys if first.get(k, 0) >= day_start)
        dw = [dwell[(k, day)] for k in keys]
        days_out.append({"day": day_start, "people": len(keys), "new": new, "returning": len(keys) - new,
                         "median_dwell": round(statistics.median(dw)) if dw else 0,
                         "peak": max((series[i] for i in range(n) if day_start <= start + i * bucket < day_start + 86400),
                                     default=0)})
    peak_i = max(range(n), key=lambda i: series[i]) if series else None
    all_dw = [v for v in dwell.values()]
    visitors = set().union(*daily.values()) if daily else set()
    return {
        "since": since, "until": until, "bucket": bucket, "t": [start + i * bucket for i in range(n)],
        "series": series, "heat": heat, "days": days_out,
        "summary": {
            "unique": len(visitors), "new": sum(1 for k in visitors if first.get(k, 0) >= since),
            "avg_present": round(sum(series) / len(series), 1) if series else 0,
            "peak": series[peak_i] if peak_i is not None else 0,
            "peak_at": start + peak_i * bucket if peak_i is not None else None,
            "median_dwell": round(statistics.median(all_dw)) if all_dw else 0,
        },
        "method": "People are estimated from Wi-Fi phones present for at least 5 minutes; devices you put in a "
                  "'person' group count as one person. Phones that are off, in flight mode or idle without "
                  "scanning are missed, and visitors' rotating MAC addresses can be counted more than once.",
    }


def _dur(s):
    s = int(s)
    return f"{s // 3600}h {s % 3600 // 60:02d}m" if s >= 3600 else f"{s // 60}m"


def weekly_summary(ctx):
    rep = occupancy(ctx, 7, tz=-int(time.localtime().tm_gmtoff / 60))
    now = time.time()
    since = now - 7 * 86400
    s = rep["summary"]
    new_dev = ctx.one("SELECT COUNT(*) n FROM devices WHERE first_seen >= ? AND randomized=0", (since,))["n"]
    alerts = ctx.one("SELECT COUNT(*) n FROM alert_log WHERE ts >= ?", (since,))["n"]
    findings = ctx.rows("SELECT severity, COUNT(*) n FROM findings WHERE status='open' GROUP BY severity")
    groups = ctx.rows("SELECT g.name, COUNT(DISTINCT CAST(s.start_ts/86400 AS INT)) days FROM groups g "
                      "JOIN device_meta m ON m.group_id=g.id JOIN sessions s ON s.mac=m.mac AND s.type='presence' "
                      "AND s.end_ts >= ? GROUP BY g.id ORDER BY g.name", (since,))
    peak = time.strftime("%a " + ("%I %p" if time_format(ctx).startswith("%I") else "%H:00"),
                         time.localtime(s["peak_at"])) if s["peak_at"] else "–"
    lines = [
        f"People (estimated): {s['unique']} unique, {s['new']} new, average {s['avg_present']} present, "
        f"peak {s['peak']} ({peak})",
        f"Median visit: {_dur(s['median_dwell'])}",
        f"New devices (non-randomized): {new_dev}",
        f"Alerts: {alerts}",
        "Open security findings: " + (", ".join(f"{f['n']} {f['severity']}" for f in findings) or "none"),
    ]
    if groups:
        lines.append("Groups seen: " + ", ".join(f"{g['name']} ({g['days']} days)" for g in groups))
    daily = "".join(f"<tr><td>{time.strftime('%a %d %b', time.localtime(d['day']))}</td><td>{d['people']}</td>"
                    f"<td>{d['new']}</td><td>{d['peak']}</td><td>{_dur(d['median_dwell'])}</td></tr>"
                    for d in rep["days"])
    html = f"""<div style="font-family:system-ui,sans-serif;color:#111;max-width:640px">
<h2 style="margin:0 0 4px">yolo weekly report</h2><p style="color:#666;margin:0 0 16px">
{time.strftime('%d %b', time.localtime(since))} – {time.strftime('%d %b %Y', time.localtime(now))}</p>
<ul>{''.join(f'<li>{l}</li>' for l in lines)}</ul>
<table cellpadding="6" style="border-collapse:collapse;font-size:14px"><tr style="text-align:left;color:#666">
<th>Day</th><th>People</th><th>New</th><th>Peak</th><th>Median visit</th></tr>{daily}</table>
<p style="color:#888;font-size:12px">{rep['method']}</p></div>"""
    return "yolo weekly report", "\n".join(lines), html


class ReportScheduler:
    def __init__(self, ctx):
        self.ctx = ctx

    def start(self, stop):
        threading.Thread(target=self.run, args=(stop,), daemon=True, name="reports").start()

    def due(self, cfg, now):
        lt = time.localtime(now)
        return cfg["email"] and cfg["notifier_id"] and lt.tm_wday == int(cfg["weekday"]) and \
            lt.tm_hour == int(cfg["hour"]) and now - (cfg.get("last_sent") or 0) > 6 * 86400

    def send_now(self):
        cfg = self.ctx.settings.get("report")
        n = self.ctx.one("SELECT * FROM notifiers WHERE id=?", (cfg["notifier_id"],))
        if not n:
            raise ValueError("Choose a notifier for the weekly report first")
        title, body, html = weekly_summary(self.ctx)
        send(n["type"], json.loads(n["config"] or "{}"), title, body, html=html)
        cfg["last_sent"] = time.time()
        self.ctx.settings.set("report", cfg)

    def run(self, stop):
        while not stop.wait(300):
            try:
                if self.due(self.ctx.settings.get("report"), time.time()):
                    self.send_now()
                    log.info("Weekly report sent")
            except Exception as e:
                log.warning("Weekly report failed: %s", e)


def routes(ctx):
    r = APIRouter()

    @r.get("/api/reports/occupancy")
    def occ(days: float = 7, tz: int = 0, end: float = 0, _=Depends(current_user)):
        return occupancy(ctx, min(days, 90), tz, end or None)

    @r.post("/api/reports/send")
    def send_report(_=Depends(require_admin)):
        try:
            ctx.reports.send_now()
        except Exception as e:
            raise HTTPException(400, str(e))
        return {"ok": True}

    return r
