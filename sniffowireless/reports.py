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

log = logging.getLogger("sniffowireless.reports")

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


def radio_lines(ctx, since):
    """LoRa and Zigbee lines of the weekly report: only for modules that are on and have something to say."""
    from .modules import disabled
    off, out = set(disabled(ctx)), []
    try:
        if "lora" not in off:
            nodes = ctx.one("SELECT COUNT(*) n, SUM(first_seen >= ?) new FROM lora_nodes WHERE last_seen >= ?", (since, since))
            if nodes["n"]:
                from .lora_protocols import PROTOCOLS
                per = ctx.rows("SELECT protocol, SUM(packets) n FROM lora_stats WHERE minute >= ? GROUP BY protocol ORDER BY n DESC", (int(since),))
                out.append(f"LoRa: {nodes['n']} nodes heard ({nodes['new'] or 0} new), " + ", ".join(
                    f"{PROTOCOLS.get(r['protocol'], r['protocol'])} {r['n']}" for r in per) + " frames")
        if "zigbee" not in off:
            z = ctx.one("SELECT COUNT(*) n FROM zigbee_radios WHERE last_seen >= ?", (since,))["n"]
            if z:
                nets = ctx.one("SELECT COUNT(*) n, SUM(first_seen >= ?) new FROM zigbee_networks WHERE last_seen >= ?", (since, since))
                out.append(f"Zigbee: {z} radios on {nets['n']} networks ({nets['new'] or 0} new)")
        n = ctx.one("SELECT COUNT(*) n FROM events WHERE ts >= ? AND type IN ('lora_flood','lora_join_flood','lora_fcnt_reset','zigbee_permit_join')", (since,))["n"]
        if n and not ({"lora", "zigbee"} <= off):
            out.append(f"LoRa / Zigbee warnings: {n} (see Events)")
    except Exception:  # tables not there (yet)
        pass
    return out


SENSOR_QUIET = 600  # a remote sensor that has not reported for this long is listed as offline


def digest_lines(ctx, since, now):
    """What happened in the period that someone should look at: [(heading, [lines])], only for headings with something under them."""
    from .alerts import EVENT_TYPES, SEVERITY
    out = []
    new = ctx.rows("SELECT d.mac, d.name, d.vendor, d.dev_type, d.kind, m.label FROM devices d LEFT JOIN device_meta m ON m.mac = d.mac "
                   "WHERE d.first_seen >= ? AND d.randomized = 0 ORDER BY d.first_seen DESC LIMIT 11", (since,))
    if new:
        from .identify import TYPE_LABELS
        lines = [" · ".join(x for x in (d["label"] or d["name"] or d["mac"], d["vendor"], TYPE_LABELS.get(d["dev_type"])) if x) for d in new[:10]]
        if len(new) > 10:
            lines.append("and more: see Devices, sorted by first seen")
        out.append(("New devices", lines))
    trackers = ctx.rows("SELECT ts, mac, detail FROM events WHERE ts >= ? AND type = 'tracker_following' ORDER BY ts DESC LIMIT 5", (since,))
    if trackers:
        out.append(("Possible trackers", [f"{time.strftime('%a %H:%M', time.localtime(t['ts']))}: {t['detail'] or t['mac']}" for t in trackers]))
    serious = [t for t, sev in SEVERITY.items() if sev in ("high", "medium") and t != "tracker_following"]
    events = ctx.rows(f"SELECT type, COUNT(*) n FROM events WHERE ts >= ? AND type IN ({','.join('?' * len(serious))}) GROUP BY type ORDER BY n DESC",
                      (since, *serious))
    if events:
        out.append(("Security and warnings", [f"{EVENT_TYPES.get(e['type'], e['type'])}: {e['n']}" for e in events]))
    try:
        quiet = ctx.rows("SELECT name, id, last_seen FROM sensors WHERE id != 'local' AND COALESCE(last_seen, 0) < ? ORDER BY name", (now - SENSOR_QUIET,))
    except Exception:  # no sensors table (yet)
        quiet = []
    if quiet:
        out.append(("Sensors offline now", [f"{q['name'] or q['id']}: " + (f"last report {_dur(now - q['last_seen'])} ago" if q["last_seen"] else "never reported")
                                            for q in quiet]))
    return out


def weekly_summary(ctx):
    return summary(ctx, 7)


def summary(ctx, days=7):
    """(title, text, html) of the report over the last `days` days: 7 for the weekly one, 1 for the daily one."""
    import html as htmllib
    rep = occupancy(ctx, days, tz=-int(time.localtime().tm_gmtoff / 60))
    now = time.time()
    since = now - days * 86400
    what = "daily" if days == 1 else "weekly"
    sections = digest_lines(ctx, since, now)
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
    lines += radio_lines(ctx, since)
    if groups:
        lines.append("Groups seen: " + ", ".join(f"{g['name']} ({g['days']} days)" for g in groups))
    daily = "".join(f"<tr><td>{time.strftime('%a %d %b', time.localtime(d['day']))}</td><td>{d['people']}</td>"
                    f"<td>{d['new']}</td><td>{d['peak']}</td><td>{_dur(d['median_dwell'])}</td></tr>"
                    for d in rep["days"])
    html = f"""<div style="font-family:system-ui,sans-serif;color:#111;max-width:640px">
<h2 style="margin:0 0 4px">sniffowireless {what} report</h2><p style="color:#666;margin:0 0 16px">
{time.strftime('%d %b', time.localtime(since))} – {time.strftime('%d %b %Y', time.localtime(now))}</p>
<ul>{''.join(f'<li>{htmllib.escape(l)}</li>' for l in lines)}</ul>
{''.join(f'<h3 style="margin:16px 0 4px;font-size:15px">{htmllib.escape(h)}</h3><ul style="margin-top:0">' + ''.join(f'<li>{htmllib.escape(i)}</li>' for i in items) + '</ul>' for h, items in sections)}
<table cellpadding="6" style="border-collapse:collapse;font-size:14px"><tr style="text-align:left;color:#666">
<th>Day</th><th>People</th><th>New</th><th>Peak</th><th>Median visit</th></tr>{daily}</table>
<p style="color:#888;font-size:12px">{rep['method']}</p></div>"""
    text = "\n".join(lines)
    for head, items in sections:
        text += f"\n\n{head}\n" + "\n".join(f"- {i}" for i in items)
    return f"sniffowireless {what} report", text, html


class ReportScheduler:
    def __init__(self, ctx):
        self.ctx = ctx

    def start(self, stop):
        threading.Thread(target=self.run, args=(stop,), daemon=True, name="reports").start()

    def due(self, cfg, now):
        lt = time.localtime(now)
        if not (cfg["email"] and cfg["notifier_id"] and lt.tm_hour == int(cfg["hour"])):
            return False
        if cfg.get("daily"):  # every day at that hour
            return now - (cfg.get("last_sent") or 0) > 20 * 3600
        return lt.tm_wday == int(cfg["weekday"]) and now - (cfg.get("last_sent") or 0) > 6 * 86400

    def send_now(self):
        cfg = self.ctx.settings.get("report")
        n = self.ctx.one("SELECT * FROM notifiers WHERE id=?", (cfg["notifier_id"],))
        if not n:
            raise ValueError("Choose a notifier for the report first")
        title, body, html = summary(self.ctx, 1 if cfg.get("daily") else 7)
        send(n["type"], json.loads(n["config"] or "{}"), title, body, html=html)
        cfg["last_sent"] = time.time()
        self.ctx.settings.set("report", cfg)

    def run(self, stop):
        while not stop.wait(300):
            try:
                if self.due(self.ctx.settings.get("report"), time.time()):
                    self.send_now()
                    log.info("Report sent")
            except Exception as e:
                log.warning("Report failed: %s", e)


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
