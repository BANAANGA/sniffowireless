"""Alert rules, notification channels and the engine that matches stored events against rules."""
import json
import logging
import queue
import smtplib
import ssl
import threading
import time
import urllib.parse
import urllib.request
from contextlib import closing
from email.message import EmailMessage
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .auth import current_user, require_admin

log = logging.getLogger("yolo.alerts")

SCHEMA = """
CREATE TABLE IF NOT EXISTS notifiers(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, type TEXT NOT NULL, config TEXT, enabled INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS alert_rules(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, enabled INTEGER DEFAULT 1, events TEXT, target TEXT,
  schedule TEXT, notifiers TEXT, cooldown INTEGER DEFAULT 300, created REAL);
CREATE TABLE IF NOT EXISTS alert_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, rule_id INTEGER, rule_name TEXT, mac TEXT, type TEXT,
  title TEXT, body TEXT, severity TEXT, delivered TEXT);
CREATE INDEX IF NOT EXISTS idx_alert_log_ts ON alert_log(ts);
"""
EVENT_TYPES = {
    "arrived": "Device arrived", "left": "Device left", "new_device": "New device seen",
    "group_arrived": "Group arrived (first device)", "group_left": "Group left (all devices gone)",
    "connected": "Connected to a network", "disconnected": "Disconnected", "roamed": "Roamed between APs",
    "moved": "Moved to another room", "rogue_ap": "Rogue / evil-twin access point", "deauth_flood": "Deauthentication flood",
    "karma_ap": "KARMA-style access point", "deauth_broadcast": "Broadcast deauthentication",
    "security_finding": "Security finding on my networks", "rogue_dhcp": "Rogue / extra DHCP server",
    "arp_spoof": "ARP spoofing", "tracker_following": "Unknown tracker following someone",
    "interference": "Radio interference episode",
}
SEVERITY = {"rogue_ap": "high", "deauth_flood": "high", "karma_ap": "high", "security_finding": "medium",
            "rogue_dhcp": "high", "arp_spoof": "high", "tracker_following": "high", "interference": "medium",
            "deauth_broadcast": "medium", "new_device": "low"}
NOTIFIER_TYPES = {
    "ntfy": ["url", "topic", "token", "priority"],
    "telegram": ["bot_token", "chat_id"],
    "discord": ["webhook_url"],
    "webhook": ["url", "secret_header"],
    "email": ["host", "port", "security", "username", "password", "sender", "to"],
}
SECRET_FIELDS = {"token", "bot_token", "webhook_url", "secret_header", "password"}
MASK = "••••••••"
DEFAULT_RULES = [
    ("Watched devices arrive or leave", ["arrived", "left", "group_arrived", "group_left"], {"mode": "watchlist"}, {}),
    ("Security alerts", ["rogue_ap", "deauth_flood", "karma_ap", "security_finding", "rogue_dhcp", "arp_spoof",
                         "tracker_following"],
     {"mode": "any"}, {}),
    ("Unknown device at night", ["new_device", "arrived"], {"mode": "unknown"},
     {"start": "23:00", "end": "06:00"}),
]


# --------------------------------------------------------------- notifiers
def _post(url, data, headers=None, timeout=10):
    body = json.dumps(data).encode() if not isinstance(data, (bytes, str)) else \
        (data.encode() if isinstance(data, str) else data)
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "yolo", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status


def send(ntype, cfg, title, body, severity="low", event=None, html=None):
    """Deliver one message. Raises on failure."""
    if ntype == "ntfy":
        url = (cfg.get("url") or "https://ntfy.sh").rstrip("/") + "/" + urllib.parse.quote(cfg["topic"])
        prio = cfg.get("priority") or {"high": "5", "medium": "4"}.get(severity, "3")
        h = {"Title": title.encode("utf-8").decode("latin-1", "replace"), "Priority": str(prio), "Tags": "satellite"}
        if cfg.get("token"):
            h["Authorization"] = f"Bearer {cfg['token']}"
        req = urllib.request.Request(url, data=body.encode(), method="POST", headers=h)
        with urllib.request.urlopen(req, timeout=10):
            pass
    elif ntype == "telegram":
        _post(f"https://api.telegram.org/bot{cfg['bot_token']}/sendMessage",
              {"chat_id": cfg["chat_id"], "text": f"{title}\n{body}", "disable_web_page_preview": True})
    elif ntype == "discord":
        _post(cfg["webhook_url"], {"content": f"**{title}**\n{body}"[:1900]})
    elif ntype == "webhook":
        h = {}
        if cfg.get("secret_header") and ":" in cfg["secret_header"]:
            k, v = cfg["secret_header"].split(":", 1)
            h[k.strip()] = v.strip()
        _post(cfg["url"], {"title": title, "body": body, "severity": severity, "event": event}, h)
    elif ntype == "email":
        msg = EmailMessage()
        msg["Subject"], msg["From"], msg["To"] = title, cfg.get("sender") or cfg.get("username"), cfg["to"]
        msg.set_content(body)
        if html:
            msg.add_alternative(html, subtype="html")
        port = int(cfg.get("port") or (465 if cfg.get("security") == "ssl" else 587))
        if cfg.get("security") == "ssl":
            server = smtplib.SMTP_SSL(cfg["host"], port, timeout=15, context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(cfg["host"], port, timeout=15)
            if cfg.get("security", "starttls") == "starttls":
                server.starttls(context=ssl.create_default_context())
        with server:
            if cfg.get("username"):
                server.login(cfg["username"], cfg.get("password") or "")
            server.send_message(msg)
    else:
        raise ValueError(f"unknown notifier type {ntype}")


# --------------------------------------------------------------- matching
def in_schedule(schedule, ts):
    if not schedule:
        return True
    lt = time.localtime(ts)
    days = schedule.get("days")
    if days and lt.tm_wday not in days:
        return False
    start, end = schedule.get("start"), schedule.get("end")
    if not start or not end:
        return True
    cur = lt.tm_hour * 60 + lt.tm_min
    s = int(start[:2]) * 60 + int(start[3:5])
    e = int(end[:2]) * 60 + int(end[3:5])
    return s <= cur < e if s <= e else (cur >= s or cur < e)  # window may wrap midnight


def matches(rule, ev, dev, meta, group):
    if ev["type"] not in rule["events"]:
        return False
    t = rule["target"] or {}
    mode = t.get("mode", "any")
    if mode == "watchlist":
        if ev["type"].startswith("group_"):
            return bool(group and group.get("watch"))
        return bool((meta and meta.get("watch")) or (group and group.get("watch")))
    if mode == "unknown":
        # Devices not marked known. Randomized MACs and access points are skipped unless asked for:
        # phones rotate addresses constantly and neighbours' APs come and go.
        if (meta and meta.get("known")) or not dev:
            return False
        if dev.get("randomized") and not t.get("randomized"):
            return False
        return dev.get("kind") != "ap" or bool(t.get("aps"))
    if mode == "macs":
        return ev["mac"] in (t.get("macs") or [])
    if mode == "groups":
        gid = int(ev["peer"].split(":")[1]) if (ev.get("peer") or "").startswith("group:") else \
            (meta or {}).get("group_id")
        return gid in (t.get("groups") or [])
    if mode == "kinds":
        return bool(dev) and (dev.get("kind") in (t.get("kinds") or []) or dev.get("dev_type") in (t.get("kinds") or []))
    return True


def describe(ev, dev, meta, group):
    name = (meta or {}).get("label") or (dev or {}).get("name") or ((dev or {}).get("ident") or {}).get("label") \
        or (dev or {}).get("ssid") or ev["mac"]
    typ = ev["type"]
    gname = (group or {}).get("name") or ev.get("detail")
    titles = {
        "arrived": f"{name} arrived", "left": f"{name} left", "new_device": f"New device: {name}",
        "group_arrived": f"{gname} arrived", "group_left": f"{gname} left",
        "connected": f"{name} connected", "disconnected": f"{name} disconnected", "roamed": f"{name} roamed",
        "moved": f"{name} moved", "rogue_ap": f"Rogue access point: {ev.get('detail') or name}",
        "deauth_flood": "Deauthentication flood detected", "karma_ap": f"KARMA access point {ev['mac']}",
        "deauth_broadcast": f"Broadcast deauth from {name}", "security_finding": f"Security: {ev.get('detail')}",
        "rogue_dhcp": f"Rogue DHCP server {ev['mac']}", "arp_spoof": f"ARP spoofing by {name}",
        "tracker_following": f"{ev.get('detail') or 'Unknown tracker following someone'}",
        "interference": f"Interference: {ev.get('detail')}",
    }
    lines = [time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ev["ts"])), EVENT_TYPES.get(typ, typ)]
    if dev:
        idl = (dev.get("ident") or {}).get("label")
        lines.append(" · ".join(x for x in (ev["mac"], idl, dev.get("vendor")) if x))
        if dev.get("room"):
            lines.append(f"Room: {dev['room']}")
        if dev.get("last_rssi") is not None:
            lines.append(f"Signal: {dev['last_rssi']} dBm")
    if ev.get("peer") and not ev["peer"].startswith("group:"):
        lines.append(f"Peer: {ev['peer']}")
    if ev.get("detail") and typ not in ("group_arrived", "group_left"):
        lines.append(str(ev["detail"]))
    return titles.get(typ, f"{typ}: {name}"), "\n".join(lines)


class AlertEngine:
    def __init__(self, ctx):
        self.ctx = ctx
        self.q = queue.Queue(maxsize=10_000)
        self.cooldowns = {}
        self.rules_cache, self.rules_at = None, 0
        with closing(ctx.wdb()) as c:
            c.executescript(SCHEMA)
            if not c.execute("SELECT COUNT(*) FROM alert_rules").fetchone()[0]:
                for name, evs, target, sched in DEFAULT_RULES:
                    c.execute("INSERT INTO alert_rules(name, enabled, events, target, schedule, notifiers, cooldown, "
                              "created) VALUES(?,?,?,?,?,?,?,?)", (name, 1, json.dumps(evs), json.dumps(target),
                                                                     json.dumps(sched), "[]", 300, time.time()))

    def invalidate(self):
        self.rules_cache = None

    def rules(self):
        if self.rules_cache is None or time.time() - self.rules_at > 30:
            rs = self.ctx.rows("SELECT * FROM alert_rules WHERE enabled=1")
            for r in rs:
                self.ctx.jsonf(r, "events", "target", "schedule", "notifiers")
            self.rules_cache, self.rules_at = rs, time.time()
        return self.rules_cache

    def on_events(self, events):
        if events:
            try:
                self.q.put_nowait(events)
            except queue.Full:
                log.warning("Alert queue full; dropping %d events", len(events))

    def start(self, stop):
        threading.Thread(target=self.run, args=(stop,), daemon=True, name="alerts").start()

    def run(self, stop):
        while not stop.is_set():
            try:
                events = self.q.get(timeout=1)
            except queue.Empty:
                continue
            for ev in events:
                try:
                    self.handle(ev)
                except Exception:
                    log.exception("Alert handling failed")

    def handle(self, ev):
        rules = [r for r in self.rules() if ev["type"] in r["events"]]
        if not rules:
            return
        ctx = self.ctx
        dev = ctx.jsonf(ctx.one("SELECT * FROM devices WHERE mac=?", (ev["mac"],)), "ident")
        meta = ctx.one("SELECT * FROM device_meta WHERE mac=?", (ev["mac"],))
        gid = int(ev["peer"].split(":")[1]) if (ev.get("peer") or "").startswith("group:") else (meta or {}).get("group_id")
        group = ctx.one("SELECT * FROM groups WHERE id=?", (gid,)) if gid else None
        for rule in rules:
            if not matches(rule, ev, dev, meta, group) or not in_schedule(rule["schedule"], ev["ts"]):
                continue
            key = (rule["id"], ev["peer"] if ev["type"].startswith("group_") else ev["mac"], ev["type"])
            if ev["ts"] - self.cooldowns.get(key, 0) < (rule.get("cooldown") or 0):
                continue
            self.cooldowns[key] = ev["ts"]
            title, body = describe(ev, dev, meta, group)
            self.fire(rule, ev, title, body)

    def fire(self, rule, ev, title, body):
        sev = SEVERITY.get(ev["type"], "low")
        delivered = {}
        for nid in rule.get("notifiers") or []:
            n = self.ctx.one("SELECT * FROM notifiers WHERE id=? AND enabled=1", (nid,))
            if not n:
                continue
            try:
                send(n["type"], json.loads(n["config"] or "{}"), title, body, sev, ev)
                delivered[n["name"]] = "ok"
            except Exception as e:
                delivered[n["name"]] = f"error: {e}"[:200]
                log.warning("Notifier %s failed: %s", n["name"], e)
        self.ctx.execute("INSERT INTO alert_log(ts, rule_id, rule_name, mac, type, title, body, severity, delivered) "
                         "VALUES(?,?,?,?,?,?,?,?,?)", (ev["ts"], rule["id"], rule["name"], ev["mac"], ev["type"],
                                                       title, body, sev, json.dumps(delivered)))
        if len(self.cooldowns) > 50_000:
            self.cooldowns.clear()


# ------------------------------------------------------------------ routes
class NotifierIn(BaseModel):
    name: str
    type: str
    config: dict = {}
    enabled: bool = True


class RuleIn(BaseModel):
    name: str
    enabled: bool = True
    events: List[str]
    target: dict = {"mode": "any"}
    schedule: dict = {}
    notifiers: List[int] = []
    cooldown: int = 300


def _masked(n):
    cfg = json.loads(n["config"] or "{}")
    n["config"] = {k: (MASK if k in SECRET_FIELDS and v else v) for k, v in cfg.items()}
    return n


def routes(ctx):
    r = APIRouter()
    eng = ctx.alerts

    @r.get("/api/alerts/meta")
    def meta(_=Depends(current_user)):
        return {"events": EVENT_TYPES, "notifier_types": NOTIFIER_TYPES, "severity": SEVERITY}

    @r.get("/api/alerts")
    def history(before: int = 0, limit: int = 100, _=Depends(current_user)):
        w, p = ("WHERE id < ?", [before]) if before else ("", [])
        items = ctx.rows(f"SELECT * FROM alert_log {w} ORDER BY id DESC LIMIT ?", p + [min(limit, 500)])
        for i in items:
            ctx.jsonf(i, "delivered")
        return {"items": items}

    @r.get("/api/notifiers")
    def notifiers(_=Depends(require_admin)):
        return [_masked(n) for n in ctx.rows("SELECT * FROM notifiers ORDER BY name")]

    def _save_notifier(body, nid=None):
        if body.type not in NOTIFIER_TYPES:
            raise HTTPException(400, "unknown notifier type")
        cfg = {k: v for k, v in body.config.items() if k in NOTIFIER_TYPES[body.type]}
        if nid:
            old = json.loads((ctx.one("SELECT config FROM notifiers WHERE id=?", (nid,)) or {}).get("config") or "{}")
            cfg = {k: (old.get(k) if v == MASK else v) for k, v in cfg.items()}
        need = {"ntfy": ["topic"], "telegram": ["bot_token", "chat_id"], "discord": ["webhook_url"],
                "webhook": ["url"], "email": ["host", "to"]}[body.type]
        missing = [k for k in need if not cfg.get(k)]
        if missing:
            raise HTTPException(400, f"missing: {', '.join(missing)}")
        return cfg

    @r.post("/api/notifiers")
    def add_notifier(body: NotifierIn, _=Depends(require_admin)):
        cfg = _save_notifier(body)
        with closing(ctx.wdb()) as c:
            nid = c.execute("INSERT INTO notifiers(name, type, config, enabled) VALUES(?,?,?,?)",
                            (body.name, body.type, json.dumps(cfg), int(body.enabled))).lastrowid
        return {"id": nid}

    @r.put("/api/notifiers/{nid}")
    def update_notifier(nid: int, body: NotifierIn, _=Depends(require_admin)):
        cfg = _save_notifier(body, nid)
        ctx.execute("UPDATE notifiers SET name=?, type=?, config=?, enabled=? WHERE id=?",
                    (body.name, body.type, json.dumps(cfg), int(body.enabled), nid))
        return {"ok": True}

    @r.delete("/api/notifiers/{nid}")
    def delete_notifier(nid: int, _=Depends(require_admin)):
        ctx.execute("DELETE FROM notifiers WHERE id=?", (nid,))
        eng.invalidate()
        return {"ok": True}

    @r.post("/api/notifiers/{nid}/test")
    def test_notifier(nid: int, _=Depends(require_admin)):
        n = ctx.one("SELECT * FROM notifiers WHERE id=?", (nid,))
        if not n:
            raise HTTPException(404)
        try:
            send(n["type"], json.loads(n["config"] or "{}"), "yolo test notification",
                 "If you can read this, alerts from yolo will reach you here.", "low",
                 html="<p>If you can read this, alerts from <b>yolo</b> will reach you here.</p>")
        except Exception as e:
            raise HTTPException(502, f"Delivery failed: {e}")
        return {"ok": True}

    @r.get("/api/alert-rules")
    def rules(_=Depends(current_user)):
        rs = ctx.rows("SELECT * FROM alert_rules ORDER BY id")
        for x in rs:
            ctx.jsonf(x, "events", "target", "schedule", "notifiers")
        return rs

    def _check_rule(body):
        bad = [e for e in body.events if e not in EVENT_TYPES]
        if bad or not body.events:
            raise HTTPException(400, f"invalid events: {bad or 'none selected'}")
        for k in ("start", "end"):
            v = body.schedule.get(k)
            if v and (len(v) != 5 or v[2] != ":"):
                raise HTTPException(400, "times must be HH:MM")

    @r.post("/api/alert-rules")
    def add_rule(body: RuleIn, _=Depends(require_admin)):
        _check_rule(body)
        with closing(ctx.wdb()) as c:
            rid = c.execute("INSERT INTO alert_rules(name, enabled, events, target, schedule, notifiers, cooldown, "
                            "created) VALUES(?,?,?,?,?,?,?,?)",
                            (body.name, int(body.enabled), json.dumps(body.events), json.dumps(body.target),
                             json.dumps(body.schedule), json.dumps(body.notifiers), body.cooldown, time.time())).lastrowid
        eng.invalidate()
        return {"id": rid}

    @r.put("/api/alert-rules/{rid}")
    def update_rule(rid: int, body: RuleIn, _=Depends(require_admin)):
        _check_rule(body)
        ctx.execute("UPDATE alert_rules SET name=?, enabled=?, events=?, target=?, schedule=?, notifiers=?, "
                    "cooldown=? WHERE id=?", (body.name, int(body.enabled), json.dumps(body.events),
                                               json.dumps(body.target), json.dumps(body.schedule),
                                               json.dumps(body.notifiers), body.cooldown, rid))
        eng.invalidate()
        return {"ok": True}

    @r.delete("/api/alert-rules/{rid}")
    def delete_rule(rid: int, _=Depends(require_admin)):
        ctx.execute("DELETE FROM alert_rules WHERE id=?", (rid,))
        eng.invalidate()
        return {"ok": True}

    return r
