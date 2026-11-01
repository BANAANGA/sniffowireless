"""HTTP API + static single-page UI."""
import base64
import csv
import io
import json
import math
import secrets
import time
from contextlib import closing
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import status
from .store import connect

KINDS = ("ap", "wifi_client", "ble", "bt_classic")
SORTABLE = {"last_seen", "first_seen", "packets", "last_rssi", "best_rssi", "mac", "vendor",
            "name", "ssid", "kind", "channel"}


def overlap_counts(rows, since, until, bucket):
    """Count distinct macs whose [start, end] overlaps each time bucket."""
    n = max(1, math.ceil((until - since) / bucket))
    sets = [set() for _ in range(n)]
    for mac, start, end in rows:
        i0 = max(0, int((start - since) // bucket))
        i1 = min(n - 1, int((end - since) // bucket))
        for i in range(i0, i1 + 1):
            sets[i].add(mac)
    return [(since + i * bucket, len(s)) for i, s in enumerate(sets)]


def create_app(cfg, store):
    app = FastAPI(title="yolo", docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)
    static = Path(__file__).parent / "static"
    vendor_dir = Path("/app/vendor")

    if cfg.web_user:
        @app.middleware("http")
        async def basic_auth(request: Request, call_next):
            if request.url.path == "/api/health":
                return await call_next(request)
            ok = False
            h = request.headers.get("authorization", "")
            if h.lower().startswith("basic "):
                try:
                    u, _, p = base64.b64decode(h[6:]).decode().partition(":")
                    ok = secrets.compare_digest(u, cfg.web_user) and secrets.compare_digest(p, cfg.web_password)
                except Exception:
                    ok = False
            if not ok:
                return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="yolo"'})
            return await call_next(request)

    def rows(sql, params=()):
        with closing(connect(cfg.db_path, readonly=True)) as c:
            return [dict(r) for r in c.execute(sql, params)]

    def one(sql, params=()):
        r = rows(sql, params)
        return r[0] if r else None

    def _dev(d):
        if d and isinstance(d.get("extra"), str):
            d["extra"] = json.loads(d["extra"] or "{}")
        return d

    # ---------------------------------------------------------------- overview
    @app.get("/api/health")
    def health():
        return {"ok": True}

    @app.get("/api/status")
    def get_status():
        return {"sensors": status.snapshot(), "store": store.stats(), "demo": cfg.demo, "now": time.time(),
                "config": {"active_window": cfg.active_window, "wifi_session_timeout": cfg.wifi_session_timeout,
                           "bt_session_timeout": cfg.bt_session_timeout, "retention_days": cfg.retention_days}}

    @app.get("/api/summary")
    def summary():
        now = time.time()
        since = now - cfg.active_window
        kinds = {k: {"total": 0, "active": 0, "new_24h": 0, "packets": 0} for k in KINDS}
        for r in rows("SELECT kind, COUNT(*) total, SUM(last_seen >= ?) active, SUM(first_seen >= ?) new_24h, "
                      "SUM(packets) packets FROM devices GROUP BY kind", (since, now - 86400)):
            kinds[r["kind"]] = {k: r[k] or 0 for k in ("total", "active", "new_24h", "packets")}
        conn = rows("SELECT d.kind, COUNT(*) n FROM sessions s JOIN devices d ON d.mac = s.mac "
                    "WHERE s.type='assoc' AND s.open=1 GROUP BY d.kind")
        for r in conn:
            kinds[r["kind"]]["connected"] = r["n"]
        events = rows("SELECT e.*, d.kind, d.name, d.vendor, d.ssid, p.ssid peer_ssid FROM events e "
                      "LEFT JOIN devices d ON d.mac=e.mac LEFT JOIN devices p ON p.mac=e.peer WHERE e.type != 'new_probe' ORDER BY e.id DESC LIMIT 30")
        return {"kinds": kinds, "events": events, "now": now}

    @app.get("/api/timeline")
    def timeline(hours: float = 24, bucket: int = 0):
        now = time.time()
        bucket = bucket or max(60, int(hours * 3600 / 288) // 60 * 60)
        since = int((now - hours * 3600) // bucket * bucket)
        series = {k: {} for k in KINDS}
        for r in rows("SELECT (s.minute / ?) * ? AS t, d.kind, COUNT(DISTINCT s.mac) n FROM samples s "
                      "JOIN devices d ON d.mac = s.mac WHERE s.minute >= ? GROUP BY t, d.kind",
                      (bucket, bucket, since)):
            series.setdefault(r["kind"], {})[r["t"]] = r["n"]
        sess = rows("SELECT mac, start_ts, end_ts FROM sessions WHERE type='assoc' AND end_ts >= ?", (since,))
        connected = overlap_counts([(s["mac"], s["start_ts"], s["end_ts"]) for s in sess], since, now, bucket)
        ts = [since + i * bucket for i in range(len(connected))]
        return {"bucket": bucket, "t": ts,
                "series": {k: [v.get(t, 0) for t in ts] for k, v in series.items()},
                "connected": [n for _, n in connected]}

    # ----------------------------------------------------------------- devices
    def device_filters(kind=None, active=0, q=None, vendor=None, ssid=None, probe=None, bssid=None,
                       channel=None, randomized=None, connected=0):
        where, params = [], []
        if kind:
            ks = [k for k in kind.split(",") if k in KINDS]
            where.append(f"d.kind IN ({','.join('?' * len(ks))})")
            params += ks
        if active:
            where.append("d.last_seen >= ?")
            params.append(time.time() - active)
        if q:
            like = f"%{q.strip()}%"
            where.append("(d.mac LIKE ? OR d.name LIKE ? OR d.ssid LIKE ? OR d.vendor LIKE ?)")
            params += [like] * 4
        if vendor:
            if vendor == "Unknown":
                where.append("d.vendor IS NULL")
            else:
                where.append("d.vendor = ?")
                params.append(vendor)
        if ssid:
            where.append("(d.ssid = ? OR d.mac IN (SELECT s.mac FROM sessions s JOIN devices a ON a.mac = s.peer "
                         "WHERE s.type='assoc' AND a.ssid = ?))")
            params += [ssid, ssid]
        if probe:
            where.append("d.mac IN (SELECT mac FROM probes WHERE ssid = ?)")
            params.append(probe)
        if bssid:
            where.append("d.mac IN (SELECT mac FROM sessions WHERE type='assoc' AND peer = ?)")
            params.append(bssid.lower())
        if channel is not None:
            where.append("d.channel = ?")
            params.append(channel)
        if randomized is not None:
            where.append("d.randomized = ?")
            params.append(int(randomized))
        if connected:
            where.append("d.mac IN (SELECT mac FROM sessions WHERE type='assoc' AND open=1)")
        return (" WHERE " + " AND ".join(where)) if where else "", params

    @app.get("/api/devices")
    def devices(kind: str = None, active: int = 0, q: str = None, vendor: str = None, ssid: str = None,
                probe: str = None, bssid: str = None, channel: int = None, randomized: int = None,
                connected: int = 0, sort: str = "last_seen", order: str = "desc", limit: int = 100,
                offset: int = 0):
        where, params = device_filters(kind, active, q, vendor, ssid, probe, bssid, channel, randomized, connected)
        sort = sort if sort in SORTABLE else "last_seen"
        order = "ASC" if order.lower() == "asc" else "DESC"
        limit = max(1, min(limit, 1000))
        total = one(f"SELECT COUNT(*) n FROM devices d{where}", params)["n"]
        items = rows(
            f"SELECT d.*, a.ssid AS bssid_ssid, "
            f"EXISTS(SELECT 1 FROM sessions s WHERE s.mac=d.mac AND s.type='assoc' AND s.open=1) AS connected, "
            f"(SELECT COUNT(*) FROM sessions s WHERE s.peer=d.mac AND s.type='assoc' AND s.open=1) AS clients_now "
            f"FROM devices d LEFT JOIN devices a ON a.mac = d.bssid{where} "
            f"ORDER BY d.{sort} {order} NULLS LAST LIMIT ? OFFSET ?", params + [limit, offset])
        return {"total": total, "items": [_dev(i) for i in items], "now": time.time()}

    @app.get("/api/devices/{mac}")
    def device(mac: str):
        mac = mac.lower()
        d = _dev(one("SELECT d.*, a.ssid AS bssid_ssid FROM devices d LEFT JOIN devices a ON a.mac=d.bssid "
                     "WHERE d.mac=?", (mac,)))
        if not d:
            raise HTTPException(404, "device not found")
        agg = "SELECT COUNT(*) n, COALESCE(SUM(end_ts-start_ts),0) total, MAX(end_ts-start_ts) longest, " \
              "AVG(end_ts-start_ts) avg, MIN(start_ts) first FROM sessions WHERE mac=? AND type=?"
        d["presence"] = one(agg, (mac, "presence"))
        d["connections"] = one(agg, (mac, "assoc"))
        d["connected_now"] = one("SELECT s.*, a.ssid peer_ssid FROM sessions s LEFT JOIN devices a ON a.mac=s.peer "
                                 "WHERE s.mac=? AND s.type='assoc' AND s.open=1", (mac,))
        if d["kind"] == "ap":
            d["peers"] = rows(
                "SELECT s.mac, d.kind, d.vendor, d.name, d.randomized, COUNT(*) sessions, "
                "SUM(s.end_ts-s.start_ts) total, MIN(s.start_ts) first, MAX(s.end_ts) last, MAX(s.open) connected "
                "FROM sessions s LEFT JOIN devices d ON d.mac=s.mac WHERE s.type='assoc' AND s.peer=? "
                "GROUP BY s.mac ORDER BY connected DESC, last DESC", (mac,))
            d["siblings"] = rows("SELECT mac, channel, last_seen, last_rssi, vendor FROM devices "
                                 "WHERE kind='ap' AND ssid=? AND mac != ? ORDER BY last_seen DESC", (d["ssid"], mac)) \
                if d["ssid"] else []
        else:
            d["peers"] = rows(
                "SELECT s.peer AS mac, a.kind, a.ssid, a.vendor, a.channel, COUNT(*) sessions, "
                "SUM(s.end_ts-s.start_ts) total, MIN(s.start_ts) first, MAX(s.end_ts) last, MAX(s.open) connected "
                "FROM sessions s LEFT JOIN devices a ON a.mac=s.peer WHERE s.type='assoc' AND s.mac=? "
                "GROUP BY s.peer ORDER BY connected DESC, last DESC", (mac,))
            d["siblings"] = []
        d["probes"] = rows("SELECT ssid, first_seen, last_seen, count, "
                           "(SELECT COUNT(*) FROM devices a WHERE a.kind='ap' AND a.ssid=p.ssid) aps "
                           "FROM probes p WHERE mac=? ORDER BY last_seen DESC", (mac,))
        d["events"] = rows("SELECT e.*, p.ssid peer_ssid FROM events e LEFT JOIN devices p ON p.mac=e.peer "
                           "WHERE e.mac=? OR e.peer=? ORDER BY e.id DESC LIMIT 200", (mac, mac))
        d["now"] = time.time()
        return d

    @app.get("/api/devices/{mac}/rssi")
    def device_rssi(mac: str, hours: float = 24):
        now = time.time()
        bucket = max(60, int(hours * 3600 / 500) // 60 * 60)
        return {"bucket": bucket, "points": rows(
            "SELECT (minute/?)*? t, ROUND(SUM(rssi_sum)*1.0/NULLIF(SUM(rssi_count),0),1) avg, MIN(rssi_min) min, "
            "MAX(rssi_max) max, SUM(packets) packets FROM samples WHERE mac=? AND minute>=? GROUP BY t ORDER BY t",
            (bucket, bucket, mac.lower(), now - hours * 3600))}

    @app.get("/api/devices/{mac}/sessions")
    def device_sessions(mac: str, hours: float = 168, as_peer: int = 0):
        since = time.time() - hours * 3600
        col = "s.peer" if as_peer else "s.mac"
        join = "s.mac" if as_peer else "s.peer"
        return {"since": since, "now": time.time(), "items": rows(
            f"SELECT s.*, a.ssid peer_ssid, a.name peer_name, a.vendor peer_vendor FROM sessions s "
            f"LEFT JOIN devices a ON a.mac={join} WHERE {col}=? AND s.end_ts>=? ORDER BY s.start_ts LIMIT 5000",
            (mac.lower(), since))}

    @app.get("/api/devices/{mac}/clients")
    def device_clients(mac: str, hours: float = 24):
        now = time.time()
        bucket = max(300, int(hours * 3600 / 200) // 300 * 300)
        since = int((now - hours * 3600) // bucket * bucket)
        sess = rows("SELECT mac, start_ts, end_ts FROM sessions WHERE type='assoc' AND peer=? AND end_ts>=?",
                    (mac.lower(), since))
        pts = overlap_counts([(s["mac"], s["start_ts"], s["end_ts"]) for s in sess], since, now, bucket)
        return {"bucket": bucket, "t": [t for t, _ in pts], "n": [n for _, n in pts]}

    @app.get("/api/devices/{mac}/heatmap")
    def device_heatmap(mac: str, days: int = 28, tz: int = 0):
        since = time.time() - days * 86400
        grid = [[0] * 24 for _ in range(7)]
        off = tz * 60
        for r in rows("SELECT minute FROM samples WHERE mac=? AND minute>=?", (mac.lower(), since)):
            lt = r["minute"] - off
            grid[int((lt // 86400 + 3) % 7)][int((lt % 86400) // 3600)] += 1
        return {"days": days, "grid": grid}

    # ------------------------------------------------------------------- stats
    @app.get("/api/stats")
    def stats(days: float = 7, tz: int = 0):
        now = time.time()
        since = now - days * 86400
        off = tz * 60
        out = {"days": days}
        out["vendors"] = rows("SELECT COALESCE(vendor,'Unknown') vendor, kind, COUNT(*) n FROM devices "
                              "WHERE last_seen>=? GROUP BY vendor, kind ORDER BY n DESC", (since,))
        ssids = rows("SELECT ssid, COUNT(*) aps, GROUP_CONCAT(DISTINCT channel) channels, "
                     "GROUP_CONCAT(DISTINCT enc) enc, MAX(last_rssi) rssi FROM devices "
                     "WHERE kind='ap' AND ssid IS NOT NULL AND ssid != '' AND last_seen>=? GROUP BY ssid", (since,))
        clients = {r["ssid"]: r for r in rows(
            "SELECT a.ssid, COUNT(DISTINCT s.mac) clients, COUNT(*) sessions FROM sessions s "
            "JOIN devices a ON a.mac=s.peer WHERE s.type='assoc' AND s.end_ts>=? GROUP BY a.ssid", (since,))}
        for s in ssids:
            c = clients.get(s["ssid"], {})
            s["clients"], s["sessions"] = c.get("clients", 0), c.get("sessions", 0)
        out["ssids"] = sorted(ssids, key=lambda s: (-s["clients"], -s["aps"]))
        out["probes"] = rows("SELECT ssid, COUNT(DISTINCT mac) clients, SUM(count) frames, "
                             "(SELECT COUNT(*) FROM devices a WHERE a.kind='ap' AND a.ssid=p.ssid) aps "
                             "FROM probes p WHERE last_seen>=? GROUP BY ssid ORDER BY clients DESC LIMIT 50", (since,))
        out["channels"] = rows("SELECT channel, COUNT(*) aps FROM devices WHERE kind='ap' AND channel IS NOT NULL "
                               "AND last_seen>=? GROUP BY channel ORDER BY channel", (since,))
        hourly = rows("SELECT h, kind, COUNT(*) n FROM (SELECT DISTINCT s.mac, d.kind, "
                      "((s.minute - ?) % 86400) / 3600 h, (s.minute - ?) / 86400 day FROM samples s "
                      "JOIN devices d ON d.mac=s.mac WHERE s.minute>=?) GROUP BY h, kind", (off, off, since))
        ndays = one("SELECT COUNT(DISTINCT (minute - ?) / 86400) n FROM samples WHERE minute>=?",
                    (off, since))["n"] or 1
        out["hourly"] = {"days": ndays, "rows": hourly}
        out["new_per_day"] = rows("SELECT CAST((first_seen - ?) / 86400 AS INTEGER) * 86400 + ? day, kind, "
                                  "COUNT(*) n FROM devices WHERE first_seen>=? GROUP BY day, kind ORDER BY day",
                                  (off, off, since))
        out["durations"] = rows(
            "SELECT type, CASE WHEN d<60 THEN 0 WHEN d<300 THEN 1 WHEN d<1800 THEN 2 WHEN d<7200 THEN 3 "
            "WHEN d<28800 THEN 4 ELSE 5 END b, COUNT(*) n FROM (SELECT type, end_ts-start_ts d FROM sessions "
            "WHERE end_ts>=?) GROUP BY type, b", (since,))
        out["top_clients"] = rows(
            "SELECT s.mac, d.kind, d.vendor, d.name, d.randomized, COUNT(*) sessions, COUNT(DISTINCT s.peer) peers, "
            "SUM(MIN(s.end_ts, ?) - MAX(s.start_ts, ?)) secs FROM sessions s LEFT JOIN devices d ON d.mac=s.mac "
            "WHERE s.type='assoc' AND s.end_ts>=? GROUP BY s.mac ORDER BY secs DESC LIMIT 15", (now, since, since))
        out["top_aps"] = rows(
            "SELECT s.peer mac, a.ssid, a.channel, a.vendor, COUNT(DISTINCT s.mac) clients, COUNT(*) sessions, "
            "SUM(MIN(s.end_ts, ?) - MAX(s.start_ts, ?)) secs FROM sessions s JOIN devices a ON a.mac=s.peer "
            "WHERE s.type='assoc' AND s.end_ts>=? AND a.kind='ap' GROUP BY s.peer ORDER BY clients DESC LIMIT 15",
            (now, since, since))
        out["randomized"] = rows("SELECT kind, randomized, COUNT(*) n FROM devices WHERE last_seen>=? "
                                 "GROUP BY kind, randomized", (since,))
        out["events"] = rows("SELECT type, COUNT(*) n FROM events WHERE ts>=? GROUP BY type ORDER BY n DESC", (since,))
        return out

    @app.get("/api/events")
    def events(type: str = None, mac: str = None, kind: str = None, before: int = 0, limit: int = 100):
        where, params = [], []
        if type:
            where.append("e.type = ?")
            params.append(type)
        if mac:
            where.append("(e.mac = ? OR e.peer = ?)")
            params += [mac.lower(), mac.lower()]
        if kind:
            where.append("d.kind = ?")
            params.append(kind)
        if before:
            where.append("e.id < ?")
            params.append(before)
        w = (" WHERE " + " AND ".join(where)) if where else ""
        return {"items": rows(f"SELECT e.*, d.kind, d.name, d.vendor, d.ssid, p.ssid peer_ssid FROM events e "
                              f"LEFT JOIN devices d ON d.mac=e.mac LEFT JOIN devices p ON p.mac=e.peer{w} "
                              f"ORDER BY e.id DESC LIMIT ?", params + [max(1, min(limit, 500))]),
                "types": [r["type"] for r in rows("SELECT DISTINCT type FROM events ORDER BY type")]}

    # ------------------------------------------------------------------ export
    def _csv(name, cols, data):
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(cols)
        for r in data:
            w.writerow([r.get(c) for c in cols])
        return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                                 headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @app.get("/api/export/devices.csv")
    def export_devices():
        cols = ["mac", "kind", "vendor", "name", "ssid", "channel", "enc", "bssid", "randomized", "packets",
                "last_rssi", "best_rssi", "first_seen", "last_seen"]
        return _csv("devices.csv", cols, rows("SELECT * FROM devices ORDER BY last_seen DESC"))

    @app.get("/api/export/sessions.csv")
    def export_sessions(days: float = 7):
        cols = ["id", "mac", "type", "peer", "start_ts", "end_ts", "packets", "rssi_min", "rssi_max", "open",
                "end_reason"]
        return _csv("sessions.csv", cols, rows("SELECT * FROM sessions WHERE end_ts>=? ORDER BY start_ts",
                                               (time.time() - days * 86400,)))

    # ------------------------------------------------------------------ static
    if vendor_dir.exists():
        app.mount("/vendor", StaticFiles(directory=vendor_dir), name="vendor")
    app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/")
    def index():
        return FileResponse(static / "index.html")

    return app
