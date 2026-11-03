"""HTTP API + static single-page UI."""
import csv
import io
import json
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import alerts, auth, health, lan, manage, metrics, reports, security, sensors, status, survey
from .auth import current_user
from .web_util import overlap_counts

KINDS = ("ap", "wifi_client", "ble", "bt_classic", "lan")
SORTABLE = {"last_seen", "first_seen", "packets", "last_rssi", "best_rssi", "mac", "vendor",
            "name", "ssid", "kind", "channel", "band", "brand", "model", "dev_type", "os", "wifi_gen", "era"}


def create_app(ctx):
    cfg, store = ctx.cfg, ctx.store
    app = FastAPI(title="yolo", docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)
    static = Path(__file__).parent / "static"
    vendor_dir = Path("/app/vendor")
    ctx.auth.install(app)
    rows, one = ctx.rows, ctx.one

    def _dev(d):
        if d:
            for k in ("extra", "ident"):
                if isinstance(d.get(k), str):
                    d[k] = json.loads(d[k] or "null")
            d["extra"] = d.get("extra") or {}
        return d

    # ---------------------------------------------------------------- overview
    @app.get("/api/health")
    def healthcheck():
        return {"ok": True}

    @app.get("/api/status", dependencies=[Depends(current_user)])
    def get_status():
        return {"sensors": status.snapshot(), "store": store.stats(), "demo": cfg.demo, "now": time.time(),
                "config": {"active_window": cfg.active_window, "wifi_session_timeout": cfg.wifi_session_timeout,
                           "bt_session_timeout": cfg.bt_session_timeout, "retention_days": cfg.retention_days}}

    @app.get("/api/summary", dependencies=[Depends(current_user)])
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
        events = rows("SELECT e.*, d.kind, d.name, d.vendor, d.ssid, p.ssid peer_ssid, m.label FROM events e "
                      "LEFT JOIN devices d ON d.mac=e.mac LEFT JOIN devices p ON p.mac=e.peer "
                      "LEFT JOIN device_meta m ON m.mac=e.mac WHERE e.type != 'new_probe' ORDER BY e.id DESC LIMIT 30")
        return {"kinds": kinds, "events": events, "now": now}

    @app.get("/api/timeline", dependencies=[Depends(current_user)])
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
                       channel=None, randomized=None, connected=0, band=None, dev_type=None, brand=None,
                       os=None, wifi_gen=None, era=None, fp=None, known=None, watch=None, group=None):
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
            where.append("(d.mac LIKE ? OR d.name LIKE ? OR d.ssid LIKE ? OR d.vendor LIKE ? OR d.brand LIKE ? "
                         "OR d.model LIKE ? OR m.label LIKE ? OR m.notes LIKE ? OR d.ip LIKE ?)")
            params += [like] * 9
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
        if band:
            where.append("d.band = ?")
            params.append(band)
        for col, val in (("dev_type", dev_type), ("brand", brand), ("os", os), ("fp_hash", fp)):
            if val == "Unknown":
                where.append(f"d.{col} IS NULL")
            elif val:
                where.append(f"d.{col} = ?")
                params.append(val)
        if wifi_gen is not None:
            where.append("d.wifi_gen = ?" if wifi_gen else "d.wifi_gen IS NULL")
            if wifi_gen:
                params.append(wifi_gen)
        if era is not None:
            where.append("d.era = ?" if era else "d.era IS NULL")
            if era:
                params.append(era)
        if randomized is not None:
            where.append("d.randomized = ?")
            params.append(int(randomized))
        if connected:
            where.append("d.mac IN (SELECT mac FROM sessions WHERE type='assoc' AND open=1)")
        if known is not None:
            where.append("COALESCE(m.known, 0) = ?")
            params.append(int(known))
        if watch:
            where.append("m.watch = 1")
        if group is not None:
            where.append("m.group_id = ?")
            params.append(group)
        return (" WHERE " + " AND ".join(where)) if where else "", params

    @app.get("/api/devices", dependencies=[Depends(current_user)])
    def devices(kind: str = None, active: int = 0, q: str = None, vendor: str = None, ssid: str = None,
                probe: str = None, bssid: str = None, channel: int = None, randomized: int = None,
                connected: int = 0, band: str = None, dev_type: str = None, brand: str = None, os: str = None,
                wifi_gen: int = None, era: int = None, fp: str = None, known: int = None, watch: int = 0,
                group: int = None, sort: str = "last_seen", order: str = "desc", limit: int = 100, offset: int = 0):
        where, params = device_filters(kind, active, q, vendor, ssid, probe, bssid, channel, randomized, connected,
                                       band, dev_type, brand, os, wifi_gen, era, fp, known, watch, group)
        sort = "m.label" if sort == "label" else f"d.{sort if sort in SORTABLE else 'last_seen'}"
        order = "ASC" if order.lower() == "asc" else "DESC"
        limit = max(1, min(limit, 1000))
        meta_join = " LEFT JOIN device_meta m ON m.mac = d.mac"
        total = one(f"SELECT COUNT(*) n FROM devices d{meta_join}{where}", params)["n"]
        items = rows(
            f"SELECT d.*, a.ssid AS bssid_ssid, m.label, m.known, m.watch, m.group_id, g.name AS group_name, "
            f"EXISTS(SELECT 1 FROM sessions s WHERE s.mac=d.mac AND s.type='assoc' AND s.open=1) AS connected, "
            f"(SELECT COUNT(*) FROM sessions s WHERE s.peer=d.mac AND s.type='assoc' AND s.open=1) AS clients_now "
            f"FROM devices d LEFT JOIN devices a ON a.mac = d.bssid{meta_join} LEFT JOIN groups g ON g.id = m.group_id"
            f"{where} ORDER BY {sort} {order} NULLS LAST LIMIT ? OFFSET ?", params + [limit, offset])
        return {"total": total, "items": [_dev(i) for i in items], "now": time.time()}

    @app.get("/api/devices/{mac}", dependencies=[Depends(current_user)])
    def device(mac: str):
        mac = mac.lower()
        d = _dev(one("SELECT d.*, a.ssid AS bssid_ssid FROM devices d LEFT JOIN devices a ON a.mac=d.bssid "
                     "WHERE d.mac=?", (mac,)))
        if not d:
            raise HTTPException(404, "device not found")
        d["meta"] = one("SELECT m.*, g.name AS group_name FROM device_meta m LEFT JOIN groups g ON g.id=m.group_id "
                        "WHERE m.mac=?", (mac,))
        d["sightings"] = rows("SELECT w.sensor, w.last_seen, w.rssi, s.name, s.room FROM sightings w LEFT JOIN sensors s "
                              "ON s.id = w.sensor WHERE w.mac=? ORDER BY w.last_seen DESC", (mac,))
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
            d["siblings"] = rows("SELECT mac, channel, band, last_seen, last_rssi, vendor FROM devices "
                                 "WHERE kind='ap' AND ssid=? AND mac != ? ORDER BY last_seen DESC", (d["ssid"], mac)) \
                if d["ssid"] else []
        else:
            d["peers"] = rows(
                "SELECT s.peer AS mac, a.kind, a.ssid, a.vendor, a.channel, a.band, COUNT(*) sessions, "
                "SUM(s.end_ts-s.start_ts) total, MIN(s.start_ts) first, MAX(s.end_ts) last, MAX(s.open) connected "
                "FROM sessions s LEFT JOIN devices a ON a.mac=s.peer WHERE s.type='assoc' AND s.mac=? "
                "GROUP BY s.peer ORDER BY connected DESC, last DESC", (mac,))
            d["siblings"] = []
        d["probes"] = rows("SELECT ssid, first_seen, last_seen, count, "
                           "(SELECT COUNT(*) FROM devices a WHERE a.kind='ap' AND a.ssid=p.ssid) aps "
                           "FROM probes p WHERE mac=? ORDER BY last_seen DESC", (mac,))
        d["fp_peers"] = one("SELECT COUNT(*) n FROM devices WHERE fp_hash=? AND mac != ?",
                            (d["fp_hash"], mac))["n"] if d.get("fp_hash") else 0
        d["events"] = rows("SELECT e.*, p.ssid peer_ssid FROM events e LEFT JOIN devices p ON p.mac=e.peer "
                           "WHERE e.mac=? OR e.peer=? ORDER BY e.id DESC LIMIT 200", (mac, mac))
        d["now"] = time.time()
        return d

    @app.get("/api/devices/{mac}/rssi", dependencies=[Depends(current_user)])
    def device_rssi(mac: str, hours: float = 24):
        now = time.time()
        bucket = max(60, int(hours * 3600 / 500) // 60 * 60)
        return {"bucket": bucket, "points": rows(
            "SELECT (minute/?)*? t, ROUND(SUM(rssi_sum)*1.0/NULLIF(SUM(rssi_count),0),1) avg, MIN(rssi_min) min, "
            "MAX(rssi_max) max, SUM(packets) packets FROM samples WHERE mac=? AND minute>=? GROUP BY t ORDER BY t",
            (bucket, bucket, mac.lower(), now - hours * 3600))}

    @app.get("/api/devices/{mac}/sessions", dependencies=[Depends(current_user)])
    def device_sessions(mac: str, hours: float = 168, as_peer: int = 0):
        since = time.time() - hours * 3600
        col = "s.peer" if as_peer else "s.mac"
        join = "s.mac" if as_peer else "s.peer"
        return {"since": since, "now": time.time(), "items": rows(
            f"SELECT s.*, a.ssid peer_ssid, a.name peer_name, a.vendor peer_vendor FROM sessions s "
            f"LEFT JOIN devices a ON a.mac={join} WHERE {col}=? AND s.end_ts>=? ORDER BY s.start_ts LIMIT 5000",
            (mac.lower(), since))}

    @app.get("/api/devices/{mac}/clients", dependencies=[Depends(current_user)])
    def device_clients(mac: str, hours: float = 24):
        now = time.time()
        bucket = max(300, int(hours * 3600 / 200) // 300 * 300)
        since = int((now - hours * 3600) // bucket * bucket)
        sess = rows("SELECT mac, start_ts, end_ts FROM sessions WHERE type='assoc' AND peer=? AND end_ts>=?",
                    (mac.lower(), since))
        pts = overlap_counts([(s["mac"], s["start_ts"], s["end_ts"]) for s in sess], since, now, bucket)
        return {"bucket": bucket, "t": [t for t, _ in pts], "n": [n for _, n in pts]}

    @app.get("/api/devices/{mac}/heatmap", dependencies=[Depends(current_user)])
    def device_heatmap(mac: str, days: int = 28, tz: int = 0):
        since = time.time() - days * 86400
        grid = [[0] * 24 for _ in range(7)]
        off = tz * 60
        for r in rows("SELECT minute FROM samples WHERE mac=? AND minute>=?", (mac.lower(), since)):
            lt = r["minute"] - off
            grid[int((lt // 86400 + 3) % 7)][int((lt % 86400) // 3600)] += 1
        return {"days": days, "grid": grid}

    # ------------------------------------------------------------------- stats
    @app.get("/api/stats", dependencies=[Depends(current_user)])
    def stats(days: float = 7, tz: int = 0):
        now = time.time()
        since = now - days * 86400
        off = tz * 60
        out = {"days": days}
        out["vendors"] = rows("SELECT COALESCE(vendor,'Unknown') vendor, kind, COUNT(*) n FROM devices "
                              "WHERE last_seen>=? GROUP BY vendor, kind ORDER BY n DESC", (since,))
        ssids = rows("SELECT ssid, COUNT(*) aps, GROUP_CONCAT(DISTINCT CASE band WHEN '6' THEN '6G:' || channel "
                     "ELSE channel END) channels, GROUP_CONCAT(DISTINCT band) bands, "
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
        out["channels"] = rows("SELECT channel, COALESCE(band, CASE WHEN channel <= 14 THEN '2.4' ELSE '5' END) AS b, "
                               "COUNT(*) aps FROM devices WHERE kind='ap' AND channel IS NOT NULL AND last_seen>=? "
                               "GROUP BY b, channel ORDER BY b = '6', b = '5', channel", (since,))
        out["bands"] = rows("SELECT band, kind, COUNT(*) n FROM devices WHERE band IS NOT NULL AND last_seen>=? "
                            "GROUP BY band, kind", (since,))
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
            "SELECT s.peer mac, a.ssid, a.channel, a.band, a.vendor, COUNT(DISTINCT s.mac) clients, COUNT(*) sessions, "
            "SUM(MIN(s.end_ts, ?) - MAX(s.start_ts, ?)) secs FROM sessions s JOIN devices a ON a.mac=s.peer "
            "WHERE s.type='assoc' AND s.end_ts>=? AND a.kind='ap' GROUP BY s.peer ORDER BY clients DESC LIMIT 15",
            (now, since, since))
        out["randomized"] = rows("SELECT kind, randomized, COUNT(*) n FROM devices WHERE last_seen>=? "
                                 "GROUP BY kind, randomized", (since,))
        out["events"] = rows("SELECT type, COUNT(*) n FROM events WHERE ts>=? GROUP BY type ORDER BY n DESC", (since,))
        for col in ("dev_type", "brand", "os", "wifi_gen", "era"):
            out[col] = rows(f"SELECT {col} v, kind, COUNT(*) n FROM devices WHERE last_seen>=? GROUP BY {col}, kind "
                            f"ORDER BY n DESC", (since,))
        out["fingerprints"] = rows(
            "SELECT fp_hash, COUNT(*) n, SUM(randomized) randomized, MAX(brand) brand, MAX(dev_type) dev_type, "
            "MAX(os) os, MAX(wifi_gen) wifi_gen FROM devices WHERE fp_hash IS NOT NULL AND last_seen>=? "
            "GROUP BY fp_hash HAVING n > 1 ORDER BY n DESC LIMIT 15", (since,))
        return out

    @app.get("/api/events", dependencies=[Depends(current_user)])
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
        return {"items": rows(f"SELECT e.*, d.kind, d.name, d.vendor, d.ssid, p.ssid peer_ssid, m.label FROM events e "
                              f"LEFT JOIN devices d ON d.mac=e.mac LEFT JOIN devices p ON p.mac=e.peer "
                              f"LEFT JOIN device_meta m ON m.mac=e.mac{w} "
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

    @app.get("/api/export/devices.csv", dependencies=[Depends(current_user)])
    def export_devices():
        cols = ["mac", "kind", "vendor", "brand", "model", "dev_type", "os", "wifi_gen", "era", "fp_hash", "name", "ssid",
                "channel", "band", "freq", "enc", "bssid", "randomized", "packets",
                "last_rssi", "best_rssi", "first_seen", "last_seen"]
        return _csv("devices.csv", cols, rows("SELECT * FROM devices ORDER BY last_seen DESC"))

    @app.get("/api/export/sessions.csv", dependencies=[Depends(current_user)])
    def export_sessions(days: float = 7):
        cols = ["id", "mac", "type", "peer", "start_ts", "end_ts", "packets", "rssi_min", "rssi_max", "open",
                "end_reason"]
        return _csv("sessions.csv", cols, rows("SELECT * FROM sessions WHERE end_ts>=? ORDER BY start_ts",
                                               (time.time() - days * 86400,)))

    # ------------------------------------------------------------------ static
    for mod in (auth, manage, alerts, security, survey, health, metrics, sensors, reports, lan):
        app.include_router(mod.routes(ctx))

    @app.get("/login")
    def login_page():
        return FileResponse(static / "login.html")

    if vendor_dir.exists():
        app.mount("/vendor", StaticFiles(directory=vendor_dir), name="vendor")
    app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/")
    def index():
        return FileResponse(static / "index.html")

    return app
