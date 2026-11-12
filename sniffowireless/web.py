"""HTTP API + static single-page UI."""
import hashlib
import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware

from . import (adapters, alerts, appearance, dataprivacy, macprivacy, auth, backup, bluetooth, capture, channels, dfs, handshake, health, interference, investigate, lan, logs, lora, manage,
               matching, metrics, modules, occupancy, mqtt, purge, radiowatch, reports, search, security, sensors, signal_live, status, survey, sysinfo, tracker_sound, trackers, version, zigbee)
from .anonymize import AnonymizeMiddleware
from .auth import current_user, require_admin
from .httpsec import SecurityMiddleware
from .web_util import csv_response, overlap_counts

log = logging.getLogger("sniffowireless.web")

CHART_JS_CDN = "https://cdn.jsdelivr.net/npm/chart.js@4.4.6/dist/chart.umd.min.js"
ESPTOOL_JS_CDN = "https://cdn.jsdelivr.net/npm/esptool-js@0.5.7/bundle.js"
QRCODE_JS_CDN = "https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.js"

KINDS = ("ap", "wifi_client", "ble", "bt_classic", "lan")
PROBE_MAX_AGE = 120  # seconds: how recently a device must have been heard to be asked for its version
SORTABLE = {"last_seen", "first_seen", "packets", "last_rssi", "best_rssi", "mac", "vendor",
            "name", "ssid", "kind", "channel", "band", "brand", "model", "dev_type", "os", "wifi_gen", "era"}


# Not worth compressing, or must not be: live streams (gzip would buffer events), downloads that are already
# compressed archives or captures, and images.
NO_GZIP = ("/api/logs/stream", "/api/backup", "/api/handshakes", "/api/floorplan/image", "/api/appearance/icon")


class JsonAndStaticGZip(GZipMiddleware):
    """gzip for GET/HEAD responses of the page, scripts, styles and the JSON API (the tables and charts fetch
    hundreds of kB of it). Skips range requests and the paths above; and never compresses POST responses,
    which keeps anything secret-bearing (a new API token) out of reach of BREACH-style length attacks."""

    async def __call__(self, scope, receive, send):
        if (scope["type"] == "http" and scope["method"] in ("GET", "HEAD") and not scope["path"].startswith(NO_GZIP)
                and not any(k == b"range" for k, _ in scope["headers"])):
            await super().__call__(scope, receive, send)
        else:
            await self.app(scope, receive, send)


class ImmutableStatic(StaticFiles):
    """Static files are requested with ?v=<content hash> (see versioned() below), so a version never changes and
    the browser can keep it without re-asking."""

    async def get_response(self, path, scope):
        resp = await super().get_response(path, scope)
        if resp.status_code == 200 and b"v=" in scope.get("query_string", b""):
            resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return resp


# The Statistics page reads its independent parts side by side (SQLite runs each query outside the interpreter lock).
STATS_POOL = ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 4), thread_name_prefix="stats")
RADIO_SLOT = 300  # granularity of the Zigbee / LoRa activity kept in radio_seen
PASSERBY_STAY = 600     # heard for this long in one go: not passing by, it's here
PASSERBY_MIN_READINGS = 3
PASSERBY_SWING_DB = 10  # a pass whose signal rises and falls by about this much looks like movement


def create_app(ctx):
    cfg, store = ctx.cfg, ctx.store
    app = FastAPI(title="sniffowireless", docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)
    static = Path(__file__).parent / "static"
    vendor_dir = Path("/app/vendor")
    ctx.auth.install(app)
    app.add_middleware(macprivacy.MacInputMiddleware)  # innermost: addresses typed in the interface become pseudonyms when privacy mode is on
    app.add_middleware(AnonymizeMiddleware, ctx=ctx)  # next: masks what the routes return
    app.add_middleware(SecurityMiddleware, allowed_hosts=cfg.allowed_hosts)  # runs before auth
    app.add_middleware(JsonAndStaticGZip, minimum_size=1024, compresslevel=5)  # outermost
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

    @app.get("/api/about", dependencies=[Depends(current_user)])
    def about():
        """Which version and build this server is, for Settings -> About (and to compare with the sensors')."""
        return {**version.info(), **version.runtime(), "mode": cfg.mode, "demo": cfg.demo, "repo": version.REPO_URL, "now": time.time()}

    @app.get("/api/status", dependencies=[Depends(current_user)])
    def get_status():
        names = {r["id"]: r for r in rows("SELECT id, name, room FROM sensors")}
        systems = [{"id": sid, "name": (names.get(sid) or {}).get("name") or sid, "room": (names.get(sid) or {}).get("room"), **v}
                   for sid, v in status.systems_snapshot().items()]
        return {"sensors": status.snapshot(), "store": store.stats(), "demo": cfg.demo, "now": time.time(),
                "build": {**version.info(), "started": version.STARTED, "ui": ui_hash},
                "system": sysinfo.snapshot(cfg.db_path, cfg.data_dir), "sensor_systems": sorted(systems, key=lambda x: x["name"].lower()),
                "config": {"active_window": cfg.active_window, "wifi_session_timeout": cfg.wifi_session_timeout,
                           "bt_session_timeout": cfg.bt_session_timeout, "retention_days": cfg.retention_days}}

    @app.get("/api/summary", dependencies=[Depends(current_user)])
    def summary(window: int = 0):
        now = time.time()
        window = min(max(window, 60), 30 * 86400) if window else cfg.active_window
        since = now - window
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
        # LoRa nodes and Zigbee radios are not devices (no MAC): they are counted from their own tables
        extra = {}
        for name, table, col in (("lora", "lora_nodes", "last_seen"), ("zigbee", "zigbee_radios", "last_seen")):
            try:
                r = rows(f"SELECT COUNT(*) total, SUM({col} >= ?) active, SUM(first_seen >= ?) new_24h FROM {table}", (since, now - 86400))[0]
                extra[name] = {k: r[k] or 0 for k in ("total", "active", "new_24h")}
            except Exception:
                extra[name] = {"total": 0, "active": 0, "new_24h": 0}
        return {"kinds": kinds, "events": events, "now": now, "window": window, "people": occupancy.now(ctx, now), **extra}

    def timeline_grid(hours, bucket):
        """(now, bucket seconds, first bucket start) of a timeline."""
        now = time.time()
        auto = max(60, int(hours * 3600 / 288) // 60 * 60)
        custom = bucket
        bucket = max(bucket, int(hours * 3600 / 2000), 60) if bucket else auto  # never more than ~2000 buckets
        # From an hour up (and by default for ranges of 3 days and more), buckets are whole hours so the distinct-device
        # counts can come from the hourly roll-up (~60x fewer rows than the per-minute samples) with identical results.
        if bucket >= 3600 or (hours >= 72 and not custom):
            bucket = -(-max(bucket, 3600) // 3600) * 3600
        return now, bucket, int((now - hours * 3600) // bucket * bucket)

    def heard_sql(source, tcol, mcol, column, group, where=""):
        """Distinct devices per (bucket, kind, `column`). From the per-minute samples a device has many rows in one bucket: those
        are reduced to one row per (bucket, device) first, so the device is looked up once per bucket instead of once per sample
        (about twice as fast). The hourly roll-up has one row per device-hour already, so there the plain form is quicker."""
        if source.startswith("samples"):
            return (f"SELECT x.t, d.kind, {column}, COUNT(*) n FROM (SELECT DISTINCT ({tcol} / ?) * ? AS t, {mcol} mac FROM {source} "
                    f"WHERE {tcol} >= ?) x JOIN devices d ON d.mac = x.mac {where} GROUP BY x.t, d.kind, {group}")
        return (f"SELECT ({tcol} / ?) * ? AS t, d.kind, {column}, COUNT(DISTINCT {mcol}) n FROM {source} JOIN devices d ON d.mac = {mcol} "
                f"WHERE {tcol} >= ? {where.replace('WHERE', 'AND')} GROUP BY t, d.kind, {group}")

    @app.get("/api/timeline/radios", dependencies=[Depends(current_user)])
    def timeline_radios(hours: float = 24, bucket: int = 0):
        """Series for the overview's own graphs of Bluetooth (random against static addresses), Zigbee / Thread / other 802.15.4 and LoRa."""
        now, bucket, since = timeline_grid(hours, bucket)
        ts = list(range(since, int(now) + 1, bucket))
        idx = {t: i for i, t in enumerate(ts)}

        def spots(t):
            """Indexes of the buckets that a radio heard in the 5-minute slot/bucket starting at t counts for (a slot spans several short buckets)."""
            if bucket >= RADIO_SLOT:
                return [idx[t]] if t in idx else []
            return [idx[u] for u in range(int(t // bucket * bucket), int(t) + RADIO_SLOT, bucket) if u in idx]

        def blank(*names):
            return {n: [0] * len(ts) for n in names}
        out = {"t": ts, "bucket": bucket, "bluetooth": blank("ble_random", "ble_static", "classic"),
               "zigbee": blank("zigbee", "thread", "other"), "lora": {}}
        source, tcol, mcol = ("presence_hours h", "h.hour", "h.mac") if bucket >= 3600 else ("samples s", "s.minute", "s.mac")
        for r in rows(heard_sql(source, tcol, mcol, "d.randomized rnd", "rnd", "WHERE d.kind IN ('ble', 'bt_classic')"), (bucket, bucket, since)):
            i = idx.get(r["t"])
            if i is not None:
                out["bluetooth"]["classic" if r["kind"] == "bt_classic" else "ble_random" if r["rnd"] else "ble_static"][i] += r["n"]
        try:
            slot = RADIO_SLOT
            # which protocol a radio belongs to: what its own frames showed, else what its network announced
            net = {r["pan"]: r["protocol"] for r in rows("SELECT pan, protocol FROM zigbee_networks")}
            hints = {f"{r['pan']}:{r['addr']}": r["hint"] for r in rows("SELECT pan, addr, hint FROM zigbee_radios")}
            seen = {}
            for r in rows("SELECT (slot / ?) * ? t, addr FROM radio_seen WHERE kind='zigbee' AND slot >= ? GROUP BY t, addr",
                          (max(bucket, slot), max(bucket, slot), since - slot)):
                pan = int(r["addr"].split(":", 1)[0]) if r["addr"].split(":", 1)[0].isdigit() else None
                h = hints.get(r["addr"])
                proto = "thread" if h == 2 or (h in (None, 0, 1) and net.get(pan) == "thread") else \
                    "zigbee" if h == 3 or (h in (None, 0, 1) and net.get(pan) == "zigbee") else "other"
                for i in spots(r["t"]):
                    seen.setdefault((proto, i), set()).add(r["addr"])
            for (proto, i), addrs in seen.items():
                out["zigbee"][proto][i] = len(addrs)
            protos = {}
            for r in rows("SELECT (slot / ?) * ? t, addr FROM radio_seen WHERE kind='lora' AND slot >= ? GROUP BY t, addr",
                          (max(bucket, slot), max(bucket, slot), since - slot)):
                proto = r["addr"].split(":", 1)[0] or "other"
                for i in spots(r["t"]):
                    protos.setdefault((proto, i), set()).add(r["addr"])
            for (proto, i), addrs in protos.items():
                out["lora"].setdefault(proto, [0] * len(ts))[i] = len(addrs)
        except Exception:  # radio tables not created yet
            log.exception("radio timeline")
        return out

    @app.get("/api/timeline", dependencies=[Depends(current_user)])
    def timeline(hours: float = 24, bucket: int = 0):
        now, bucket, since = timeline_grid(hours, bucket)
        source = "presence_hours h" if bucket >= 3600 else "samples s"
        tcol = "h.hour" if bucket >= 3600 else "s.minute"
        mcol = "h.mac" if bucket >= 3600 else "s.mac"
        # One pass over `samples` (grouped by bucket, kind AND band) instead of two: the per-kind series is
        # exactly the per-band figures summed back up (each device has one band at a time), and the GROUP BY
        # + COUNT(DISTINCT) here is the expensive part of this endpoint at a 30-day range — halving how many
        # times it scans `samples` is worth more than the SQL staying simple.
        series = {k: {} for k in KINDS}
        bands = {b: {"ap": {}, "wifi_client": {}} for b in ("2.4", "5", "6")}
        for r in rows(heard_sql(source, tcol, mcol, "d.band", "d.band"), (bucket, bucket, since)):
            k, t, n = r["kind"], r["t"], r["n"]
            s = series.setdefault(k, {})
            s[t] = s.get(t, 0) + n
            if k in ("ap", "wifi_client") and r["band"] in bands:
                bands[r["band"]][k][t] = n
        sess = rows("SELECT mac, start_ts, end_ts FROM sessions WHERE type='assoc' AND end_ts >= ?", (since,))
        connected = overlap_counts([(s["mac"], s["start_ts"], s["end_ts"]) for s in sess], since, now, bucket)
        ts = [since + i * bucket for i in range(len(connected))]
        # Per Wi-Fi band: APs and active clients (on the band the device was last heard on), plus connected
        # clients counted on the band of the AP they were connected to at that time (correct when roaming).
        by_band = {}
        for r in rows("SELECT s.mac, s.start_ts, s.end_ts, a.band FROM sessions s JOIN devices a ON a.mac = s.peer "
                      "WHERE s.type='assoc' AND s.end_ts >= ? AND a.band IN ('2.4', '5', '6')", (since,)):
            by_band.setdefault(r["band"], []).append((r["mac"], r["start_ts"], r["end_ts"]))
        band_out = {}
        for b, v in bands.items():
            conn = overlap_counts(by_band.get(b, []), since, now, bucket)
            band_out[b] = {"ap": [v["ap"].get(t, 0) for t in ts], "wifi_client": [v["wifi_client"].get(t, 0) for t in ts],
                           "connected": [n for _, n in conn][:len(ts)]}
        out = {k: [v.get(t, 0) for t in ts] for k, v in series.items()}
        # Zigbee radios and LoRa nodes heard (kept per 5 minutes in radio_seen): distinct per bucket, or, for buckets
        # shorter than a slot, what the slot holding that bucket had.
        out.update(zigbee=[0] * len(ts), lora=[0] * len(ts))
        try:
            if bucket >= RADIO_SLOT:
                found = {(r["kind"], r["t"]): r["n"] for r in rows(
                    "SELECT kind, (slot / ?) * ? t, COUNT(DISTINCT addr) n FROM radio_seen WHERE slot >= ? GROUP BY kind, t", (bucket, bucket, since - RADIO_SLOT))}
                for k in ("zigbee", "lora"):
                    out[k] = [found.get((k, t), 0) for t in ts]
            else:
                found = {(r["kind"], r["slot"]): r["n"] for r in rows(
                    "SELECT kind, slot, COUNT(*) n FROM radio_seen WHERE slot >= ? GROUP BY kind, slot", (since - RADIO_SLOT,))}
                for k in ("zigbee", "lora"):
                    out[k] = [found.get((k, int(t // RADIO_SLOT) * RADIO_SLOT), 0) for t in ts]
        except Exception:  # no such table yet
            pass
        return {"bucket": bucket, "t": ts,
                "series": out,
                "connected": [n for _, n in connected], "bands": band_out}

    # ----------------------------------------------------------------- devices
    def device_filters(kind=None, active=0, q=None, vendor=None, ssid=None, probe=None, bssid=None,
                       channel=None, randomized=None, connected=0, band=None, dev_type=None, brand=None,
                       os=None, wifi_gen=None, era=None, fp=None, known=None, watch=None, group=None,
                       addr_type=None, company=None, bt_ver=None, mobility=None):
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
        for path, val in (("$.addr_type", addr_type), ("$.company", company), ("$.bt_ver", bt_ver), ("$.mobility.c", mobility)):  # Bluetooth details, movement
            if val == "Unknown":
                where.append(f"json_extract(d.extra, '{path}') IS NULL")
            elif val:
                where.append(f"json_extract(d.extra, '{path}') = ?")
                params.append(val)
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

    def filter_args(kind: str = None, active: int = 0, q: str = None, vendor: str = None, ssid: str = None,
                    probe: str = None, bssid: str = None, channel: int = None, randomized: int = None,
                    connected: int = 0, band: str = None, dev_type: str = None, brand: str = None, os: str = None,
                    wifi_gen: int = None, era: int = None, fp: str = None, known: int = None, watch: int = 0,
                    group: int = None, addr_type: str = None, company: str = None, bt_ver: str = None,
                    mobility: str = None):
        """The device filters as query parameters; shared by the list and the exports so both mean the same thing."""
        return device_filters(kind, active, q, vendor, ssid, probe, bssid, channel, randomized, connected, band,
                              dev_type, brand, os, wifi_gen, era, fp, known, watch, group, addr_type, company, bt_ver, mobility)

    @app.get("/api/devices", dependencies=[Depends(current_user)])
    def devices(flt=Depends(filter_args), sort: str = "last_seen", order: str = "desc", limit: int = 100, offset: int = 0,
                slim: int = 0):
        where, params = flt
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
        items = [_dev(i) for i in items]
        for i in items:  # also in the slim rows, which drop `extra`
            i["bt_ver"] = i["extra"].get("bt_ver")
            i["bt_basis"] = i["extra"].get("bt_basis")
            i["mobility"] = (i["extra"].get("mobility") or {}).get("c")
        if slim:  # tables only show the identification label; the evidence and raw fingerprints are ~70% of each row
            for i in items:
                i["ident"] = {"label": (i.get("ident") or {}).get("label")}
                i.pop("extra", None)
        return {"total": total, "items": items, "now": time.time()}

    @app.get("/api/passersby", dependencies=[Depends(current_user)])
    def passersby(days: float = 30, min_passes: int = 3, max_secs: int = 120, max_per_day: int = 6, gap: int = 1800,
                  moving: int = 0, aps: int = 0, hide_known: int = 0, tz: int = 0):
        """Devices that are heard only briefly, a few times a day, as they go by (a neighbour on their regular walk,
        a delivery route, traffic on a nearby street). Nothing to do with connecting: it's about being heard.

        What tells a passer-by from a stationary device that merely flickers in and out at the edge of range:
        * a *pass* is a run of short visits less than `gap` seconds apart (one flickering device is one long
          episode, not dozens of passes), and it must be shorter than `max_secs` to count;
        * a few passes per day, at most `max_per_day`: a flickering device does it constantly;
        * never a long stay: a device that is ever heard for 10 minutes straight lives or works nearby;
        * optionally (`moving`) the signal rises and falls during a pass, as it does when something moves.
        Grouped by MAC, so a device with a randomized (rotating) address under-counts: each new address looks like a
        different, less frequent visitor."""
        since = time.time() - days * 86400
        min_passes, max_secs = max(2, min(min_passes, 10_000)), max(1, min(max_secs, 3600))
        max_per_day, gap = max(1, min(max_per_day, 1000)), max(60, min(gap, 86400))
        kinds = "" if aps else " AND mac NOT IN (SELECT mac FROM devices WHERE kind='ap')"
        # Cheap pre-filter in SQL: enough short visits, and no long stay at all.
        cand = [r["mac"] for r in rows(
            f"SELECT mac FROM sessions WHERE type='presence' AND end_ts>=?{kinds} GROUP BY mac "
            f"HAVING SUM(end_ts-start_ts >= ?) = 0 AND SUM(end_ts-start_ts < ?) >= ? LIMIT 5000",
            (since, PASSERBY_STAY, max_secs, min_passes))]
        if not cand:
            return {"items": []}
        by_mac = {}
        for i in range(0, len(cand), 500):  # stay clear of SQLite's variable limit
            part = cand[i:i + 500]
            for r in rows(f"SELECT mac, start_ts, end_ts, rssi_min, rssi_max, rssi_count FROM sessions WHERE type='presence' "
                          f"AND end_ts>=? AND mac IN ({','.join('?' * len(part))}) ORDER BY mac, start_ts", [since] + part):
                by_mac.setdefault(r["mac"], []).append(r)
        agg = []
        for mac, vs in by_mac.items():
            passes, cur = [], None  # a pass: [start, end, rssi_min, rssi_max, visits, signal readings]
            for v in vs:
                lo, hi = v["rssi_min"], v["rssi_max"]
                if cur and v["start_ts"] - cur[1] < gap:
                    cur[1] = max(cur[1], v["end_ts"])
                    cur[2] = min((x for x in (cur[2], lo) if x is not None), default=None)
                    cur[3] = max((x for x in (cur[3], hi) if x is not None), default=None)
                    cur[4] += 1
                    cur[5] += v["rssi_count"] or 0
                else:
                    cur = [v["start_ts"], v["end_ts"], lo, hi, 1, v["rssi_count"] or 0]
                    passes.append(cur)
            short = [p for p in passes if p[1] - p[0] <= max_secs]
            if len(short) < min_passes or len(short) < 0.8 * len(passes):  # mostly passes, not long episodes
                continue
            day_of = lambda t: int((t - tz * 60) // 86400)
            per_day = {}
            for p in short:
                per_day[day_of(p[0])] = per_day.get(day_of(p[0]), 0) + 1
            rate = len(short) / len(per_day)
            if rate > max_per_day:
                continue
            # Signal swing only from passes with enough readings to tell: one frame has no spread whether it moves or not.
            swings = [p[3] - p[2] for p in short if p[2] is not None and p[3] is not None and p[5] >= PASSERBY_MIN_READINGS]
            swing = sum(swings) / len(swings) if swings else None
            if moving and (swing is None or swing < PASSERBY_SWING_DB):
                continue
            lens = [p[1] - p[0] for p in short]
            agg.append({"mac": mac, "visits": len(short), "days_seen": len(per_day), "per_day": round(rate, 1),
                        "avg_secs": sum(lens) / len(lens), "max_secs": max(lens), "swing_db": round(swing) if swing is not None else None,
                        "first_seen": short[0][0], "last_seen": short[-1][1]})
        agg.sort(key=lambda r: (-r["visits"], r["mac"]))
        agg = agg[:300]
        if not agg:
            return {"items": []}
        macs = [r["mac"] for r in agg]
        q = ",".join("?" * len(macs))
        devs = {d["mac"]: _dev(d) for d in rows(
            f"SELECT d.mac, d.kind, d.vendor, d.name, d.dev_type, d.randomized, d.last_rssi, d.ident, "
            f"m.label, m.known, m.watch FROM devices d LEFT JOIN device_meta m ON m.mac=d.mac WHERE d.mac IN ({q})", macs)}
        items = []
        for r in agg:
            d = devs.get(r["mac"]) or {}
            if hide_known and d.get("known"):
                continue
            items.append({**r, "kind": d.get("kind"), "vendor": d.get("vendor"), "name": d.get("name"),
                         "dev_type": d.get("dev_type"), "randomized": d.get("randomized"),
                         "last_rssi": d.get("last_rssi"), "ident": (d.get("ident") or {}).get("label"),
                         "label": d.get("label"), "known": d.get("known"), "watch": d.get("watch")})
        return {"items": items}

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

    @app.post("/api/devices/{mac}/sound", dependencies=[Depends(require_admin)])  # transmits: admins only, like bt-version
    def play_sound(mac: str):
        """Try to make a BLE tracker tag play its "find me" sound. Only works on devices that implement
        the standard Immediate Alert Service — notably not genuine Apple AirTags (see tracker_sound.py)."""
        mac = mac.lower()
        d = one("SELECT kind, extra FROM devices WHERE mac=?", (mac,))
        if not d:
            raise HTTPException(404, "device not found")
        if d["kind"] != "ble":
            raise HTTPException(400, "only BLE devices can be asked to play a sound")
        if not cfg.bt_devices:
            raise HTTPException(400, "no Bluetooth adapter is configured (BT_DEVICES)")
        extra = json.loads(d["extra"] or "null") or {}
        addr_type = 0 if extra.get("addr_type") == "public" else 1
        try:
            real = macprivacy.resolve(mac)  # privacy mode: the real address is only known for a device heard minutes ago
            if real == mac and macprivacy.is_pseudonym(mac):
                raise HTTPException(409, "In privacy mode the address of this device is not kept; wait until it is heard again")
            tracker_sound.play_sound(cfg.bt_devices[0], real, addr_type)
        except tracker_sound.SoundError as e:
            raise HTTPException(502, str(e))
        return {"ok": True}

    probe_last = {}  # mac -> when its version was last asked for: a cooldown per device

    @app.post("/api/devices/{mac}/bt-version")
    def read_bt_version(mac: str, user=Depends(require_admin)):
        """Ask a Bluetooth LE device for its exact version by connecting to it for a moment (btprobe.py). This TRANSMITS, unlike
        everything else sniffowireless does, so: admin only, only a device heard in the last two minutes (the connection goes to an
        address that is really there), one request per device a minute, and the adapter that heard it best does the asking (a remote
        sensor gets it as a command and reports the answer like any observation: extra.bt_probe, extra.bt_version)."""
        mac = mac.lower()
        if not cfg.bt_active_probe:
            raise HTTPException(403, "Reading a version by connecting is switched off (BT_ACTIVE_PROBE=0)")
        d = one("SELECT kind, last_seen, extra FROM devices WHERE mac=?", (mac,))
        if not d:
            raise HTTPException(404, "device not found")
        if d["kind"] != "ble":
            raise HTTPException(400, "Only Bluetooth LE devices can be asked for their version")
        now = time.time()
        if now - (d["last_seen"] or 0) > PROBE_MAX_AGE:
            raise HTTPException(409, "This device has not been heard in the last two minutes. It may be gone, and a private address may have changed.")
        if now - probe_last.get(mac, 0) < 60:
            raise HTTPException(429, "This device was asked a moment ago; wait a minute")
        real = macprivacy.resolve(mac)
        if real == mac and macprivacy.is_pseudonym(mac):
            raise HTTPException(409, "In privacy mode the address of this device is not kept; wait until it is heard again")
        extra = json.loads(d["extra"] or "null") or {}
        addr_type = 0 if extra.get("addr_type") == "public" else 1
        heard = rows("SELECT sensor, rssi FROM sightings WHERE mac=? AND last_seen>=? ORDER BY rssi IS NULL, rssi DESC", (mac, now - PROBE_MAX_AGE))
        snap = status.snapshot()
        for h in heard:  # strongest first
            if h["sensor"] == "local":
                names = sorted(n for n, sensor in bluetooth.SENSORS.items() if (status.SENSORS.get(n) or {}).get("state") != "error")
                for name in names:
                    try:
                        bluetooth.SENSORS[name].request_probe(real, addr_type)
                    except ValueError as e:
                        raise HTTPException(409, str(e))
                    probe_last[mac] = now
                    log.info("%s asked %s for its Bluetooth version via %s", user.username, mac, name)
                    return {"ok": True, "queued": False, "adapter": name}
            else:
                names = sorted(x["name"] for x in snap if x.get("type") == "bluetooth" and x.get("remote") == h["sensor"] and x.get("state") != "error")
                if names:
                    adapters.queue_probe(h["sensor"], names[0], real, addr_type)
                    probe_last[mac] = now
                    log.info("%s asked %s for its Bluetooth version via %s on sensor %s", user.username, mac, names[0], h["sensor"])
                    return {"ok": True, "queued": True, "adapter": names[0], "sensor": h["sensor"]}
        raise HTTPException(409, "No Bluetooth adapter that heard this device just now is available")

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
    def stats(days: float = 7, tz: int = 0, limit: int = 20):
        """Everything on the Statistics page. The parts don't depend on each other, so they are read side by side (each query
        has a database connection of its own), and what can be counted from one pass over a table is: the devices of the
        period are read once for all the per-kind counts, and the presence rows once for the hourly and weekly charts."""
        limit = max(1, min(limit, 1000))  # rows in the top-N lists; the page asks for more when a list is opened in full
        now = time.time()
        since = now - days * 86400
        off = tz * 60

        def networks():
            total = one("SELECT COUNT(DISTINCT ssid) n FROM devices WHERE kind='ap' AND ssid IS NOT NULL "
                        "AND ssid != '' AND last_seen>=?", (since,))["n"]
            # The 100 most recently seen networks (the page shows 20 and expands to 100).
            ssids = rows("SELECT ssid, COUNT(*) aps, GROUP_CONCAT(DISTINCT CASE band WHEN '6' THEN '6G:' || channel "
                         "ELSE channel END) channels, GROUP_CONCAT(DISTINCT band) bands, "
                         "GROUP_CONCAT(DISTINCT enc) enc, MAX(last_rssi) rssi, MAX(last_seen) last_seen FROM devices "
                         "WHERE kind='ap' AND ssid IS NOT NULL AND ssid != '' AND last_seen>=? GROUP BY ssid "
                         "ORDER BY last_seen DESC LIMIT 100", (since,))
            clients = {r["ssid"]: r for r in rows(
                "SELECT a.ssid, COUNT(DISTINCT s.mac) clients, COUNT(*) sessions FROM sessions s "
                "JOIN devices a ON a.mac=s.peer WHERE s.type='assoc' AND s.end_ts>=? GROUP BY a.ssid", (since,))}
            ignored, mine = ({e["ssid"] for e in ctx.settings.get("ignore")["ssids"]}, set(ctx.settings.get("networks")["ssids"]))
            for x in ssids:
                c = clients.get(x["ssid"], {})
                x["clients"], x["sessions"] = c.get("clients", 0), c.get("sessions", 0)
                x["ignored"], x["mine"] = x["ssid"] in ignored, x["ssid"] in mine
            return {"ssid_total": total, "ssids": ssids,
                    "channels": rows("SELECT channel, COALESCE(band, CASE WHEN channel <= 14 THEN '2.4' ELSE '5' END) AS b, "
                                     "COUNT(*) aps FROM devices WHERE kind='ap' AND channel IS NOT NULL AND last_seen>=? "
                                     "GROUP BY b, channel ORDER BY b = '6', b = '5', channel", (since,))}

        def probes():
            return {"probes": rows("SELECT ssid, COUNT(DISTINCT mac) clients, SUM(count) frames, "
                                   "(SELECT COUNT(*) FROM devices a WHERE a.kind='ap' AND a.ssid=p.ssid) aps "
                                   "FROM probes p WHERE last_seen>=? GROUP BY ssid ORDER BY clients DESC LIMIT ?", (since, limit))}

        def presence():
            # Which device was heard in which local hour, one row each: from the hourly roll-up where the timezone is a
            # whole number of hours (then every stored hour is exactly one local hour, so the result is the same as from
            # `samples`); the partial hour at the start of the period, and odd offsets such as +5:30, come from `samples`.
            if off % 3600 == 0:
                first = -(-int(since) // 3600) * 3600
                heard = ("SELECT mac, (hour - ?) / 3600 lh FROM presence_hours WHERE hour >= ? UNION ALL "  # the two never overlap
                         "SELECT DISTINCT mac, (minute - ?) / 3600 FROM samples WHERE minute >= ? AND minute < ?", (off, first, off, since, first))
            else:
                heard = ("SELECT DISTINCT mac, (minute - ?) / 3600 lh FROM samples WHERE minute >= ?", (off, since))
            # Counted per (local hour, kind) in one pass; the hourly chart, the weekly pattern and the number of days are all sums of that.
            return {"cells": rows(f"SELECT p.lh, d.kind, COUNT(*) n FROM ({heard[0]}) p LEFT JOIN devices d ON d.mac = p.mac "
                                  f"GROUP BY p.lh, d.kind", heard[1])}

        def radio_presence():
            # Zigbee radios and LoRa nodes are not devices: the same count from radio_seen (which radio was heard in each 5 minutes).
            return {"radio_cells": rows("SELECT (slot - ?) / 3600 lh, kind, COUNT(DISTINCT addr) n FROM radio_seen WHERE slot >= ? "
                                        "GROUP BY lh, kind", (off, since))}

        def activity(cells, radio):
            """The hourly chart and the weekly pattern from the per-local-hour counts (lh = hours since the epoch, local time)."""
            hourly, weekly = {}, {}
            for r in cells:
                day, h = divmod(r["lh"], 24)
                if r["kind"] is not None:  # a device that was deleted since is in no kind
                    hourly[(h, r["kind"])] = hourly.get((h, r["kind"]), 0) + r["n"]
                # Weekly activity pattern: distinct devices per (weekday, hour), same convention as a device's own
                # "weekly pattern" heatmap (/api/devices/{mac}/heatmap): epoch day 0 (1970-01-01) was a Thursday,
                # so +3 aligns it to a Monday=0 week. Not normalised per how many of each weekday fall in the
                # period (same simplification the per-device heatmap already makes), so it reads as relative
                # busyness, not a literal daily average.
                wd = (day + 3) % 7
                weekly[(wd, h)] = weekly.get((wd, h), 0) + r["n"]
            for r in radio:
                day, h = divmod(r["lh"], 24)
                hourly[(h, r["kind"])] = hourly.get((h, r["kind"]), 0) + r["n"]
                wd = (day + 3) % 7
                weekly[(wd, h)] = weekly.get((wd, h), 0) + r["n"]
            ndays = max(len({r["lh"] // 24 for r in cells}), len({r["lh"] // 24 for r in radio}), 1)
            return {"hourly": {"days": ndays, "rows": [{"h": h, "kind": k, "n": n} for (h, k), n in hourly.items()]},
                    "weekly_heat": [{"wd": wd, "h": h, "n": n} for (wd, h), n in weekly.items()]}

        def new():
            per_day = rows("SELECT CAST((first_seen - ?) / 86400 AS INTEGER) * 86400 + ? day, kind, "
                           "COUNT(*) n FROM devices WHERE first_seen>=? GROUP BY day, kind ORDER BY day", (off, off, since))
            # Zigbee radios and LoRa nodes first heard, from their own tables
            for kind, mod in (("zigbee", zigbee), ("lora", lora)):
                per_day += [{"day": r["day"], "kind": kind, "n": r["n"]} for r in mod.new_per_day(ctx, since, off)]
            return {"new_per_day": sorted(per_day, key=lambda r: r["day"]),
                    # New vendors: the first time ever (not just in this period) a vendor was seen, if that fell in
                    # this period: distinct from "new devices per day", which is usually dominated by randomized-MAC
                    # churn; this filters down to genuinely new kinds of hardware showing up nearby.
                    "new_vendors": rows(
                        "SELECT vendor, MIN(first_seen) first_seen, COUNT(*) devices FROM devices WHERE vendor IS NOT NULL "
                        "AND vendor != '' GROUP BY vendor HAVING MIN(first_seen) >= ? ORDER BY first_seen DESC LIMIT 100", (since,))}

        def sessions_part():
            return {"durations": rows(
                        "SELECT type, CASE WHEN d<60 THEN 0 WHEN d<300 THEN 1 WHEN d<1800 THEN 2 WHEN d<7200 THEN 3 "
                        "WHEN d<28800 THEN 4 ELSE 5 END b, COUNT(*) n FROM (SELECT type, end_ts-start_ts d FROM sessions "
                        "WHERE end_ts>=?) GROUP BY type, b", (since,)),
                    "top_clients": rows(
                        "SELECT s.mac, d.kind, d.vendor, d.name, d.randomized, COUNT(*) sessions, COUNT(DISTINCT s.peer) peers, "
                        "SUM(MIN(s.end_ts, ?) - MAX(s.start_ts, ?)) secs FROM sessions s LEFT JOIN devices d ON d.mac=s.mac "
                        "WHERE s.type='assoc' AND s.end_ts>=? GROUP BY s.mac ORDER BY secs DESC LIMIT ?", (now, since, since, limit)),
                    "top_aps": rows(
                        "SELECT s.peer mac, a.ssid, a.channel, a.band, a.vendor, COUNT(DISTINCT s.mac) clients, COUNT(*) sessions, "
                        "SUM(MIN(s.end_ts, ?) - MAX(s.start_ts, ?)) secs FROM sessions s JOIN devices a ON a.mac=s.peer "
                        "WHERE s.type='assoc' AND s.end_ts>=? AND a.kind='ap' GROUP BY s.peer ORDER BY clients DESC LIMIT ?",
                        (now, since, since, limit))}

        def events():
            return {"events": rows("SELECT type, COUNT(*) n FROM events WHERE ts>=? GROUP BY type ORDER BY n DESC", (since,))}

        # The per-kind counts of the devices heard in the period: one GROUP BY each, so the counting stays inside SQLite
        # (which runs side by side) instead of in Python.
        def by_column(col):
            return lambda: {col: rows(f"SELECT {col} v, kind, COUNT(*) n FROM devices WHERE last_seen>=? GROUP BY {col}, kind "
                                      f"ORDER BY n DESC", (since,))}

        def by_json(name, path, kinds):  # a field of the stored JSON, read only for the kinds that have it
            where = f"kind IN ({', '.join(repr(k) for k in kinds)}) AND " if kinds else ""
            return lambda: {name: rows(f"SELECT json_extract(extra, '{path}') v, kind, COUNT(*) n FROM devices WHERE {where}last_seen>=? "
                                       f"GROUP BY v, kind ORDER BY n DESC", (since,))}

        def vendors():
            return {"vendors": rows("SELECT COALESCE(vendor,'Unknown') vendor, kind, COUNT(*) n FROM devices "
                                    "WHERE last_seen>=? GROUP BY vendor, kind ORDER BY n DESC", (since,)),
                    "bands": rows("SELECT band, kind, COUNT(*) n FROM devices WHERE band IS NOT NULL AND last_seen>=? "
                                  "GROUP BY band, kind", (since,)),
                    "randomized": rows("SELECT kind, randomized, COUNT(*) n FROM devices WHERE last_seen>=? "
                                       "GROUP BY kind, randomized", (since,))}

        def sensors_part():
            # Which kinds of device each sensor heard in the period (a device heard by two sensors counts for both).
            return {"sensor_kinds": rows(
                "SELECT w.sensor id, COALESCE(s.name, w.sensor) name, d.kind, COUNT(*) n FROM sightings w "
                "JOIN devices d ON d.mac = w.mac LEFT JOIN sensors s ON s.id = w.sensor WHERE w.last_seen>=? "
                "GROUP BY w.sensor, d.kind", (since,))}

        def fingerprints():
            return {"fingerprints": rows(
                "SELECT fp_hash, COUNT(*) n, SUM(randomized) randomized, MAX(brand) brand, MAX(dev_type) dev_type, "
                "MAX(os) os, MAX(wifi_gen) wifi_gen FROM devices WHERE fp_hash IS NOT NULL AND last_seen>=? "
                "GROUP BY fp_hash HAVING n > 1 ORDER BY n DESC LIMIT ?", (since, limit))}

        def radios():
            # Zigbee / Thread radios and LoRa nodes live in tables of their own: their breakdowns come ready-made.
            return {"zigbee": zigbee.breakdown(ctx, since), "lora": lora.breakdown(ctx, since)}

        out = {"days": days}
        parts = (presence, radio_presence, vendors, networks, probes, new, sessions_part, events, sensors_part, fingerprints, radios,
                 *(by_column(c) for c in ("dev_type", "brand", "os", "wifi_gen", "era")),
                 by_json("addr_type", "$.addr_type", ("ble",)), by_json("company", "$.company", ("ble",)),
                 by_json("bt_ver", "$.bt_ver", ("ble", "bt_classic")), by_json("mobility", "$.mobility.c", ()))
        for part in STATS_POOL.map(lambda f: f(), parts):
            out.update(part)
        out.update(activity(out.pop("cells"), out.pop("radio_cells")))
        return out

    # Session-duration buckets of the Statistics chart (index -> seconds [lo, hi)); keep in sync with the CASE in stats().
    DURATION_BUCKETS = [(0, 60), (60, 300), (300, 1800), (1800, 7200), (7200, 28800), (28800, None)]

    @app.get("/api/sessions", dependencies=[Depends(current_user)])
    def sessions(type: str = "assoc", b: int = -1, days: float = 7, mac: str = None, sort: str = "start",
                 limit: int = 100, offset: int = 0):
        """Sessions that ended within the period, optionally only one duration bucket: the drill-down of the chart."""
        where, params = ["s.type = ?", "s.end_ts >= ?"], [type if type in ("assoc", "presence") else "assoc",
                                                          time.time() - days * 86400]
        if 0 <= b < len(DURATION_BUCKETS):
            lo, hi = DURATION_BUCKETS[b]
            where.append("s.end_ts - s.start_ts >= ?")
            params.append(lo)
            if hi is not None:
                where.append("s.end_ts - s.start_ts < ?")
                params.append(hi)
        if mac:
            where.append("s.mac = ?")
            params.append(mac.lower())
        w = " WHERE " + " AND ".join(where)
        order = "(s.end_ts - s.start_ts) DESC" if sort == "duration" else "s.start_ts DESC"
        total = one(f"SELECT COUNT(*) n FROM sessions s{w}", params)["n"]
        items = rows("SELECT s.id, s.mac, s.type, s.peer, s.start_ts, s.end_ts, s.open, s.end_reason, s.packets, "
                     "s.rssi_min, s.rssi_max, d.kind, d.name, d.vendor, d.randomized, m.label, a.ssid peer_ssid, "
                     "a.kind peer_kind FROM sessions s LEFT JOIN devices d ON d.mac = s.mac "
                     "LEFT JOIN devices a ON a.mac = s.peer LEFT JOIN device_meta m ON m.mac = s.mac"
                     f"{w} ORDER BY {order} LIMIT ? OFFSET ?", params + [max(1, min(limit, 500)), max(0, offset)])
        return {"total": total, "items": items, "now": time.time()}

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
    _csv = csv_response

    DEVICE_EXPORT_COLS = ["mac", "kind", "label", "group_name", "vendor", "brand", "model", "dev_type", "os", "wifi_gen",
                          "era", "fp_hash", "name", "ssid", "channel", "band", "freq", "enc", "bssid", "randomized",
                          "packets", "last_rssi", "best_rssi", "first_seen", "last_seen"]

    def export_rows(flt, sort, order):
        where, params = flt
        sort = "m.label" if sort == "label" else f"d.{sort if sort in SORTABLE else 'last_seen'}"
        order = "ASC" if order.lower() == "asc" else "DESC"
        return rows("SELECT d.*, m.label, g.name AS group_name FROM devices d LEFT JOIN device_meta m ON m.mac = d.mac "
                    f"LEFT JOIN groups g ON g.id = m.group_id{where} ORDER BY {sort} {order} NULLS LAST LIMIT 50000", params)

    # Both exports honour the same filters as the Devices page, so "export what I'm looking at" works.
    @app.get("/api/export/devices.csv", dependencies=[Depends(current_user)])
    def export_devices(flt=Depends(filter_args), sort: str = "last_seen", order: str = "desc"):
        return _csv("devices.csv", DEVICE_EXPORT_COLS, export_rows(flt, sort, order))

    @app.get("/api/export/devices.json", dependencies=[Depends(current_user)])
    def export_devices_json(flt=Depends(filter_args), sort: str = "last_seen", order: str = "desc"):
        data = [{c: r.get(c) for c in DEVICE_EXPORT_COLS} for r in export_rows(flt, sort, order)]
        return StreamingResponse(iter([json.dumps({"exported": time.time(), "count": len(data), "devices": data})]),
                                 media_type="application/json",
                                 headers={"Content-Disposition": 'attachment; filename="devices.json"'})

    @app.get("/api/export/sessions.csv", dependencies=[Depends(current_user)])
    def export_sessions(days: float = 7):
        cols = ["id", "mac", "type", "peer", "start_ts", "end_ts", "packets", "rssi_min", "rssi_max", "open",
                "end_reason"]
        return _csv("sessions.csv", cols, rows("SELECT * FROM sessions WHERE end_ts>=? ORDER BY start_ts",
                                               (time.time() - days * 86400,)))

    # ------------------------------------------------------------------ static
    # investigate and mqtt before manage: manage's catch-all /api/settings/{key} would otherwise shadow
    # /api/settings/investigate and /api/settings/mqtt
    for mod in (auth, appearance, modules, dataprivacy, adapters, purge, radiowatch, investigate, mqtt, manage, alerts, security, survey, health, metrics, sensors, reports, lan, zigbee, lora, interference, dfs,
                trackers, backup, search, logs, matching, handshake, channels, occupancy, capture, signal_live):
        app.include_router(mod.routes(ctx))

    # Cache-busting: reference static files as /static/x.js?v=<content hash>, so browsers pick up new
    # versions right after an update instead of running a stale cached copy.
    def versioned(name):
        html = (static / name).read_text()

        def tag(m):
            f = static / m.group(1)
            digest = hashlib.sha256(f.read_bytes()).hexdigest()[:10] if f.exists() else "0"
            return f'/static/{m.group(1)}?v={digest}"'
        return re.sub(r'/static/([\w.-]+\.(?:js|css))"', tag, html)

    pages = {"index": versioned("index.html"), "login": versioned("login.html")}
    ui_hash = hashlib.sha1(pages["index"].encode(), usedforsecurity=False).hexdigest()[:10]  # changes when any script or style of the UI does

    @app.get("/login")
    def login_page():
        return HTMLResponse(pages["login"])

    @app.get("/vendor/chart.umd.min.js")
    def chart_js():
        # bundled at build time; fall back to the pinned CDN copy (allowed by the CSP) if it's missing
        f = vendor_dir / "chart.umd.min.js"
        # pinned version, so a week is safe; the browser keeps its copy instead of re-fetching 200 kB per visit
        return (FileResponse(f, media_type="text/javascript", headers={"Cache-Control": "public, max-age=604800"})
                if f.exists() else RedirectResponse(CHART_JS_CDN))

    @app.get("/vendor/qrcode.js")
    def qrcode_js():
        # for the QR code of the two-factor setup; bundled at build time, the pinned CDN copy as fallback
        f = vendor_dir / "qrcode.js"
        return (FileResponse(f, media_type="text/javascript", headers={"Cache-Control": "public, max-age=604800"})
                if f.exists() else RedirectResponse(QRCODE_JS_CDN))

    @app.get("/vendor/esptool.bundle.js")
    def esptool_js():
        # the browser-side flasher (Settings -> LoRa flasher); bundled at build time like Chart.js, with the pinned CDN copy as fallback
        f = vendor_dir / "esptool.bundle.js"
        return (FileResponse(f, media_type="text/javascript", headers={"Cache-Control": "public, max-age=604800"})
                if f.exists() else RedirectResponse(ESPTOOL_JS_CDN))

    app.mount("/static", ImmutableStatic(directory=static), name="static")

    @app.get("/")
    def index():
        return HTMLResponse(pages["index"])

    return app
