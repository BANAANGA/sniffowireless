"""Prometheus metrics endpoint (/metrics). Requires a login session or an API token
(scope metrics, read or admin) sent as `Authorization: Bearer <token>`."""
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse

from . import status, version


def _esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


class Out:
    def __init__(self):
        self.lines, self.seen = [], set()

    def add(self, name, value, help_, type_="gauge", **labels):
        if name not in self.seen:
            self.lines += [f"# HELP {name} {help_}", f"# TYPE {name} {type_}"]
            self.seen.add(name)
        lab = ",".join(f'{k}="{_esc(v)}"' for k, v in labels.items() if v is not None)
        self.lines.append(f"{name}{{{lab}}} {value}" if lab else f"{name} {value}")

    def text(self):
        return "\n".join(self.lines) + "\n"


def render(ctx):
    now = time.time()
    o = Out()
    v = version.info()
    o.add("sniffowireless_build_info", 1, "Version and build of this server", version=v["version"], commit=v["commit"] or "unknown")
    active = now - ctx.cfg.active_window
    for r in ctx.rows("SELECT kind, COUNT(*) total, SUM(last_seen >= ?) active FROM devices GROUP BY kind", (active,)):
        o.add("sniffowireless_devices_total", r["total"], "Devices ever seen (within retention)", kind=r["kind"])
        o.add("sniffowireless_devices_active", r["active"] or 0, "Devices seen within the active window", kind=r["kind"])
    for r in ctx.rows("SELECT dev_type, COUNT(*) n FROM devices WHERE last_seen >= ? GROUP BY dev_type", (active,)):
        o.add("sniffowireless_devices_active_by_type", r["n"], "Active devices by identified type", type=r["dev_type"] or "unknown")
    for r in ctx.rows("SELECT a.ssid, a.mac, a.band, a.channel, COUNT(s.id) n FROM devices a LEFT JOIN sessions s ON "
                      "s.peer=a.mac AND s.type='assoc' AND s.open=1 WHERE a.kind='ap' AND a.last_seen >= ? "
                      "GROUP BY a.mac", (now - 3600,)):
        o.add("sniffowireless_ap_clients", r["n"], "Clients currently connected per access point", bssid=r["mac"],
              ssid=r["ssid"] or "", band=r["band"], channel=r["channel"])
    my = ctx.settings.get("networks")["ssids"]
    for r in ctx.rows("SELECT d.mac, d.last_rssi, d.last_seen, d.kind, COALESCE(m.label, d.name, d.mac) label, "
                      "m.watch FROM device_meta m JOIN devices d ON d.mac=m.mac WHERE m.watch=1 OR m.label IS NOT NULL"):
        o.add("sniffowireless_device_present", int(r["last_seen"] >= active), "Labelled/watched device present (1) or not (0)",
              mac=r["mac"], label=r["label"], kind=r["kind"])
        if r["last_rssi"] is not None and r["last_seen"] >= active:
            o.add("sniffowireless_device_rssi_dbm", r["last_rssi"], "Last signal strength of labelled devices", mac=r["mac"],
                  label=r["label"])
    for r in ctx.rows("SELECT g.id, g.name, SUM(d.last_seen >= ?) present FROM groups g JOIN device_meta m ON "
                      "m.group_id=g.id JOIN devices d ON d.mac=m.mac GROUP BY g.id", (active,)):
        o.add("sniffowireless_group_present", int((r["present"] or 0) > 0), "Group (person) present", group=r["name"])
    for r in ctx.rows("SELECT type, COUNT(*) n FROM events WHERE ts >= ? GROUP BY type", (now - 86400,)):
        o.add("sniffowireless_events_24h", r["n"], "Events in the last 24 hours", type=r["type"])
    for r in ctx.rows("SELECT severity, COUNT(*) n FROM findings WHERE status='open' GROUP BY severity"):
        o.add("sniffowireless_security_findings_open", r["n"], "Open security findings", severity=r["severity"])
    for r in ctx.rows("SELECT freq, SUM(airtime_us)*1.0/NULLIF(SUM(dwell_ms)*1000,0) u, SUM(retries)*1.0/"
                      "NULLIF(SUM(frames),0) rr FROM channel_stats WHERE minute >= ? GROUP BY freq", (now - 900,)):
        if r["u"] is not None:
            o.add("sniffowireless_channel_utilization_ratio", round(min(1, r["u"]), 4), "Estimated airtime use (15 min)",
                  freq=r["freq"])
        if r["rr"] is not None:
            o.add("sniffowireless_channel_retry_ratio", round(r["rr"], 4), "Share of retransmitted frames (15 min)", freq=r["freq"])
    if my:
        q = ",".join("?" * len(my))
        for r in ctx.rows(f"SELECT a.ssid, COUNT(DISTINCT s.mac) n FROM sessions s JOIN devices a ON a.mac=s.peer "
                          f"WHERE s.type='assoc' AND s.open=1 AND a.ssid IN ({q}) GROUP BY a.ssid", my):
            o.add("sniffowireless_my_network_clients", r["n"], "Clients connected to my networks", ssid=r["ssid"])
    for s in status.snapshot():
        o.add("sniffowireless_sensor_packets_total", s.get("packets") or 0, "Frames/adverts captured", "counter",
              sensor=s["name"])
        o.add("sniffowireless_sensor_pps", s.get("pps") or 0, "Frames per second", sensor=s["name"])
        o.add("sniffowireless_sensor_up", int(s.get("state") not in ("error", "offline")), "Sensor healthy", sensor=s["name"])
    for r in ctx.rows("SELECT t.mac, COALESCE(m.label, d.name, d.ip, t.mac) label, SUM(t.bytes_out) o, SUM(t.bytes_in) i "
                      "FROM lan_traffic t LEFT JOIN devices d ON d.mac=t.mac LEFT JOIN device_meta m ON m.mac=t.mac "
                      "WHERE t.minute >= ? GROUP BY t.mac ORDER BY o + i DESC LIMIT 50", (now - 3600,)):
        o.add("sniffowireless_lan_bytes_1h", r["o"] or 0, "LAN bytes sent/received in the last hour (top 50 devices)",
              mac=r["mac"], label=r["label"], direction="out")
        o.add("sniffowireless_lan_bytes_1h", r["i"] or 0, "LAN bytes sent/received in the last hour (top 50 devices)",
              mac=r["mac"], label=r["label"], direction="in")
    for r in ctx.rows("SELECT from_ch, COUNT(*) n FROM dfs_events WHERE dfs=1 AND ts >= ? GROUP BY from_ch", (now - 86400,)):
        o.add("sniffowireless_dfs_radar_24h", r["n"], "Radar hits (access points forced off a DFS channel) in the last 24 h",
              channel=r["from_ch"])
    if ctx.dfs:
        for k, v in ctx.dfs.counts.items():
            o.add("sniffowireless_dfs_events_total", v, "DFS events since start (radar, channel switch announcements, channel changes)",
                  "counter", kind=k)
    st = ctx.store.stats()
    o.add("sniffowireless_store_queue", st["queue"], "Observations waiting to be processed")
    o.add("sniffowireless_store_dropped_total", st["dropped"], "Observations dropped because the queue was full", "counter")
    o.add("sniffowireless_store_processed_total", st["processed"], "Observations processed", "counter")
    o.add("sniffowireless_db_bytes", st["db_bytes"], "Database size")
    o.add("sniffowireless_present_devices", st["open_presence"], "Devices currently in range")
    return o.text()


def routes(ctx):
    r = APIRouter()

    @r.get("/metrics")
    def metrics(request: Request):
        u = request.state.user
        if not u or getattr(u, "scope", "metrics") not in ("metrics", "read", "admin"):
            raise HTTPException(401, "metrics token required")
        return PlainTextResponse(render(ctx), media_type="text/plain; version=0.0.4")

    return r
