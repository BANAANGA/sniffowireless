"""Admin: clear everything stored for one kind of radio (Wi-Fi, Bluetooth, Ethernet, Zigbee, LoRa), and / or its events and
alert history, or the in-memory application log. For starting over, or after trying something out.

What goes: the devices of that kind with their sessions, signal history, probes and events, and the module's own tables
(channel survey, DFS and interference history, security findings, LAN traffic / DNS / flows, Zigbee and LoRa data ...).
What stays: labels, notes, groups and watch flags (they belong to you, and attach again if a device comes back), alert
rules, notification channels, settings, users, sensors, and downloaded handshake captures.
Deleting runs on the store's writer thread, after everything pending is written, so memory and database stay consistent."""
import logging
import threading

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .auth import require_admin
from .modules import MODULES

log = logging.getLogger("sniffowireless.purge")

# kinds: rows of `devices`; tables: deleted completely; finding_types: security findings that belong to the module
SPEC = {
    "wifi": {"kinds": ("ap", "wifi_client"), "tables": ("channel_stats", "interference", "dfs_events", "ap_enc"), "findings": "wifi"},
    "bluetooth": {"kinds": ("ble", "bt_classic"), "tables": (), "findings": ("unknown_tracker",)},
    "lan": {"kinds": ("lan",), "tables": ("lan_dns", "lan_flows", "lan_traffic", "dhcp_servers"), "findings": ("rogue_dhcp", "arp_spoof")},
    "zigbee": {"kinds": (), "tables": ("zigbee_networks", "zigbee_radios", "zigbee_channels", "zigbee_energy"), "seen": "zigbee"},
    "lora": {"kinds": (), "tables": ("lora_packets", "lora_nodes", "lora_stats"), "seen": "lora"},
}
OTHER_FINDINGS = SPEC["bluetooth"]["findings"] + SPEC["lan"]["findings"]
# events (and the alert history, which has the same type / mac columns) that belong to a module
EVENT_TYPES = {  # (events about watched radios have lora: / zb: addresses and are found through those)
    "wifi": ("ap_restart", "rogue_ap", "deauth_flood", "deauth_broadcast", "karma_ap", "security_finding", "interference", "dfs_radar", "channel_switch_announced",
             "channel_change", "investigated_seen", "investigated_connect", "investigated_probe", "fingerprint_changed", "handshake_attack",
             "ap_downgrade", "probe_scan", "mac_duplicate"),
    "bluetooth": ("tracker_following",),
    "lan": ("rogue_dhcp", "arp_spoof"),
    "zigbee": (),
    "lora": (),
}
EVENT_LIKE = {"zigbee": "zigbee\\_%", "lora": "lora\\_%"}
EVENT_MAC_LIKE = {"wifi": ("rf:%",), "zigbee": ("zb:%",), "lora": ("lora:%",)}


def log_predicate(module):
    """SQL for the rows of `events` / `alert_log` of a module, and its parameters."""
    spec, parts, params = SPEC[module], [], []
    types = EVENT_TYPES[module]
    if types:
        parts.append(f"type IN ({','.join('?' * len(types))})")
        params += types
    if module in EVENT_LIKE:
        parts.append("type LIKE ? ESCAPE '\\'")
        params.append(EVENT_LIKE[module])
    if spec["kinds"]:
        parts.append(f"mac IN (SELECT mac FROM devices WHERE kind IN ({','.join('?' * len(spec['kinds']))}))")
        params += spec["kinds"]
    for like in EVENT_MAC_LIKE.get(module, ()):
        parts.append("mac LIKE ?")
        params.append(like)
    return "(" + " OR ".join(parts) + ")", params


def finding_predicate(module):
    f = SPEC[module].get("findings")
    if f == "wifi":
        return f"type NOT IN ({','.join('?' * len(OTHER_FINDINGS))})", list(OTHER_FINDINGS)
    if f:
        return f"type IN ({','.join('?' * len(f))})", list(f)
    return None, []


def counts(ctx, module):
    """What clearing a module would delete (a preview for the confirmation)."""
    spec, one = SPEC[module], ctx.one
    entries, logs = {}, {}
    if spec["kinds"]:
        entries["devices"] = one(f"SELECT COUNT(*) n FROM devices WHERE kind IN ({','.join('?' * len(spec['kinds']))})", spec["kinds"])["n"]
    for t in spec["tables"]:
        try:
            entries[t] = one(f"SELECT COUNT(*) n FROM {t}")["n"]
        except Exception:
            entries[t] = 0
    where, params = finding_predicate(module)
    if where:
        entries["findings"] = one(f"SELECT COUNT(*) n FROM findings WHERE {where}", params)["n"]
    pred, pp = log_predicate(module)
    logs["events"] = one(f"SELECT COUNT(*) n FROM events WHERE {pred}", pp)["n"]
    logs["alert_log"] = one(f"SELECT COUNT(*) n FROM alert_log WHERE {pred}", pp)["n"]
    return {"entries": entries, "entries_total": sum(entries.values()), "logs": logs, "logs_total": sum(logs.values())}


def clear(ctx, st, module, entries, logs):
    """On the writer thread."""
    st.flush()
    c, spec, out = st.conn, SPEC[module], {}
    if logs:  # first: the entries' own events are matched through the devices that still exist
        pred, params = log_predicate(module)
        c.execute("BEGIN")
        for table in ("events", "alert_log"):
            out[table] = c.execute(f"DELETE FROM {table} WHERE {pred}", params).rowcount
        c.execute("COMMIT")
    if entries:
        if spec["kinds"]:
            macs = [r[0] for r in c.execute(f"SELECT mac FROM devices WHERE kind IN ({','.join('?' * len(spec['kinds']))})", spec["kinds"])]
            st.forget(macs)
            out["devices"] = len(macs)
        c.execute("BEGIN")
        for t in spec["tables"]:
            try:
                out[t] = c.execute(f"DELETE FROM {t}").rowcount
            except Exception:
                pass
        where, params = finding_predicate(module)
        if where:
            out["findings"] = c.execute(f"DELETE FROM findings WHERE {where}", params).rowcount
        if spec.get("seen"):
            c.execute("DELETE FROM radio_seen WHERE kind=?", (spec["seen"],))
        c.execute("COMMIT")
        for hook in (ctx.lora, ctx.zigbee, ctx.interference, ctx.lan):  # what they remember in memory about what is gone
            if hook is not None and hasattr(hook, "reset"):
                hook.reset(module)
    log.info("Cleared %s%s: %s", module, "" if entries and logs else " entries" if entries else " logs", out)
    return out


class Body(BaseModel):
    module: str
    entries: bool = False
    logs: bool = False
    confirm: str = ""


def routes(ctx):
    r = APIRouter()

    @r.get("/api/purge")
    def preview(_=Depends(require_admin)):
        return {"modules": [{"id": m, "label": label, **counts(ctx, m)} for m, label in MODULES.items()]}

    @r.post("/api/purge")
    def purge(body: Body, _=Depends(require_admin)):
        if body.module not in SPEC:
            raise HTTPException(400, "Unknown module")
        if body.confirm != body.module:
            raise HTTPException(400, "Confirm by sending the module name in `confirm`")
        if not (body.entries or body.logs):
            raise HTTPException(400, "Nothing selected")
        done, box = threading.Event(), {}

        def job(st):
            try:
                box["out"] = clear(ctx, st, body.module, body.entries, body.logs)
            except Exception as e:  # reported to the caller, the writer carries on
                log.exception("Clearing %s failed", body.module)
                box["err"] = str(e)
            finally:
                done.set()

        ctx.store.command(job)
        if not done.wait(300):
            raise HTTPException(504, "Still working; check again in a minute")
        if "err" in box:
            raise HTTPException(500, box["err"])
        return {"deleted": box["out"], **counts(ctx, body.module)}

    @r.delete("/api/purge/app-log")
    def clear_app_log(_=Depends(require_admin)):
        from .logs import HANDLER
        with HANDLER.buf_lock:
            n = len(HANDLER.buf)
            HANDLER.buf.clear()
        log.info("The application log was cleared (%d lines)", n)
        return {"deleted": n}

    return r
