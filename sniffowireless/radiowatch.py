"""Names and watches for LoRa nodes and Zigbee radios (they have no MAC address, so the device labels and watch flags do not
apply to them). A node can be given a name, and watched: when it has not been heard for the number of minutes chosen, an event
`watched_silent` is raised (alert rules can notify on it), and `watched_back` when it is heard again.

A radio that hops between profiles hears a node only part of the time, so choose a time well above the node's own
interval (Meshtastic and MeshCore nodes announce themselves every few hours; a sensor sending every 10 minutes is heard
within about an hour even with a few profiles)."""
import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .auth import current_user, require_admin
from .sanitize import clean_str

log = logging.getLogger("sniffowireless.radiowatch")

SCHEMA = """
CREATE TABLE IF NOT EXISTS radio_watch(
  kind TEXT NOT NULL, ref TEXT NOT NULL, addr TEXT NOT NULL, label TEXT, watch INTEGER DEFAULT 0, silent_min INTEGER DEFAULT 60,
  state TEXT DEFAULT 'ok', changed REAL, PRIMARY KEY(kind, ref, addr)) WITHOUT ROWID;
"""
CHECK_EVERY = 60
LAST_SEEN_SQL = {
    "lora": "SELECT last_seen FROM lora_nodes WHERE protocol=? AND addr=?",
    "zigbee": "SELECT last_seen FROM zigbee_radios WHERE pan=? AND addr=?",
}
MAC_PREFIX = {"lora": "lora:", "zigbee": "zb:"}


def _ago(s):
    s = int(s)
    return f"{s // 86400} days" if s >= 2 * 86400 else f"{s // 3600} hours" if s >= 7200 else f"{max(1, s // 60)} minutes"


class RadioWatch:
    """Store plugin: checks the watched nodes once a minute."""

    def __init__(self, ctx):
        self.ctx = ctx
        ctx.store.conn.executescript(SCHEMA)
        self.checked = 0
        self.pending = False

    def sweep(self, store, now):
        if now - self.checked < CHECK_EVERY:
            return
        self.checked = now
        c = store.conn
        for kind, ref, addr, label, silent_min, state in c.execute(
                "SELECT kind, ref, addr, label, silent_min, state FROM radio_watch WHERE watch=1").fetchall():
            try:
                row = c.execute(LAST_SEEN_SQL[kind], (int(ref) if kind == "zigbee" else ref, addr)).fetchone()
            except (KeyError, ValueError):
                continue
            if not row:
                continue  # never heard: nothing to be silent about yet
            quiet = now - row[0]
            name = label or addr
            mac = MAC_PREFIX[kind] + addr
            if quiet > silent_min * 60 and state != "silent":
                store._event(now, mac, "watched_silent", ref, f"{name} has not been heard for {_ago(quiet)}", always=True)
                c.execute("UPDATE radio_watch SET state='silent', changed=? WHERE kind=? AND ref=? AND addr=?", (now, kind, ref, addr))
            elif quiet <= silent_min * 60 and state == "silent":
                store._event(now, mac, "watched_back", ref, f"{name} is heard again", always=True)
                c.execute("UPDATE radio_watch SET state='ok', changed=? WHERE kind=? AND ref=? AND addr=?", (now, kind, ref, addr))


def watch_map(ctx, kind):
    """(ref, addr) -> the saved name / watch of a node, for the pages that list them."""
    try:
        return {(r["ref"], r["addr"]): r for r in ctx.rows("SELECT * FROM radio_watch WHERE kind=?", (kind,))}
    except Exception:
        return {}


class WatchBody(BaseModel):
    kind: str = Field(pattern="^(lora|zigbee)$")
    ref: str = Field(min_length=1, max_length=40)     # LoRa: the protocol; Zigbee: the PAN as a number
    addr: str = Field(min_length=1, max_length=100)
    label: Optional[str] = Field(None, max_length=60)
    watch: bool = False
    silent_min: int = Field(60, ge=5, le=60 * 24 * 14)


def routes(ctx):
    r = APIRouter()

    @r.get("/api/radios/watch")
    def listing(_=Depends(current_user)):
        return {"items": ctx.rows("SELECT * FROM radio_watch ORDER BY kind, label, addr")}

    @r.put("/api/radios/watch")
    def save(body: WatchBody, _=Depends(require_admin)):
        if body.kind == "zigbee" and not body.ref.isdigit():
            raise HTTPException(400, "A Zigbee radio is identified by its PAN, a number")
        label = clean_str(body.label, 60) if body.label else None
        key = (body.kind, body.ref, body.addr)
        with ctx.wdb() as c:
            if not label and not body.watch:
                c.execute("DELETE FROM radio_watch WHERE kind=? AND ref=? AND addr=?", key)
            else:
                c.execute("INSERT INTO radio_watch(kind, ref, addr, label, watch, silent_min, state, changed) VALUES(?,?,?,?,?,?, 'ok', ?) "
                          "ON CONFLICT(kind, ref, addr) DO UPDATE SET label=excluded.label, watch=excluded.watch, silent_min=excluded.silent_min, "
                          "state=CASE WHEN excluded.watch=0 THEN 'ok' ELSE state END", (*key, label, int(body.watch), body.silent_min, time.time()))
        return ctx.one("SELECT * FROM radio_watch WHERE kind=? AND ref=? AND addr=?", key) or {"deleted": True}

    return r
