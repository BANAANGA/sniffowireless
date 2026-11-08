"""Which kinds of radios the web interface shows. An admin can switch off the ones this installation doesn't use:
their menu entries, overview cards and statistics then disappear. Display only: capture itself is configured with
environment variables and keeps running."""
import secrets
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from . import status
from .auth import current_user, require_admin

MODULES = {"wifi": "Wi-Fi", "bluetooth": "Bluetooth", "lan": "Ethernet / LAN", "zigbee": "Zigbee & 802.15.4", "lora": "LoRa"}
# status type of a sensor interface -> module
SENSOR_MODULE = {"wifi": "wifi", "bluetooth": "bluetooth", "ethernet": "lan", "zigbee": "zigbee", "lora": "lora"}
# One cheap probe per module: does the database hold anything of that kind?
PROBES = {
    "wifi": "SELECT 1 FROM devices WHERE kind IN ('ap','wifi_client') LIMIT 1",
    "bluetooth": "SELECT 1 FROM devices WHERE kind IN ('ble','bt_classic') LIMIT 1",
    "lan": "SELECT 1 FROM devices WHERE kind='lan' LIMIT 1",
    "zigbee": "SELECT 1 FROM zigbee_radios LIMIT 1",
    "lora": "SELECT 1 FROM lora_nodes LIMIT 1",
}


class ModulesBody(BaseModel):
    disabled: List[str]


class PrivacyBody(BaseModel):
    macs: bool
    ssids: bool


def disabled(ctx):
    return [m for m in ctx.settings.get("modules").get("disabled", []) if m in MODULES]


def in_use(ctx):
    """Modules with a sensor interface configured (here or on a remote sensor) or with stored data."""
    used = {SENSOR_MODULE[s.get("type")] for s in status.snapshot() if s.get("type") in SENSOR_MODULE}
    for m, sql in PROBES.items():
        if m not in used:
            try:
                if ctx.rows(sql):
                    used.add(m)
            except Exception:  # a table that does not exist yet: nothing of that kind
                pass
    return used


def routes(ctx):
    r = APIRouter()

    def view():
        off, used = set(disabled(ctx)), in_use(ctx)
        p = ctx.settings.get("privacy")
        return {"modules": [{"id": m, "label": label, "enabled": m not in off, "in_use": m in used} for m, label in MODULES.items()],
                "privacy": {"macs": bool(p.get("macs")), "ssids": bool(p.get("ssids"))}}

    @r.get("/api/modules")
    def get_modules(_=Depends(current_user)):
        return view()

    @r.put("/api/modules")
    def put_modules(body: ModulesBody, _=Depends(require_admin)):
        bad = [m for m in body.disabled if m not in MODULES]
        if bad:
            raise HTTPException(400, f"Unknown module: {bad[0]}")
        ctx.settings.set("modules", {"disabled": sorted(set(body.disabled))})
        return view()

    @r.get("/api/privacy")
    def get_privacy(_=Depends(current_user)):
        return view()["privacy"]

    @r.put("/api/privacy")
    def put_privacy(body: PrivacyBody, _=Depends(require_admin)):
        p = ctx.settings.get("privacy")
        p.update(macs=body.macs, ssids=body.ssids)
        if (body.macs or body.ssids) and not p.get("secret"):
            p["secret"] = secrets.token_hex(16)  # the key of the pseudonyms: kept, so they stay the same
        ctx.settings.set("privacy", p)
        return view()["privacy"]

    return r
