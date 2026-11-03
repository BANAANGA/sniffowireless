"""Appearance: admin-chosen app name, icon and colours. Readable without login (the sign-in page uses it too).

Colours are strict #rrggbb values; the icon is one of the built-in glyphs or an uploaded PNG/JPEG/WebP (no SVG, so
nothing scriptable is ever served back), stored in the data directory and included in full backups.
"""
import os
import re
import time
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator

from .auth import require_admin
from .sanitize import clean_str

# Defaults are the stock palette in style.css; keep both in sync.
COLORS = {
    "bg": "#0b0c0e", "panel": "#111316", "border": "#1f2227", "text": "#e6e7e9", "muted": "#8a8f98",
    "ap": "#4cc2ff", "wifi_client": "#3ecf8e", "ble": "#f5b84a", "bt_classic": "#ef6f6c", "lan": "#a8b3c2",
    "good": "#3ecf8e", "warn": "#f5b84a", "bad": "#ef6f6c", "icon": "#e6e7e9",
}
ICONS = ("dot", "wifi", "radar", "bluetooth", "eye", "shield", "custom")
STYLES = ("", "vicecity")  # optional decoration on top of the colours (gradients, glow); see style.css
CLOCKS = ("auto", "24", "12")  # auto: the browser's locale decides
ICON_TYPES = {"png": "image/png", "jpg": "image/jpeg", "webp": "image/webp"}
MAX_ICON = 256 * 1024
HEX = re.compile(r"^#[0-9a-f]{6}$")


def icon_file(a):
    """The stored icon file name, only if it is one we wrote (a restored config backup could hold anything)."""
    name = a.get("icon_file")
    return name if isinstance(name, str) and re.fullmatch(r"appicon\.(png|jpg|webp)", name) else None


def icon_type(data):
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


class Appearance(BaseModel):
    name: str = Field("yolo", max_length=32)
    icon: str = "dot"
    clock: str = "auto"
    style: str = ""
    colors: Dict[str, str] = {}

    @field_validator("clock")
    @classmethod
    def _clock(cls, v):
        if v not in CLOCKS:
            raise ValueError("clock must be auto, 24 or 12")
        return v

    @field_validator("style")
    @classmethod
    def _style(cls, v):
        if v not in STYLES:
            raise ValueError("unknown style")
        return v

    @field_validator("name")
    @classmethod
    def _name(cls, v):
        return re.sub(r"[<>]", "", clean_str(v, 32) or "").strip() or "yolo"

    @field_validator("icon")
    @classmethod
    def _icon(cls, v):
        if v not in ICONS:
            raise ValueError("unknown icon")
        return v

    @field_validator("colors")
    @classmethod
    def _colors(cls, v):
        out = {}
        for k, c in v.items():
            c = str(c).strip().lower()
            if k not in COLORS:
                raise ValueError(f"unknown colour {k!r}")
            if not HEX.match(c):
                raise ValueError(f"{k}: use a #rrggbb colour")
            if c != COLORS[k]:
                out[k] = c  # store only what differs from the default
        return out


def time_format(ctx, seconds=False):
    """strftime time format for server-made text (notifications, reports): 12-hour only if the admin chose it."""
    twelve = ctx.settings.get("appearance").get("clock") == "12" if ctx and ctx.settings else False
    return ("%I:%M:%S %p" if seconds else "%I:%M %p") if twelve else ("%H:%M:%S" if seconds else "%H:%M")


def current(ctx):
    a = ctx.settings.get("appearance")
    icon = a.get("icon") or "dot"
    custom = icon_file(a) if icon == "custom" else None
    if icon == "custom" and not (custom and os.path.exists(os.path.join(ctx.cfg.data_dir, custom))):
        icon, custom = "dot", None
    return {"name": a.get("name") or "yolo", "icon": icon,
            "clock": a.get("clock") if a.get("clock") in CLOCKS else "auto",
            "style": a.get("style") if a.get("style") in STYLES else "",
            "colors": {**COLORS, **(a.get("colors") or {})},
            "custom_colors": sorted((a.get("colors") or {}).keys()), "defaults": COLORS, "icons": list(ICONS),
            "icon_url": f"/api/appearance/icon?v={int(a.get('icon_ver') or 0)}" if custom else None}


def routes(ctx):
    r = APIRouter()
    data_dir = ctx.cfg.data_dir

    @r.get("/api/appearance")
    def get_appearance():
        return current(ctx)

    @r.put("/api/appearance")
    def put_appearance(body: Appearance, _=Depends(require_admin)):
        a = dict(ctx.settings.get("appearance"))
        if body.icon == "custom" and not icon_file(a):
            raise HTTPException(400, "Upload an icon image first")
        a.update({"name": body.name, "icon": body.icon, "clock": body.clock, "style": body.style, "colors": body.colors})
        ctx.settings.set("appearance", a)
        return current(ctx)

    @r.post("/api/appearance/icon")
    async def upload_icon(request: Request, _=Depends(require_admin)):
        data = await request.body()
        if len(data) > MAX_ICON:
            raise HTTPException(413, "Icon larger than 256 kB")
        ext = icon_type(data)  # judge by content, not by the client's Content-Type
        if not ext:
            raise HTTPException(415, "Upload a PNG, JPEG or WebP image")
        for old in os.listdir(data_dir):
            if old.startswith("appicon."):
                os.remove(os.path.join(data_dir, old))
        name = f"appicon.{ext}"
        with open(os.path.join(data_dir, name), "wb") as fh:
            fh.write(data)
        a = dict(ctx.settings.get("appearance"))
        a.update({"icon": "custom", "icon_file": name, "icon_ver": int(time.time())})
        ctx.settings.set("appearance", a)
        return current(ctx)

    @r.delete("/api/appearance/icon")
    def delete_icon(_=Depends(require_admin)):
        a = dict(ctx.settings.get("appearance"))
        if icon_file(a):
            try:
                os.remove(os.path.join(data_dir, icon_file(a)))
            except OSError:
                pass
        a.update({"icon": "dot" if a.get("icon") == "custom" else a.get("icon", "dot"), "icon_file": None})
        ctx.settings.set("appearance", a)
        return current(ctx)

    @r.get("/api/appearance/icon")
    def icon(v: Optional[int] = None):
        name = icon_file(ctx.settings.get("appearance"))
        path = os.path.join(data_dir, name) if name else None
        if not path or not os.path.exists(path):
            raise HTTPException(404)
        return FileResponse(path, media_type=ICON_TYPES[name.rsplit(".", 1)[-1]])

    return r
