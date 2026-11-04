"""Per-SSID WPA/WPA2 4-way-handshake capture: an opt-in admin feature for auditing the password strength
of your own Wi-Fi networks offline (e.g. with hashcat or aircrack-ng).

Capture can only be turned on for SSIDs already marked "My networks" (Settings → My networks): the two
settings are intersected on every read, so a network dropped from "My networks" stops being captured
immediately, even if it is still ticked here. This is deliberate and load-bearing — without it, the
feature would let an admin capture handshakes from any nearby network, including a neighbour's, which
is a different (and unauthorized) use. Nothing here sends deauthentication frames or otherwise forces a
handshake; it only records one if a client naturally (re)associates while capture is on.
"""
import hashlib
import json
import logging
import os
import threading
import time

log = logging.getLogger("yolo.handshake")

DIR_NAME = "handshakes"


def eapol_message(pkt):
    """1-4 for a WPA/WPA2 4-way-handshake EAPOL-Key frame, else None.

    Classifies by the Key Information flags (ACK / MIC / Secure) the same way aircrack-ng and
    hcxdumptool do; scapy parses the EAPOL header but not the WPA key body, so those three bits are
    read directly from the raw payload (byte 0 is the descriptor type, bytes 1-2 are Key Information).
    """
    try:
        from scapy.layers.eap import EAPOL
    except ImportError:  # pragma: no cover - scapy always available where this runs
        return None
    if not pkt.haslayer(EAPOL) or pkt[EAPOL].type != 3:
        return None
    body = bytes(pkt[EAPOL].payload)
    if len(body) < 3:
        return None
    ki = (body[1] << 8) | body[2]
    ack, mic, secure = bool(ki & 0x80), bool(ki & 0x100), bool(ki & 0x200)
    if ack and not mic:
        return 1
    if not ack and mic and not secure:
        return 2
    if ack and mic and secure:
        return 3
    if not ack and mic and secure:
        return 4
    return None


def _slug(ssid):
    """A filesystem-safe, non-reversible name for the SSID's files (SSIDs are chosen by whoever broadcasts
    them, so they're never used directly as a path or HTTP header value)."""
    return hashlib.sha1(ssid.encode("utf-8", "surrogatepass")).hexdigest()[:20]


class HandshakeCapture:
    """Owned by Ctx; fed raw 802.11 frames by every local WifiSensor, read/controlled by the web API."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.dir = os.path.join(ctx.cfg.data_dir, DIR_NAME)
        os.makedirs(self.dir, exist_ok=True)
        self.lock = threading.Lock()
        self.bssid_ssid = {}   # bssid -> ssid, learned from beacons/probe responses (not persisted; relearned in seconds)
        self.wanted = set()    # cache of {capture-enabled ssids} ∩ {my networks}, refreshed on settings change
        self.writers = {}      # ssid -> open scapy PcapWriter, while capture is wanted and this process has seen a frame
        self.state = {}        # ssid -> {"bssids": set, "pairs": {(bssid, sta): set(msg numbers)}, "frames", "bytes", "started", "updated"}
        self._load_state()
        self._refresh()
        ctx.settings.on_change(lambda k: self._refresh() if k in ("handshake", "networks") else None)

    # -------------------------------------------------------------- scope (settings)
    def _refresh(self):
        mine = set(self.ctx.settings.get("networks")["ssids"])
        on = set(self.ctx.settings.get("handshake")["ssids"])
        with self.lock:
            self.wanted = mine & on
            for ssid in list(self.writers):  # e.g. dropped from "My networks", or capture just turned off
                if ssid not in self.wanted:
                    self._close(ssid)

    def want(self, ssid):
        return ssid in self.wanted

    # -------------------------------------------------------------- persistence (a capture often spans a
    # restart of the sensor; the admin should still be able to see progress and download what was captured)
    def _meta_path(self, ssid):
        return os.path.join(self.dir, _slug(ssid) + ".json")

    def _pcap_path(self, ssid):
        return os.path.join(self.dir, _slug(ssid) + ".pcap")

    def _load_state(self):
        if not os.path.isdir(self.dir):
            return
        for name in os.listdir(self.dir):
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.dir, name), encoding="utf-8") as fh:
                    m = json.load(fh)
                ssid = m.get("ssid")
                if not isinstance(ssid, str) or not ssid:
                    continue
                self.state[ssid] = {
                    "bssids": set(m.get("bssids") or []),
                    "pairs": {tuple(k.split("|", 1)): set(v) for k, v in (m.get("pairs") or {}).items()},
                    "frames": int(m.get("frames", 0)), "bytes": int(m.get("bytes", 0)),
                    "started": m.get("started"), "updated": m.get("updated"),
                }
            except (OSError, ValueError):
                log.warning("Could not read handshake state %s", name, exc_info=True)

    def _save_state(self, ssid):
        st = self.state[ssid]
        m = {"ssid": ssid, "bssids": sorted(st["bssids"]), "frames": st["frames"], "bytes": st["bytes"],
            "started": st["started"], "updated": st["updated"],
            "pairs": {f"{b}|{s}": sorted(v) for (b, s), v in st["pairs"].items()}}
        tmp = self._meta_path(ssid) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(m, fh)
        os.replace(tmp, self._meta_path(ssid))

    # -------------------------------------------------------------- live capture (WifiSensor capture thread)
    def note_ap(self, bssid, ssid):
        """Learn which SSID a BSSID is currently broadcasting, from an already-parsed beacon/probe response."""
        if ssid:
            self.bssid_ssid[bssid] = ssid

    def feed(self, pkt, bssid, sta, msg):
        """Record one EAPOL-Key frame if its BSSID is currently broadcasting a wanted SSID."""
        ssid = self.bssid_ssid.get(bssid)
        if not ssid or not self.want(ssid):
            return
        with self.lock:
            w = self.writers.get(ssid)
            if w is None:
                from scapy.utils import PcapWriter
                try:
                    w = self.writers[ssid] = PcapWriter(self._pcap_path(ssid), append=True, sync=True)
                except OSError:
                    log.warning("Could not open handshake capture file for %r", ssid, exc_info=True)
                    return
            try:
                w.write(pkt)
            except OSError:
                log.warning("Could not write handshake capture frame for %r", ssid, exc_info=True)
                return
            st = self.state.setdefault(ssid, {"bssids": set(), "pairs": {}, "frames": 0, "bytes": 0,
                                               "started": time.time(), "updated": None})
            st["bssids"].add(bssid)
            st["pairs"].setdefault((bssid, sta), set()).add(msg)
            st["frames"] += 1
            st["bytes"] += len(pkt)
            st["updated"] = time.time()
            self._save_state(ssid)

    def _close(self, ssid):
        w = self.writers.pop(ssid, None)
        if w:
            try:
                w.close()
            except OSError:
                pass

    # -------------------------------------------------------------- admin API
    def status(self):
        mine = self.ctx.settings.get("networks")["ssids"]
        on = set(self.ctx.settings.get("handshake")["ssids"])
        out = []
        for ssid in mine:
            st = self.state.get(ssid) or {}
            pairs = st.get("pairs", {})
            # "usable" needs message 2 (the client's MIC'd nonce) paired with message 1 or 3 from the AP.
            usable = sum(1 for msgs in pairs.values() if 2 in msgs and (1 in msgs or 3 in msgs))
            path = self._pcap_path(ssid)
            out.append({"ssid": ssid, "enabled": ssid in on, "bssids": sorted(st.get("bssids", [])),
                       "pairs": len(pairs), "usable_pairs": usable, "frames": st.get("frames", 0),
                       "bytes": os.path.getsize(path) if os.path.exists(path) else 0,
                       "started": st.get("started"), "updated": st.get("updated"),
                       "downloadable": os.path.exists(path)})
        return out

    def enable(self, ssid, on):
        mine = self.ctx.settings.get("networks")["ssids"]
        if ssid not in mine:
            raise ValueError(f'"{ssid}" is not in My networks — add it there first')
        cur = set(self.ctx.settings.get("handshake")["ssids"])
        if on:
            cur.add(ssid)
        else:
            cur.discard(ssid)
        self.ctx.settings.set("handshake", {"ssids": sorted(cur)})  # on_change -> _refresh() opens/closes writers

    def clear(self, ssid):
        self._close(ssid)
        with self.lock:
            self.state.pop(ssid, None)
        for p in (self._pcap_path(ssid), self._meta_path(ssid)):
            if os.path.exists(p):
                os.remove(p)

    def pcap_path(self, ssid):
        """The capture file for an SSID that's currently in My networks, or None if there isn't one."""
        if ssid not in self.ctx.settings.get("networks")["ssids"]:
            return None
        p = self._pcap_path(ssid)
        return p if os.path.exists(p) else None


# ------------------------------------------------------------------ web API
def routes(ctx):
    from fastapi import APIRouter, Depends, HTTPException
    from fastapi.responses import FileResponse
    from pydantic import BaseModel

    from .auth import require_admin
    from .sanitize import clean_str

    class Toggle(BaseModel):
        enabled: bool

    r = APIRouter()

    @r.get("/api/handshakes")
    def list_handshakes(_=Depends(require_admin)):
        return {"items": ctx.handshake.status()}

    @r.put("/api/handshakes/{ssid}")
    def set_handshake(ssid: str, body: Toggle, _=Depends(require_admin)):
        ssid = clean_str(ssid, 64)
        if not ssid:
            raise HTTPException(400, "invalid SSID")
        try:
            ctx.handshake.enable(ssid, body.enabled)
        except ValueError as e:
            raise HTTPException(400, str(e))
        return {"ok": True}

    @r.get("/api/handshakes/{ssid}/capture.pcap")
    def download_handshake(ssid: str, _=Depends(require_admin)):
        ssid = clean_str(ssid, 64)
        path = ctx.handshake.pcap_path(ssid or "")
        if not path:
            raise HTTPException(404, "no capture for this network")
        return FileResponse(path, media_type="application/vnd.tcpdump.pcap", filename="handshake.pcap")

    @r.delete("/api/handshakes/{ssid}")
    def delete_handshake(ssid: str, _=Depends(require_admin)):
        ssid = clean_str(ssid, 64)
        if ssid:
            ctx.handshake.clear(ssid)
        return {"ok": True}

    return r
