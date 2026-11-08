"""Anonymised view: with an admin setting on, MAC addresses and/or SSIDs are replaced by stable pseudonyms in everything
the web interface and the API show, for every user. Display only: the database keeps the real values, the capture and the
sensors are untouched, and switching the setting off brings the real values back.

How: a middleware masks API responses (JSON, CSV, the log stream, Prometheus labels) and, the other way round, replaces
pseudonyms in incoming requests (path, query, JSON body) by the real values, so a link or a form built from a masked
page still finds the right record. Pseudonyms are keyed hashes (a random secret kept in the settings), so they are the
same on every request and after a restart, and the reverse map can always be rebuilt from the database.

  MAC  aa:bb:cc:dd:ee:ff -> aa:bb:cc:<3 bytes of the hash>   the vendor part stays, so vendors and "randomized" still make sense
  SSID HomeNet           -> Network-1a2b3c

Multicast and broadcast addresses are not masked (they name a protocol, not a device). Sensors' uploads (/api/ingest) are
never touched. Notifications sent out, backups and the database itself are real.
"""
import asyncio
import csv
import hashlib
import hmac
import io
import json
import re
import secrets
import threading
import time
from urllib.parse import parse_qsl, quote, urlencode

# A run of colon separated byte pairs: exactly six is a MAC address (an 8 byte Zigbee address is not one). Text around it may
# use colons too ("BSSID aa:bb:cc:dd:ee:ff: locally administered", "rogue:aa:bb:..."), so the run is found first and then judged.
RUN_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})+(?![0-9A-Fa-f])")
MAC_RE = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f:])")  # a whole string / token that is one MAC
PSEUDO_SSID_RE = re.compile(r"Network-[0-9a-f]{6}")
FREE_TEXT = {"detail", "title", "body", "message", "text", "summary", "evidence", "source"}   # keys whose text may mention a known SSID
SSID_MAPS = {"ssid_time"}   # dictionaries keyed by SSID (a "series" dictionary is keyed by SSID in one place and by kind in another)
MAX_MAP = 300_000
SKIP = ("/api/ingest", "/api/privacy")
JSON_BODY_LIMIT = 8 * 1024 * 1024
REBUILD_EVERY = 20  # seconds between rebuilds of the reverse map after a pseudonym is not found


def active_settings(ctx):
    p = ctx.settings.get("privacy") if ctx.settings else {}
    return bool(p.get("macs")), bool(p.get("ssids"))


class Anonymizer:
    def __init__(self, ctx):
        self.ctx = ctx
        self.lock = threading.Lock()
        self.fwd, self.rev = {}, {}
        self.known_re, self.known_at = None, 0
        self.rebuilt_at = 0

    # -------------------------------------------------------------- pseudonyms
    def _key(self):
        p = self.ctx.settings.get("privacy")
        if not p.get("secret"):
            p["secret"] = secrets.token_hex(16)
            self.ctx.settings.set("privacy", p)
        return bytes.fromhex(p["secret"])

    def _digest(self, kind, real, n=0):
        return hmac.new(self._key(), f"{kind}:{n}:{real}".encode(), hashlib.sha256).digest()

    def _remember(self, kind, real, pseudo):
        with self.lock:
            if len(self.fwd) > MAX_MAP:
                self.fwd.clear()
                self.rev.clear()
            self.fwd[(kind, real)] = pseudo
            self.rev[pseudo] = real

    def mac(self, real):
        low = real.lower()
        if int(low[:2], 16) & 1:  # multicast / broadcast
            return real
        got = self.fwd.get(("m", low))
        if got:
            return got
        for n in range(8):  # a clash of two MACs with the same vendor part is possible but rare: rehash
            h = self._digest("mac", low, n)
            pseudo = low[:8] + ":" + ":".join(f"{b:02x}" for b in h[:3])
            if self.rev.get(pseudo, low) == low:
                break
        self._remember("m", low, pseudo)
        return pseudo

    def ssid(self, real):
        if not real:
            return real
        got = self.fwd.get(("s", real))
        if got:
            return got
        n = 0
        while True:
            pseudo = "Network-" + self._digest("ssid", real, n)[:3].hex()
            if self.rev.get(pseudo, real) == real:
                break
            n += 1
        self._remember("s", real, pseudo)
        return pseudo

    # -------------------------------------------------------------- what SSIDs exist (for text that mentions them)
    def known_ssids(self):
        now = time.time()
        if self.known_re is not None and now - self.known_at < 60:
            return self.known_re
        found = set()
        try:
            for sql in ("SELECT DISTINCT ssid FROM devices WHERE ssid IS NOT NULL AND ssid != '' LIMIT 5000",
                        "SELECT DISTINCT ssid FROM probes WHERE ssid IS NOT NULL AND ssid != '' LIMIT 5000"):
                found.update(r["ssid"] for r in self.ctx.rows(sql))
        except Exception:
            pass
        s = self.ctx.settings
        for key in ("networks", "investigate", "ignore", "handshake"):
            for x in (s.get(key) or {}).get("ssids") or []:
                found.add(x["ssid"] if isinstance(x, dict) else x)
        names = sorted((x for x in found if isinstance(x, str) and len(x) >= 3), key=len, reverse=True)[:6000]
        self.known_re = re.compile(r"(?<!\w)(?:" + "|".join(re.escape(x) for x in names) + r")(?!\w)") if names else False
        self.known_at = now
        return self.known_re

    def rebuild(self):
        """Pseudonyms of everything stored, so a pseudonym seen before a restart still maps back."""
        if time.time() - self.rebuilt_at < REBUILD_EVERY:
            return
        self.rebuilt_at = time.time()
        macs, ssids = active_settings(self.ctx)
        try:
            if macs:
                for r in self.ctx.rows("SELECT mac FROM devices"):
                    if MAC_RE.fullmatch(r["mac"] or ""):
                        self.mac(r["mac"])
            if ssids:
                self.known_at = 0
                for x in (self.ctx.rows("SELECT DISTINCT ssid FROM devices WHERE ssid IS NOT NULL AND ssid != '' LIMIT 20000")
                          + self.ctx.rows("SELECT DISTINCT ssid FROM probes WHERE ssid IS NOT NULL AND ssid != '' LIMIT 20000")):
                    self.ssid(x["ssid"])
        except Exception:
            pass

    def sub_macs(self, s):
        """Replace the MAC addresses in a text (see RUN_RE for what counts as one)."""
        def one(m):
            pairs = m.group().split(":")
            if len(pairs) == 6:
                return self.mac(m.group())
            if len(pairs) == 7 and m.start() > 0 and s[m.start() - 1].isalpha():  # "nowpa3:aa:bb:cc:dd:ee:ff": the first pair ends a word
                return pairs[0] + ":" + self.mac(":".join(pairs[1:]))
            return m.group()
        return RUN_RE.sub(one, s)

    # -------------------------------------------------------------- masking (responses)
    def mask_str(self, s, key, macs, ssids, all_text=False):
        if ssids and s:
            if key == "ssid" or key.endswith("_ssid") or key == "ssids":
                return self.ssid(s)
            if s.startswith("ssid:"):
                return "ssid:" + self.ssid(s[5:])
            if all_text or key in FREE_TEXT:
                s = self._text_ssids(s)
        if macs:
            s = self.sub_macs(s)
        return s

    def _text_ssids(self, s):
        rx = self.known_ssids()
        s = re.sub(r"(?<=ssid:)[^\s,;)]+", lambda m: self.ssid(m.group()), s)
        return rx.sub(lambda m: self.ssid(m.group()), s) if rx else s

    def mask_json(self, o, macs, ssids, key="", all_text=False):
        if isinstance(o, dict):
            out = {}
            for k, v in o.items():
                nk = k
                if isinstance(k, str):
                    if macs and MAC_RE.fullmatch(k):
                        nk = self.mac(k)
                    elif ssids and (key in SSID_MAPS or (key == "series" and self._is_known(k))):
                        nk = self.ssid(k)
                out[nk] = self.mask_json(v, macs, ssids, k if isinstance(k, str) else "", all_text)
            return out
        if isinstance(o, list):
            return [self.mask_json(v, macs, ssids, key, all_text) for v in o]
        if isinstance(o, str):
            return self.mask_str(o, key, macs, ssids, all_text)
        return o

    def _is_known(self, name):
        rx = self.known_ssids()
        return bool(rx and rx.fullmatch(name))

    def mask_text(self, text, macs, ssids):
        if ssids:
            text = self._text_ssids(text)
        return self.sub_macs(text) if macs else text

    def mask_csv(self, text, macs, ssids):
        rows = list(csv.reader(io.StringIO(text)))
        if not rows:
            return text
        ssid_cols = {i for i, h in enumerate(rows[0]) if h == "ssid" or h.endswith("_ssid")}
        out = io.StringIO()
        w = csv.writer(out)
        for n, row in enumerate(rows):
            w.writerow(row if n == 0 else [self.ssid(c) if ssids and i in ssid_cols and c else
                                           (self.sub_macs(c) if macs else c) for i, c in enumerate(row)])
        return out.getvalue()

    def mask_metrics(self, text, macs, ssids):
        if ssids:
            text = re.sub(r'(ssid=")([^"]*)(")', lambda m: m.group(1) + self.ssid(m.group(2)) + m.group(3), text)
        return self.sub_macs(text) if macs else text

    # -------------------------------------------------------------- unmasking (requests)
    def unmask_str(self, s, macs, ssids):
        def one(m):
            word = m.group().lower() if MAC_RE.fullmatch(m.group()) else m.group()
            real = self.rev.get(word)
            if real is None:
                self.rebuild()
                real = self.rev.get(word)
            return m.group() if real is None else real
        if macs:
            def run(m):
                pairs = m.group().split(":")
                if len(pairs) == 6:
                    return one(m)
                if len(pairs) == 7 and m.start() > 0 and s[m.start() - 1].isalpha():
                    tail = re.match(r".*", ":".join(pairs[1:]))
                    mm = re.fullmatch(MAC_RE, tail.group())
                    return pairs[0] + ":" + (one(mm) if mm else tail.group())
                return m.group()
            s = RUN_RE.sub(run, s)
        if ssids:
            s = PSEUDO_SSID_RE.sub(one, s)
        return s

    def unmask_json(self, o, macs, ssids):
        if isinstance(o, dict):
            return {self.unmask_str(k, macs, ssids) if isinstance(k, str) else k: self.unmask_json(v, macs, ssids) for k, v in o.items()}
        if isinstance(o, list):
            return [self.unmask_json(v, macs, ssids) for v in o]
        return self.unmask_str(o, macs, ssids) if isinstance(o, str) else o


# ------------------------------------------------------------------------------------------------ the middleware
class AnonymizeMiddleware:
    """Pure ASGI, innermost: it sees plain (not compressed) bodies and runs before the routes and after the auth checks."""

    def __init__(self, app, ctx):
        self.app = app
        self.ctx = ctx
        self.a = Anonymizer(ctx)

    def applies(self, path):
        return (path.startswith("/api/") or path == "/metrics") and not path.startswith(SKIP)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self.applies(scope["path"]):
            return await self.app(scope, receive, send)
        macs, ssids = active_settings(self.ctx)
        if not (macs or ssids):
            return await self.app(scope, receive, send)
        a = self.a
        scope = dict(scope)
        # --- the request: pseudonyms back to the real values
        path = a.unmask_str(scope["path"], macs, ssids)
        if path != scope["path"]:
            scope["path"] = path
            scope["raw_path"] = quote(path, safe="/:@!$&'()*+,;=-._~").encode()
        qs = scope.get("query_string", b"").decode("latin-1")
        if qs:
            pairs = [(k, a.unmask_str(v, macs, ssids)) for k, v in parse_qsl(qs, keep_blank_values=True)]
            scope["query_string"] = urlencode(pairs).encode()
        headers = dict((k.lower(), v) for k, v in scope["headers"])
        if scope["method"] in ("POST", "PUT", "PATCH", "DELETE") and headers.get(b"content-type", b"").startswith(b"application/json"):
            body, more = b"", True
            while more:
                msg = await receive()
                body += msg.get("body", b"")
                more = msg.get("more_body", False)
                if len(body) > JSON_BODY_LIMIT:
                    raise ValueError("request body too large")
            try:
                new = json.dumps(await asyncio.to_thread(lambda: a.unmask_json(json.loads(body), macs, ssids))).encode() if body else body
            except ValueError:
                new = body  # not JSON after all: the route reports it
            scope["headers"] = [(k, (str(len(new)).encode() if k.lower() == b"content-length" else v)) for k, v in scope["headers"]]
            sent = False

            async def receive():  # noqa: F811 - replaces the original
                nonlocal sent
                if sent:
                    return {"type": "http.disconnect"}
                sent = True
                return {"type": "http.request", "body": new, "more_body": False}

        # --- the response: real values to pseudonyms
        start, chunks = None, []
        kind = None

        async def masked_send(msg):
            nonlocal start, kind
            if msg["type"] == "http.response.start":
                ctype = next((v for k, v in msg["headers"] if k.lower() == b"content-type"), b"").decode("latin-1").lower()
                kind = ("json" if ctype.startswith("application/json") else "csv" if ctype.startswith("text/csv") else
                        "sse" if ctype.startswith("text/event-stream") else "metrics" if scope["path"] == "/metrics" else None)
                if kind in ("json", "csv", "metrics"):
                    start = msg  # sent with the new length once the body is complete
                    return
                return await send(msg)
            if msg["type"] != "http.response.body" or kind is None:
                return await send(msg)
            if kind == "sse":
                text = msg.get("body", b"").decode("utf-8", "replace")
                return await send({**msg, "body": a.mask_text(text, macs, ssids).encode()})
            chunks.append(msg.get("body", b""))
            if msg.get("more_body"):
                return
            raw = b"".join(chunks)
            if kind == "json":
                def work():
                    try:
                        return json.dumps(a.mask_json(json.loads(raw), macs, ssids, all_text=scope["path"].startswith("/api/logs")),
                                          separators=(",", ":")).encode()
                    except ValueError:
                        return raw
            elif kind == "csv":
                def work():
                    return a.mask_csv(raw.decode("utf-8", "replace"), macs, ssids).encode()
            else:
                def work():
                    return a.mask_metrics(raw.decode("utf-8", "replace"), macs, ssids).encode()
            out = await asyncio.to_thread(work)
            hdrs = [(k, v) for k, v in start["headers"] if k.lower() != b"content-length"] + [(b"content-length", str(len(out)).encode())]
            await send({**start, "headers": hdrs})
            await send({"type": "http.response.body", "body": out})

        await self.app(scope, receive, masked_send)
