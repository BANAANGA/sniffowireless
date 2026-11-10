"""Privacy mode: never store a full, globally unique ("static") MAC address.

With this on, every static MAC address is replaced by a pseudonym *before* anything is stored:

    a4:83:e7:5c:21:0b  ->  a4:83:e7:<3 bytes of a keyed hash>

The vendor part (the first three bytes, which name the maker, not the person) stays, so vendor names, device types and the
"randomised" test keep working; the last three bytes, which are what make the address unique, are the first bytes of an
HMAC-SHA-256 under a secret key. The pseudonym is the same every time, so a device is still recognised when it comes back.
If two addresses would get the same pseudonym, the second is moved to the next free one (the table `mac_alias` remembers
that), so two devices are never merged.

Where it happens: Store.process() runs every observation (from local radios, remote sensors and the demo) through
MacHasher.scrub(), which also catches addresses inside text (event details, JSON). Addresses a person types in the web
interface are turned into the same pseudonyms before they reach a route or the settings table (MacInputMiddleware), so
"my networks", the ignore list and searches keep working. Log lines are scrubbed too.

What it does not do, so nobody is misled:
* The key lives in a file next to the database (or in PRIVACY_KEY), not in the database. A leaked database or backup
  cannot be reversed without it; whoever has both can recompute the address of any device they can guess, because only 24
  bits of an address are unknown to them once the vendor is known.
* Radios still hear real addresses, remote sensors still send them to the server (use HTTPS), and the server keeps the
  addresses of recently heard devices in memory for a few minutes so that actions that must reach a device (play a sound,
  read its version) still work. Nothing of that is written to disk.
* Randomised addresses are not "static" and are left alone unless the scope is "all".
* Captured WPA handshakes contain real addresses, so capturing them is switched off in this mode.
"""
import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from urllib.parse import parse_qsl, quote, urlencode

from .anonymize import RUN_RE

log = logging.getLogger("sniffowireless.macprivacy")

SCOPES = ("static", "all")
KEY_FILE = "privacy.key"
MAX_CACHE = 300_000
RECENT_TTL = 15 * 60       # how long the real address of a heard device is kept in memory only
RECENT_MAX = 100_000
SKIP_TABLES = {"users", "auth_sessions", "api_tokens", "meta", "mac_alias"}   # not about devices
SKIP_PATHS = ("/api/ingest", "/api/backup/", "/api/privacy")
JSON_BODY_LIMIT = 8 * 1024 * 1024
CHUNK = 100_000

_active = {"hasher": None}


def current():
    return _active["hasher"]


def is_active():
    return _active["hasher"] is not None


def set_current(h):
    _active["hasher"] = h


def is_pseudonym(mac):
    h = _active["hasher"]
    return bool(h) and h.is_pseudonym(mac)


def resolve(mac):
    """The real address behind a pseudonym, if that device was heard in the last minutes (memory only); else `mac`."""
    h = _active["hasher"]
    return h.real(mac) if h else mac


def load_key(data_dir, env_key=""):
    """The secret key: PRIVACY_KEY if set, else the key file in the data directory (created with mode 0600)."""
    if env_key:
        return hashlib.sha256(env_key.encode()).digest()
    path = os.path.join(data_dir, KEY_FILE)
    try:
        with open(path, "r", encoding="ascii") as f:
            k = f.read().strip()
        if len(k) >= 32:
            return bytes.fromhex(k)
    except (OSError, ValueError):
        pass
    k = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(k.hex() + "\n")
    log.info("Created the privacy key %s (keep it out of backups and away from the database)", path)
    return k


def key_source(data_dir, env_key=""):
    return "PRIVACY_KEY" if env_key else os.path.join(data_dir, KEY_FILE)


def _parse(mac):
    """6 bytes of a MAC written with colons, or None."""
    p = mac.split(":")
    if len(p) != 6 or any(len(x) != 2 for x in p):
        return None
    try:
        return bytes(int(x, 16) for x in p)
    except ValueError:
        return None


def find_macs(s):
    """[(start, end, mac)] for the MAC addresses in a text. A run of colon-separated byte pairs is a MAC address when it has exactly
    six; a seventh pair directly after a letter ("nowpa3:aa:bb:cc:dd:ee:ff") is the end of a word, not part of the address."""
    out = []
    for m in RUN_RE.finditer(s):
        pairs = m.group().split(":")
        if len(pairs) == 6:
            out.append((m.start(), m.end(), m.group()))
        elif len(pairs) == 7 and m.start() > 0 and s[m.start() - 1].isalpha():
            out.append((m.start() + 3, m.end(), ":".join(pairs[1:])))
    return out


def replace_macs(s, fn):
    spans = find_macs(s)
    if not spans:
        return s
    out, last = [], 0
    for a, b, mac in spans:
        out.append(s[last:a])
        out.append(fn(mac))
        last = b
    out.append(s[last:])
    return "".join(out)


class MacHasher:
    def __init__(self, conn, key, scope="static"):
        """conn: a connection of its own to the database (used from several threads, under a lock)."""
        self.conn, self.key = conn, key
        self.scope = scope if scope in SCOPES else "static"
        self.lock = threading.Lock()
        self.cache = {}       # real mac -> pseudonym
        self.known = set()    # pseudonyms seen to exist in mac_alias
        self.recent = {}      # pseudonym -> (real mac, when): memory only
        conn.execute("CREATE TABLE IF NOT EXISTS mac_alias(pseud TEXT PRIMARY KEY, digest BLOB NOT NULL UNIQUE)")

    # ------------------------------------------------------------------ addresses
    def should_hash(self, raw):
        return not raw[0] & 1 and (self.scope == "all" or not raw[0] & 2)

    def pseudonym(self, mac):
        """The pseudonym of an address (allocated on first use); addresses that are not hashed come back unchanged."""
        m = mac.lower()
        hit = self.cache.get(m)
        if hit is not None:
            self._remember(hit, m)
            return hit
        raw = _parse(m)
        if raw is None or not self.should_hash(raw):
            return mac
        d = hmac.new(self.key, raw, hashlib.sha256).digest()
        digest, base = d[:16], int.from_bytes(d[16:19], "big")
        with self.lock:
            row = self.conn.execute("SELECT pseud FROM mac_alias WHERE digest=?", (digest,)).fetchone()
            if row:
                p = row[0]
            else:
                p = None
                for k in range(1 << 24):
                    cand = raw[:3].hex(":", 1) + ":" + ((base + k) & 0xFFFFFF).to_bytes(3, "big").hex(":", 1)
                    try:
                        self.conn.execute("INSERT INTO mac_alias(pseud, digest) VALUES(?,?)", (cand, digest))
                        p = cand
                        break
                    except sqlite3.IntegrityError:
                        again = self.conn.execute("SELECT pseud FROM mac_alias WHERE digest=?", (digest,)).fetchone()
                        if again:  # another thread stored it first
                            p = again[0]
                            break
                if p is None:
                    raise RuntimeError("no free pseudonym for this vendor")
        if len(self.cache) > MAX_CACHE:
            self.cache.clear()
        self.cache[m] = p
        self.known.add(p)
        self._remember(p, m)
        return p

    def is_pseudonym(self, mac):
        m = mac.lower()
        if m in self.known:
            return True
        with self.lock:
            row = self.conn.execute("SELECT 1 FROM mac_alias WHERE pseud=?", (m,)).fetchone()
        if row:
            self.known.add(m)
        return bool(row)

    def _remember(self, pseud, real):
        now = time.time()
        if len(self.recent) > RECENT_MAX:
            self.recent = {k: v for k, v in self.recent.items() if now - v[1] < RECENT_TTL}
        self.recent[pseud] = (real, now)

    def real(self, pseud):
        """Real address of a device heard in the last RECENT_TTL seconds (never written anywhere), else `pseud`."""
        v = self.recent.get(pseud.lower())
        return v[0] if v and time.time() - v[1] < RECENT_TTL else pseud

    # ------------------------------------------------------------------ text and structures
    def scrub_text(self, s, idempotent=False):
        """Replace every MAC address in `s`. idempotent: leave addresses that already are pseudonyms (input from the
        interface, which shows pseudonyms); observations are always real, so they are not asked."""
        if ":" not in s:
            return s
        return replace_macs(s, lambda mac: mac if idempotent and self.is_pseudonym(mac) else self.pseudonym(mac))

    def scrub(self, o, idempotent=False):
        """A copy of a JSON-like structure with every MAC address (also as a dictionary key) replaced."""
        if isinstance(o, str):
            return self.scrub_text(o, idempotent)
        if isinstance(o, dict):
            return {(self.scrub_text(k, idempotent) if isinstance(k, str) else k): self.scrub(v, idempotent) for k, v in o.items()}
        if isinstance(o, (list, tuple)):
            return [self.scrub(v, idempotent) for v in o]
        return o

    # ------------------------------------------------------------------ what is stored
    def count(self):
        with self.lock:
            return self.conn.execute("SELECT COUNT(*) FROM mac_alias").fetchone()[0]

    def migrate_existing(self, conn, progress=None):
        """Replace the real addresses already in the database (all text columns of all tables but the account ones), then
        remove the old values from the file (secure_delete + VACUUM). `conn` must be the only connection in use.

        Two phases, because the hasher writes its table over its own connection and must not wait for a write lock that
        this one holds: first every address found is given its pseudonym, then the rewrite only looks them up in memory."""
        log.info("Privacy: replacing the MAC addresses already stored (this can take a while on a big database)")
        conn.execute("PRAGMA secure_delete=ON")
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        targets = []   # (table, column, first rowid, last rowid); rowids None: a WITHOUT ROWID table, done in one statement
        for t in tables:
            if t in SKIP_TABLES:
                continue
            try:
                lo, hi = conn.execute(f'SELECT MIN(rowid), MAX(rowid) FROM "{t}"').fetchone()
            except sqlite3.OperationalError:  # a table without a rowid
                if not conn.execute(f'SELECT 1 FROM "{t}" LIMIT 1').fetchone():
                    continue
                lo = hi = None
            else:
                if lo is None:
                    continue
            for r in conn.execute(f'PRAGMA table_info("{t}")'):
                if (r[2] or "").upper() in ("", "TEXT", "JSON"):
                    targets.append((t, r[1], lo, hi))
        like = "LIKE '%:%:%:%:%:%'"
        mapping = {}
        def scan(v):
            if not isinstance(v, str):
                return
            for _a, _b, run in find_macs(v):
                low = run.lower()
                if low not in mapping and not self.is_pseudonym(low):
                    p = self.pseudonym(low)
                    if p != low:
                        mapping[low] = p
        for t, c, lo, hi in targets:                                      # phase 1: who is in there
            if lo is None:
                for (v,) in conn.execute(f'SELECT DISTINCT "{c}" FROM "{t}" WHERE "{c}" {like}').fetchall():
                    scan(v)
                continue
            for a in range(lo, hi + 1, CHUNK):
                for (v,) in conn.execute(f'SELECT "{c}" FROM "{t}" WHERE rowid BETWEEN ? AND ? AND "{c}" {like}', (a, a + CHUNK - 1)).fetchall():
                    scan(v)

        def swap(s):
            return replace_macs(s, lambda mac: mapping.get(mac.lower(), mac)) if isinstance(s, str) and ":" in s else s
        conn.create_function("pseud_text", 1, swap)
        changed = 0
        for t, c, lo, hi in targets:                                      # phase 2: rewrite, from memory only
            if lo is None:
                cur = conn.execute(f'UPDATE OR REPLACE "{t}" SET "{c}"=pseud_text("{c}") WHERE "{c}" {like}')
                changed += max(cur.rowcount, 0)
            else:
                for a in range(lo, hi + 1, CHUNK):
                    cur = conn.execute(f'UPDATE OR REPLACE "{t}" SET "{c}"=pseud_text("{c}") WHERE rowid BETWEEN ? AND ? AND "{c}" {like}',
                                       (a, a + CHUNK - 1))
                    changed += max(cur.rowcount, 0)
            if progress:
                progress(t, c)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("VACUUM")
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        log.info("Privacy: %d addresses replaced in %d stored values; the database file was compacted so the old values are gone",
                 len(mapping), changed)
        return changed


# ---------------------------------------------------------------------- web requests
class MacInputMiddleware:
    """Pure ASGI, innermost (after the anonymised view has turned its display pseudonyms back): an address typed into the
    interface, a URL or a form becomes the stored pseudonym before it reaches a route or the settings table. Addresses that
    already are pseudonyms (everything the interface itself shows) are left alone."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        h = _active["hasher"]
        path = scope.get("path", "")
        if scope["type"] != "http" or h is None or not path.startswith("/api/") or path.startswith(SKIP_PATHS):
            return await self.app(scope, receive, send)
        scope = dict(scope)
        new_path = h.scrub_text(path, True)
        if new_path != path:
            scope["path"] = new_path
            scope["raw_path"] = quote(new_path, safe="/:@!$&'()*+,;=-._~").encode()
        qs = scope.get("query_string", b"").decode("latin-1")
        if qs:
            scope["query_string"] = urlencode([(k, h.scrub_text(v, True)) for k, v in parse_qsl(qs, keep_blank_values=True)]).encode()
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
                new = json.dumps(await asyncio.to_thread(lambda: h.scrub(json.loads(body), True))).encode() if body else body
            except ValueError:
                new = body
            scope["headers"] = [(k, (str(len(new)).encode() if k.lower() == b"content-length" else v)) for k, v in scope["headers"]]
            sent = False

            async def receive():  # noqa: F811 - replaces the original
                nonlocal sent
                if sent:
                    return {"type": "http.disconnect"}
                sent = True
                return {"type": "http.request", "body": new, "more_body": False}
        await self.app(scope, receive, send)


# ---------------------------------------------------------------------- logs
class LogScrubber(logging.Filter):
    """Replaces MAC addresses in log lines (those that are already pseudonyms stay) while privacy mode is on."""

    def filter(self, record):
        h = _active["hasher"]
        if h is not None:
            try:
                msg = record.getMessage()
                if ":" in msg:
                    record.msg, record.args = h.scrub_text(msg, True), ()
            except Exception:  # a log line must never fail because of this
                pass
        return True


def install_log_filter():
    f = LogScrubber()
    for handler in logging.getLogger().handlers:
        if not any(isinstance(x, LogScrubber) for x in handler.filters):
            handler.addFilter(f)
