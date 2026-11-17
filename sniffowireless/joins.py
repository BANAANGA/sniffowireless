"""How clients join and roam: every step of a connection, as heard over the air, so the step that failed can be named.

The sensor picks out of what it hears, per client, the frames that make up a connection:

    authentication     request and response (Open, SAE commit / confirm, Fast BSS Transition), with the status code
    (re)association    request and response, with the status code; a reassociation request names the access point it comes from
    802.1X / EAP       EAPOL-Start, the EAP method, EAP-Success and EAP-Failure (enterprise networks)
    4-way handshake    EAPOL-Key messages 1 to 4 (the group key handshake is left out)
    disconnect         deauthentication and disassociation, from either side, with the reason code
    steering           802.11v BSS transition requests and responses, 802.11k neighbour report requests

These frames are sent before the keys are in place, so they are readable to anyone nearby; nothing secret is in them (the key
handshake messages carry nonces and a MIC, which are not stored). The server groups a client's steps into attempts: one
connection to one access point, from the first step to the end of the 4-way handshake (or to the failure). A successful attempt
on another access point of the same network soon after an earlier one is a roam, and its duration is the roam time.

A sensor that hops channels hears only part of a connection; one that stays on the channel of the access point hears all of it.
"""
import logging
import struct
import threading
import time

from fastapi import APIRouter, Depends, HTTPException

from .auth import current_user
from .dissect import AUTH_ALGOS, REASONS, STATUSES

log = logging.getLogger("sniffowireless.joins")

EAP_TYPES = {1: "Identity", 4: "MD5", 13: "EAP-TLS", 17: "LEAP", 18: "EAP-SIM", 21: "EAP-TTLS", 23: "EAP-AKA", 25: "PEAP", 26: "MSCHAPv2",
             43: "EAP-FAST", 50: "EAP-AKA'", 52: "EAP-pwd", 55: "TEAP"}
SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
FLOOD = 60            # steps per client and 10 seconds; more (a deauth flood) are dropped


def _mac(b):
    return ":".join(f"{x:02x}" for x in b)


def _radiotap(d):
    """(header length, signal or None) of the radiotap header in front of the frame."""
    if len(d) < 8 or d[0] != 0:
        return None, None
    length = int.from_bytes(d[2:4], "little")
    if length < 8 or length > len(d):
        return None, None
    present = int.from_bytes(d[4:8], "little")
    at = 8
    w = present
    while w & 0x80000000 and at + 4 <= length:   # more present words
        w = int.from_bytes(d[at:at + 4], "little")
        at += 4
    rssi = None
    if present & 0x20:   # antenna signal: after TSFT (8, aligned 8), flags (1), rate (1), channel (2+2, aligned 2), FHSS (2)
        p = at
        if present & 0x01:
            p = (p + 7) // 8 * 8 + 8
        p += (1 if present & 0x02 else 0) + (1 if present & 0x04 else 0)
        if present & 0x08:
            p = (p + 1) // 2 * 2 + 4
        if present & 0x10:
            p += 2
        if p < length:
            v = d[p]
            rssi = v - 256 if v > 127 else v
    return length, rssi


def steps(raw):
    """The connection steps in one captured frame (radiotap header included): a list of dicts with mac (the client), bssid,
    step, and code / algo / seq / detail where they apply. Empty for every other frame."""
    o, rssi = _radiotap(raw)
    if o is None or len(raw) < o + 24:
        return []
    fc0, fc1 = raw[o], raw[o + 1]
    ftype, sub = fc0 >> 2 & 3, fc0 >> 4
    a1, a2, a3 = raw[o + 4:o + 10], raw[o + 10:o + 16], raw[o + 16:o + 22]
    body = raw[o + 24:]
    if raw[o:o + 24] and fc1 & 0x40 and ftype == 0 and sub != 13:   # a protected management frame: nothing readable
        return []
    from_ap = a2 == a3
    client, bssid = (a1, a2) if from_ap else (a2, a1)
    if client[0] & 1:
        return []
    base = {"mac": _mac(client), "bssid": _mac(bssid), "from_ap": from_ap, "rssi": rssi if not from_ap else None}
    out = []
    try:
        if ftype == 0:
            if sub == 11 and len(body) >= 6:   # authentication
                algo, seq, status = struct.unpack("<HHH", body[:6])
                out.append({**base, "step": "auth", "algo": algo, "seq": seq, "code": status})
            elif sub in (0, 2):                # (re)association request
                s = {**base, "step": "assoc" if sub == 0 else "reassoc"}
                if sub == 2 and len(body) >= 10:
                    s["detail"] = _mac(body[4:10])   # the access point it comes from
                out.append(s)
            elif sub in (1, 3) and len(body) >= 4:   # (re)association response
                out.append({**base, "step": "assoc_resp" if sub == 1 else "reassoc_resp", "code": struct.unpack("<H", body[2:4])[0]})
            elif sub in (10, 12) and len(body) >= 2:   # disassociation / deauthentication
                out.append({**base, "step": "deauth" if sub == 12 else "disassoc", "code": struct.unpack("<H", body[:2])[0]})
            elif sub == 13 and len(body) >= 2 and not fc1 & 0x40:   # action
                cat, act = body[0], body[1]
                if cat == 10 and act in (7, 8):    # WNM: BSS transition management request / response
                    s = {**base, "step": "btm_req" if act == 7 else "btm_resp"}
                    if act == 8 and len(body) >= 4:
                        s["code"] = body[3]
                        if body[3] == 0 and len(body) >= 11:
                            s["detail"] = _mac(body[5:11])   # the access point it will move to
                    out.append(s)
                elif cat == 5 and act in (4, 5):   # radio measurement: neighbour report request / response
                    out.append({**base, "step": "nr_req" if act == 4 else "nr_resp"})
        elif ftype == 2 and not fc1 & 0x40:
            ds = fc1 & 3
            if ds not in (1, 2):
                return []
            hdr = 24 + (2 if sub & 8 else 0) + (4 if sub & 8 and fc1 & 0x80 else 0)
            p = raw[o + hdr:]
            if p[:8] != SNAP_EAPOL or len(p) < 12:
                return []
            client, bssid = (a2, a1) if ds == 1 else (a1, a2)
            base.update(mac=_mac(client), bssid=_mac(bssid), from_ap=ds == 2, rssi=rssi if ds == 1 else None)
            etype = p[9]
            e = p[12:]
            if etype == 1:
                out.append({**base, "step": "eapol_start"})
            elif etype == 0 and len(e) >= 4:   # EAP packet
                code = e[0]
                if code in (3, 4):
                    out.append({**base, "step": "eap_success" if code == 3 else "eap_failure"})
                elif code in (1, 2) and len(e) >= 5:
                    t = e[4]
                    out.append({**base, "step": "eap", "code": t, "detail": EAP_TYPES.get(t, f"type {t}")})
            elif etype == 3 and len(e) >= 3:   # EAPOL-Key
                ki = e[1] << 8 | e[2]
                if not ki & 0x08:   # group key handshake
                    return []
                ack, mic, secure, install = bool(ki & 0x80), bool(ki & 0x100), bool(ki & 0x200), bool(ki & 0x40)
                n = 1 if ack and not mic else 3 if ack and mic and install else 2 if mic and not secure else 4 if mic and secure else None
                if n:
                    out.append({**base, "step": f"m{n}"})
    except (struct.error, IndexError):
        return []
    return out


class JoinWatcher:
    """The sensor side: the steps of every frame, at most FLOOD per client and 10 seconds."""

    def __init__(self):
        self.lock = threading.Lock()
        self.counts, self.window = {}, 0

    def feed(self, raw, ts):
        found = steps(raw)
        if not found:
            return []
        w = int(ts // 10)
        out = []
        with self.lock:
            if w != self.window:
                self.counts, self.window = {}, w
            for s in found:
                n = self.counts.get(s["mac"], 0)
                if n >= FLOOD:
                    continue
                self.counts[s["mac"]] = n + 1
                out.append({"t": "join", "ts": ts, **s})
        return out


# ------------------------------------------------------------------ the server
SCHEMA = """
CREATE TABLE IF NOT EXISTS join_events(
  ts REAL NOT NULL, mac TEXT NOT NULL, bssid TEXT, step TEXT NOT NULL, code INTEGER, algo INTEGER, seq INTEGER, detail TEXT,
  from_ap INTEGER, rssi INTEGER, sensor TEXT);
CREATE INDEX IF NOT EXISTS idx_join_mac ON join_events(mac, ts);
CREATE INDEX IF NOT EXISTS idx_join_ts ON join_events(ts);
"""
STEPS = {"auth", "assoc", "reassoc", "assoc_resp", "reassoc_resp", "deauth", "disassoc", "btm_req", "btm_resp", "nr_req", "nr_resp",
         "eapol_start", "eap", "eap_success", "eap_failure", "m1", "m2", "m3", "m4"}
DUP_WINDOW = 0.25     # the same step heard by two sensors (or sent again at once) within this many seconds is kept once


class JoinCollector:
    """Store plugin: keeps every connection step (one row each; a step two sensors heard is kept once)."""

    def __init__(self, ctx):
        self.ctx = ctx
        ctx.store.conn.executescript(SCHEMA)
        self.pending, self.recent = [], {}
        self.attempt, self.last_ok, self.failed = {}, {}, {}
        self._mine_set, self._mine_at = None, 0.0

    def observe(self, store, o, dev):
        if o["t"] != "join":
            return
        key = (o["mac"], o.get("bssid"), o["step"], o.get("code"), o.get("seq"), o.get("from_ap"))
        last = self.recent.get(key)
        if last is not None and abs(o["ts"] - last) < DUP_WINDOW:
            return
        if len(self.recent) > 20000:
            self.recent.clear()
        self.recent[key] = o["ts"]
        try:
            self._events(store, o)
        except Exception:
            log.debug("Could not judge a connection step", exc_info=True)
        self.pending.append((o["ts"], o["mac"], o.get("bssid"), o["step"], o.get("code"), o.get("algo"), o.get("seq"), o.get("detail"),
                             1 if o.get("from_ap") else 0, o.get("rssi"), o.get("sensor") or "local"))

    def _mine(self):
        """My networks' BSSIDs (all access points when none are set), looked up at most once a minute."""
        now = time.time()
        if now - self._mine_at > 60:
            n = self.ctx.settings.get("networks")
            trusted = set(n["trusted_bssids"])
            self._mine_set = {r["mac"] for r in self.ctx.rows(f"SELECT mac FROM devices WHERE kind='ap' AND ssid IN ({','.join('?' * len(n['ssids']))})",
                                                               n["ssids"]) if not trusted or r["mac"] in trusted} if n["ssids"] else None
            self._mine_at = now
        return self._mine_set

    def _events(self, store, o):
        """Events while the steps arrive: a connection to my network that failed, and a slow roam on it (alerts and triggers.py
        act on them). The full picture is worked out when it is asked for (attempts())."""
        mac, bssid, st, code, ts = o["mac"], o.get("bssid"), o["step"], o.get("code"), o["ts"]
        mine = self._mine()
        if mine is not None and bssid not in mine:
            return
        a = self.attempt.get(mac)
        if st in ("auth", "assoc", "reassoc") and not o.get("from_ap") and (not a or a["bssid"] != bssid or ts - a["last"] > GAP or a["done"]):
            a = self.attempt[mac] = {"bssid": bssid, "start": ts, "last": ts, "reassoc": False, "ft": False, "done": False}
            if len(self.attempt) > 20000:
                self.attempt.clear()
        if a and a["bssid"] == bssid:
            a["last"] = ts
            a["reassoc"] |= st == "reassoc"
            a["ft"] |= st == "auth" and o.get("algo") == 2
        why = None
        if st in ("assoc_resp", "reassoc_resp", "auth") and o.get("from_ap") and code:
            why = f"{'authentication' if st == 'auth' else 'association'} refused: {STATUSES.get(code, f'status {code}')}"
        elif st == "eap_failure":
            why = "802.1X login rejected"
        elif st in ("deauth", "disassoc") and code in (14, 15, 23) and a and not a["done"]:
            why = {15: "4-way handshake timed out (often a wrong password)", 23: "802.1X authentication failed", 14: "MIC failure"}[code]
        if why:
            if a:
                a["done"] = True
            if ts - self.failed.get(mac, 0) >= 300:   # one event per client per 5 minutes
                self.failed[mac] = ts
                store._event(ts, mac, "connection_failed", bssid, why, always=True)
            return
        ok = st == "m4" or (st == "reassoc_resp" and not code and a and a["ft"])
        if ok and a and not a["done"]:
            a["done"] = True
            prev = self.last_ok.get(mac)
            self.last_ok[mac] = (bssid, ts)
            ms = (ts - a["start"]) * 1000
            if prev and prev[0] != bssid and a["reassoc"] and ts - prev[1] <= ROAM_WITHIN and ms >= 150:
                store._event(ts, mac, "roam_slow", bssid, f"{ms:.0f} ms from {prev[0]} to {bssid}" + (" (802.11r)" if a["ft"] else ""), always=True)

    def flush(self, store, c):
        if self.pending:
            c.executemany("INSERT INTO join_events VALUES(?,?,?,?,?,?,?,?,?,?,?)", self.pending)
            self.pending = []

    def prune(self, store, c, cutoff):
        c.execute("DELETE FROM join_events WHERE ts < ?", (cutoff,))


# ------------------------------------------------------------------ attempts and roams
GAP = 15.0            # seconds without a step after which an unfinished attempt is over
ROAM_WITHIN = 3600    # a successful connection to another access point of the same network within this time is a roam
STATUS_CAUSE = {13: "Authentication method not offered", 15: "Wrong WEP key", 17: "Access point full", 30: "PMF: try again later",
                31: "PMF settings do not match", 43: "Key management not offered", 53: "Cached key rejected", 77: "Unknown SAE password identifier"}
REASON_CAUSE = {14: "MIC failure", 15: "4-way handshake timeout", 16: "Group key handshake timeout", 23: "802.1X login failed",
                34: "Too many frames lost"}
STATUS_HINTS = {
    1: "The access point refused without giving a reason.",
    12: "The access point refused for a reason of its own (often a MAC filter, a full client list or band steering).",
    13: "The client asked for an authentication method this network does not offer (for example WPA3 on a WPA2-only network).",
    15: "The shared-key (WEP) challenge failed: a wrong WEP key.",
    17: "The access point has as many clients as it takes.",
    30: "Refused for now, to be tried again later: management frame protection (PMF) is checking an earlier connection of this client.",
    31: "Management frame protection (PMF) settings do not match: the network requires PMF and the client does not do it, or the other way round.",
    40: "An element in the request was not accepted (often a driver or firmware problem on one side).",
    43: "The client asked for a key management method (WPA2, WPA3, 802.1X) this network does not offer.",
    53: "The cached key (PMKID) was not accepted; the client has to log in again in full.",
    72: "The access point is busy with SAE and asks for an anti-clogging token: under load, or a client retrying very often.",
    77: "The SAE password identifier is not known to the access point.",
}
REASON_HINTS = {
    2: "The access point no longer knows this client's authentication (it restarted, or the client was idle too long).",
    3: "The access point is leaving or restarting.",
    4: "The client was idle too long.",
    6: "A frame came from a client that had not authenticated: the access point lost track of it.",
    7: "A frame came from a client that was not associated: the access point lost track of it.",
    8: "The client is leaving (it roams away, switches network or turns Wi-Fi off).",
    14: "A message integrity (MIC) failure: a wrong key, or someone tampering.",
    15: "The 4-way handshake timed out: most often a wrong password, sometimes a client that is too far away.",
    16: "The group key handshake timed out.",
    17: "The client's security elements in the handshake differ from its association request (a downgrade attempt or a buggy driver).",
    23: "802.1X authentication failed: wrong user credentials, an untrusted or expired certificate, or a RADIUS policy.",
    34: "Too many frames were lost: the link is too poor.",
}


def _label(s):
    names = {"auth": "Authentication", "assoc": "Association request", "reassoc": "Reassociation request", "assoc_resp": "Association response",
             "reassoc_resp": "Reassociation response", "deauth": "Deauthentication", "disassoc": "Disassociation",
             "btm_req": "BSS transition request (802.11v)", "btm_resp": "BSS transition response (802.11v)", "nr_req": "Neighbour report request (802.11k)",
             "nr_resp": "Neighbour report (802.11k)", "eapol_start": "EAPOL-Start", "eap": "EAP", "eap_success": "EAP-Success", "eap_failure": "EAP-Failure",
             "m1": "4-way handshake 1/4", "m2": "4-way handshake 2/4", "m3": "4-way handshake 3/4", "m4": "4-way handshake 4/4"}
    t = names.get(s["step"], s["step"])
    if s["step"] == "auth":
        t += f" ({AUTH_ALGOS.get(s['algo'], s['algo'])}{', commit' if s['algo'] == 3 and s['seq'] == 1 else ', confirm' if s['algo'] == 3 and s['seq'] == 2 else ''})"
    elif s["step"] == "eap" and s.get("detail"):
        t += f" {s['detail']}"
    return t


def _ok(s):
    return s.get("code") in (None, 0)


class Attempt:
    def __init__(self, s):
        self.bssid, self.start, self.last = s["bssid"], s["ts"], s["ts"]
        self.steps, self.outcome, self.done_at, self.why, self.failed_at, self.cause = [], None, None, None, None, None
        self.method, self.came_from, self.steered = None, None, False

    def add(self, s):
        self.steps.append(s)
        self.last = s["ts"]
        st, code = s["step"], s.get("code")
        if st == "auth":
            self.method = self.method or {2: "FT", 3: "SAE"}.get(s["algo"], "Open" if s["algo"] == 0 else None)
            if s["from_ap"] and code:
                self.fail(s, f"Authentication refused: {STATUSES.get(code, f'status {code}')}.", STATUS_HINTS.get(code),
                          STATUS_CAUSE.get(code, f"Authentication refused ({code})"))
        elif st == "reassoc" and s.get("detail"):
            self.came_from = s["detail"]
        elif st in ("assoc_resp", "reassoc_resp"):
            if code:
                self.fail(s, f"{'Reassociation' if st == 'reassoc_resp' else 'Association'} refused: {STATUSES.get(code, f'status {code}')}.",
                          STATUS_HINTS.get(code), STATUS_CAUSE.get(code, f"Association refused ({code})"))
            elif self.method == "FT":   # Fast BSS Transition: the keys come with the reassociation, no 4-way handshake
                self.succeed(s)
        elif st in ("eap", "eapol_start") and self.method in (None, "Open"):
            self.method = "802.1X"
        elif st == "eap_failure":
            self.fail(s, "The 802.1X login was rejected (EAP-Failure).", REASON_HINTS[23], "802.1X login rejected")
        elif st == "m4":
            self.succeed(s)
        elif st in ("deauth", "disassoc"):
            pattern, cause = self.handshake_pattern()
            who = "The access point" if s["from_ap"] else "The client"
            reason = REASONS.get(code, f"reason {code}")
            self.fail(s, f"{who} ended it before it was complete: {reason}.", pattern or REASON_HINTS.get(code),
                      cause or REASON_CAUSE.get(code, f"Ended by the {'access point' if s['from_ap'] else 'client'} ({code})"))

    def handshake_pattern(self):
        """(explanation, cause) of what the 4-way handshake messages so far say about why it did not finish, or (None, None)."""
        seq = [s["step"] for s in self.steps if s["step"] in ("m1", "m2", "m3", "m4")]
        if not seq:
            return None, None
        if "m3" not in seq and seq.count("m2") >= 2:
            return ("Wrong password: the client answered message 1 again and again, but the access point never sent message 3. That is what "
                    "happens when the client's message 2 does not check out against the network's password.", "Wrong password")
        if "m2" not in seq and seq.count("m1") >= 2:
            return "The client never answered message 1 of the 4-way handshake (out of range, or its supplicant gave up).", "No answer to the handshake"
        if "m3" in seq and "m4" not in seq:
            return "The client never confirmed message 3 of the 4-way handshake (out of range, or a driver problem).", "Handshake not confirmed"
        return None, None

    def fail(self, s, why, hint=None, cause=None):
        if self.outcome:
            return
        self.outcome, self.done_at, self.failed_at, self.cause = "failed", s["ts"], _label(s), cause
        self.why = why + (" " + hint if hint else "")

    def succeed(self, s):
        if not self.outcome:
            self.outcome, self.done_at = "connected", s["ts"]

    def close(self):
        if self.outcome:
            return
        steps = [s["step"] for s in self.steps]
        pattern, cause = self.handshake_pattern()
        if pattern:
            self.outcome, self.failed_at, self.why, self.cause = "failed", "4-way handshake", pattern, cause
            self.done_at = self.last
        elif any(s["step"] in ("assoc_resp", "reassoc_resp") and _ok(s) for s in self.steps) and not any(x in steps for x in ("m1", "eap")):
            self.outcome, self.done_at = "connected", next(s["ts"] for s in self.steps if s["step"] in ("assoc_resp", "reassoc_resp") and _ok(s))
            self.method = self.method if self.method not in (None, "Open") else "Open (or the handshake was not heard)"
        else:
            self.outcome = "incomplete"
            self.why = "Only part of it was heard: the sensor may have been on another channel, or the client gave up without a word."

    def as_dict(self, ssids):
        t0 = self.start
        if self.method in (None, "Open") and any(s["step"] in ("m1", "m2") for s in self.steps):
            self.method = "PSK"
        return {"bssid": self.bssid, "ssid": ssids.get(self.bssid), "start": t0, "outcome": self.outcome, "why": self.why, "cause": self.cause,
                "failed_at": self.failed_at, "method": self.method, "came_from": self.came_from, "steered": self.steered,
                "duration_ms": round((self.done_at - t0) * 1000, 1) if self.done_at else None,
                "steps": [{"ms": round((s["ts"] - t0) * 1000, 1), "step": s["step"], "label": _label(s), "from_ap": bool(s["from_ap"]),
                           "ok": _ok(s) if s["step"] in ("auth", "assoc_resp", "reassoc_resp", "btm_resp") else s["step"] not in ("eap_failure", "deauth", "disassoc"),
                           "code": s.get("code"), "sensor": s.get("sensor")} for s in self.steps]}


STARTS = {"auth", "assoc", "reassoc"}


def attempts(events):
    """A client's steps (sorted by time) as attempts, and the disconnects that came after a connection was made."""
    out, disconnects, cur, steering = [], [], None, None
    for s in events:
        st = s["step"]
        if st in ("btm_req", "btm_resp", "nr_req", "nr_resp"):
            if st == "btm_req":
                steering = s["ts"]
            continue
        # A new attempt: after a pause, on another access point, or a start step once the current one is decided or got past
        # association (a start step before that, like SAE's second authentication exchange, belongs to the same attempt).
        restart = st in STARTS and (cur is not None and (cur.outcome or any(x["step"] in ("m1", "m2", "m3", "m4", "assoc_resp", "reassoc_resp")
                                                                             for x in cur.steps)))
        if cur and (s["ts"] - cur.last > GAP or s["bssid"] != cur.bssid or restart):
            if cur.outcome == "connected" and st in ("deauth", "disassoc") and s["bssid"] == cur.bssid:
                disconnects.append(s)
                continue
            cur.close()
            out.append(cur)
            cur = None
        if cur is None:
            if st in ("deauth", "disassoc"):
                disconnects.append(s)
                continue
            if st not in STARTS and st not in ("m1", "eapol_start", "eap"):
                continue   # the middle of something the sensor did not hear begin
            cur = Attempt(s)
            cur.steered = steering is not None and 0 <= s["ts"] - steering <= 15
        if cur.outcome == "connected" and st in ("deauth", "disassoc"):
            disconnects.append(s)
            continue
        cur.add(s)
    if cur:
        if not cur.outcome and events and time.time() - cur.last < GAP:
            cur.outcome = "in progress"
        else:
            cur.close()
        out.append(cur)
    return out, disconnects


def roams(tries):
    """Roams among a client's attempts (as dicts, oldest first): a reassociation (which is how a client moves within a network,
    a first connection is an association) to another access point, while the last connection was to another one not long before."""
    out, prev = [], None
    for a in tries:
        if a["outcome"] != "connected":
            continue
        reassoc = any(s["step"] == "reassoc" for s in a["steps"])
        if prev and reassoc and a["bssid"] != prev["bssid"] and a["start"] - prev["start"] <= ROAM_WITHIN:
            ms = a["duration_ms"]
            out.append({"ts": a["start"], "from": prev["bssid"], "to": a["bssid"], "ssid": a["ssid"], "ms": ms, "method": a["method"],
                        "steered": a["steered"],
                        "grade": None if ms is None else "fast" if ms < 50 else "ok" if ms < 150 else "slow" if ms < 1000 else "very slow"})
        prev = a
    return out


def _events(ctx, since, mac=None):
    w, p = "ts >= ?", [since]
    if mac:
        w += " AND mac = ?"
        p.append(mac)
    return ctx.rows(f"SELECT * FROM join_events WHERE {w} ORDER BY mac, ts LIMIT 200000", p)


def _ssids(ctx, bssids):
    bssids = [b for b in bssids if b]
    if not bssids:
        return {}
    return {r["mac"]: r["ssid"] for r in ctx.rows(f"SELECT mac, ssid FROM devices WHERE mac IN ({','.join('?' * len(bssids))})", bssids)}


def client(ctx, mac, since):
    ev = _events(ctx, since, mac)
    ssids = _ssids(ctx, {e["bssid"] for e in ev})
    tries, gone = attempts(ev)
    tries = [a.as_dict(ssids) for a in tries]
    return {"mac": mac, "attempts": tries[::-1][:100], "roams": roams(tries)[::-1],
            "disconnects": [{"ts": s["ts"], "bssid": s["bssid"], "ssid": ssids.get(s["bssid"]), "by": "access point" if s["from_ap"] else "client",
                             "step": s["step"], "code": s["code"], "reason": REASONS.get(s["code"], f"reason {s['code']}"),
                             "hint": REASON_HINTS.get(s["code"])} for s in gone][::-1][:100]}


def site(ctx, since, bssids=None):
    """Every client's attempts and roams, summed up: failures by cause, roam times and methods. `bssids`: only these access points."""
    ev = _events(ctx, since)
    by = {}
    for e in ev:
        by.setdefault(e["mac"], []).append(e)
    ssids = _ssids(ctx, {e["bssid"] for e in ev})
    fails, all_roams, counts = [], [], {"attempts": 0, "connected": 0, "failed": 0, "incomplete": 0}
    for mac, evs in by.items():
        tries = [a.as_dict(ssids) for a in attempts(evs)[0]]
        if bssids is not None:
            tries = [a for a in tries if a["bssid"] in bssids]
        for a in tries:
            counts["attempts"] += 1
            if a["outcome"] in counts:
                counts[a["outcome"]] += 1
            if a["outcome"] == "failed":
                fails.append({"mac": mac, **{k: a[k] for k in ("bssid", "ssid", "start", "why", "cause", "failed_at", "method")}})
        all_roams += [{"mac": mac, **r} for r in roams(tries)]
    causes = {}
    for f in fails:
        k = f["cause"] or (f["why"].split(":")[0] if f["why"] else "?")
        c = causes.setdefault(k, {"cause": k, "count": 0, "clients": set(), "example": f["why"], "last": 0})
        c["count"] += 1
        c["clients"].add(f["mac"])
        c["last"] = max(c["last"], f["start"])
    timed = sorted(r["ms"] for r in all_roams if r["ms"] is not None)
    methods = {}
    for r in all_roams:
        methods[r["method"] or "?"] = methods.get(r["method"] or "?", 0) + 1
    names = {r["mac"]: r for r in ctx.rows(f"SELECT mac, name, vendor FROM devices WHERE mac IN ({','.join('?' * len(by))})", list(by))} if by else {}
    for x in fails + all_roams:
        d = names.get(x["mac"]) or {}
        x["name"] = d.get("name") or d.get("vendor")
    return {"counts": counts, "causes": sorted(({**c, "clients": len(c["clients"])} for c in causes.values()), key=lambda c: -c["count"]),
            "failures": sorted(fails, key=lambda f: -f["start"])[:200], "roams": sorted(all_roams, key=lambda r: -r["ts"])[:200],
            "roam_stats": {"count": len(all_roams), "timed": len(timed), "median_ms": timed[len(timed) // 2] if timed else None,
                           "slow": sum(1 for x in timed if x >= 150), "methods": methods}}


def routes(ctx):
    r = APIRouter()

    def mine():
        n = ctx.settings.get("networks")
        trusted = set(n["trusted_bssids"])
        if not n["ssids"]:
            return None
        rows = ctx.rows(f"SELECT mac FROM devices WHERE kind='ap' AND ssid IN ({','.join('?' * len(n['ssids']))})", n["ssids"])
        return {x["mac"] for x in rows if not trusted or x["mac"] in trusted}

    @r.get("/api/joins")
    def joins_site(hours: float = 24, mine_only: bool = True, _=Depends(current_user)):
        """Connection attempts and roams of every client (of my networks' access points by default)."""
        return site(ctx, time.time() - hours * 3600, mine() if mine_only else None)

    @r.get("/api/joins/{mac}")
    def joins_client(mac: str, hours: float = 24, _=Depends(current_user)):
        """One client's connection attempts step by step, its roams and its disconnects."""
        if len(mac) > 64:
            raise HTTPException(400, "Not an address")
        return client(ctx, mac.lower(), time.time() - hours * 3600)

    return r
