"""Display filters for the frame inspector, in the spirit of Wireshark's:

    wifi                         a radio (wifi, bt / ble / bluetooth, zigbee, lora) or a word in the protocol or frame type
    beacon && rssi > -60         comparisons: == != > < >= <= and `contains`, combined with && / and, || / or, ! / not, ( )
    addr == aa:bb:cc:dd:ee:ff    either address; also src, dst
    ssid contains "home"         text compares ignoring case; values with spaces go in quotes

Fields: no, time, radio, proto, type, src, dst, addr, bssid, info, len, rssi, channel, ssid, name, company, sensor.
A filter is parsed once into a predicate over the frame summaries (dissect.py); a mistake raises FilterError with a sentence.
"""
import re

FIELDS = {"no", "time", "radio", "proto", "protocol", "type", "src", "dst", "addr", "bssid", "info", "len", "length", "rssi", "channel",
          "ssid", "name", "company", "sensor", "pan", "epid", "network"}
NUMERIC = {"no", "time", "len", "length", "rssi"}
RADIOS = {"wifi": "wifi", "wlan": "wifi", "802.11": "wifi", "bt": "bt", "ble": "bt", "bluetooth": "bt", "zigbee": "zigbee", "thread": None,
          "802.15.4": "zigbee", "wpan": "zigbee", "lora": "lora"}
ALIASES = {"protocol": "proto", "length": "len"}
TOKEN = re.compile(r'\s*(?:(&&|\|\||==|!=|>=|<=|>|<|!|\(|\))|"((?:[^"\\]|\\.)*)"|([^\s()!=<>&|"]+))')
MAX_LEN = 500


class FilterError(ValueError):
    pass


def tokens(text):
    out, at = [], 0
    text = text.strip()
    while at < len(text):
        m = TOKEN.match(text, at)
        if not m or m.end() == at:
            raise FilterError(f"Unexpected character at position {at + 1}: {text[at:at + 10]!r}")
        op, quoted, word = m.groups()
        if op:
            out.append(("op", op))
        elif quoted is not None:
            out.append(("str", re.sub(r"\\(.)", r"\1", quoted)))
        else:
            low = word.lower()
            out.append(("op", {"and": "&&", "or": "||", "not": "!"}[low]) if low in ("and", "or", "not") else
                       ("op", "contains") if low == "contains" else ("word", word))
        at = m.end()
    return out


def value_of(s, field):
    field = ALIASES.get(field, field)
    if field == "addr":
        return [s.get("src") or "", s.get("dst") or "", s.get("bssid") or ""]
    v = s.get(field)
    return [v] if v is not None else []


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def norm(v):
    return str(v).lower().strip()


def compare(field, op, want):
    field = ALIASES.get(field, field)
    if field in NUMERIC:
        w = num(want)
        if w is None:
            raise FilterError(f"{field} needs a number, not {want!r}")
    else:
        w = norm(want)

    def test(s):
        for v in value_of(s, field):
            if field in NUMERIC:
                x = num(v)
                if x is None:
                    continue
            elif field == "channel":
                x = norm(v)
                xn, wn = num(v), num(want)
                if xn is not None and wn is not None and op in (">", "<", ">=", "<="):
                    x, w2 = xn, wn
                    if {">": x > w2, "<": x < w2, ">=": x >= w2, "<=": x <= w2}[op]:
                        return True
                    continue
            else:
                x = norm(v)
            if op == "contains":
                if str(w) in str(x):
                    return True
            elif op == "==":
                if x == w:
                    return True
            elif op == "!=":
                if x != w:
                    return True
            elif field in NUMERIC and {">": x > w, "<": x < w, ">=": x >= w, "<=": x <= w}[op]:
                return True
        return op == "!=" and not value_of(s, field)
    return test


def bare(word):
    w = word.lower()
    radio = RADIOS.get(w)
    if w == "thread":
        return lambda s: "thread" in norm(s.get("proto")) or "6lowpan" in norm(s.get("proto"))
    if radio:
        return lambda s: s.get("radio") == radio
    return lambda s: w in norm(s.get("proto")) or w in norm(s.get("type")) or w in norm(s.get("info"))


class Parser:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self):
        tok = self.peek()
        self.i += 1
        return tok

    def expr(self):
        left = self.term()
        while self.peek() == ("op", "||"):
            self.take()
            right = self.term()
            left = (lambda a, b: lambda s: a(s) or b(s))(left, right)
        return left

    def term(self):
        left = self.factor()
        while self.peek() == ("op", "&&"):
            self.take()
            right = self.factor()
            left = (lambda a, b: lambda s: a(s) and b(s))(left, right)
        return left

    def factor(self):
        kind, v = self.take()
        if (kind, v) == ("op", "!"):
            inner = self.factor()
            return lambda s: not inner(s)
        if (kind, v) == ("op", "("):
            e = self.expr()
            if self.take() != ("op", ")"):
                raise FilterError("A closing parenthesis is missing")
            return e
        if kind == "word":
            nxt = self.peek()
            if nxt[0] == "op" and nxt[1] in ("==", "!=", ">", "<", ">=", "<=", "contains"):
                field = v.lower()
                if field not in FIELDS:
                    raise FilterError(f"Unknown field {v!r}; fields are: {', '.join(sorted(FIELDS - set(ALIASES)))}")
                self.take()
                k2, want = self.take()
                if k2 not in ("word", "str"):
                    raise FilterError(f"A value is missing after {nxt[1]}")
                return compare(field, nxt[1], want)
            return bare(v)
        if kind == "str":
            w = v.lower()
            return lambda s: w in norm(s.get("info")) or w in norm(s.get("src")) or w in norm(s.get("dst"))
        raise FilterError("The filter ends too early" if kind is None else f"Unexpected {v!r}")


def compile_filter(text):
    """A predicate over frame summaries, or None for an empty filter."""
    text = (text or "").strip()
    if not text:
        return None
    if len(text) > MAX_LEN:
        raise FilterError("The filter is too long")
    p = Parser(tokens(text))
    pred = p.expr()
    if p.i < len(p.t):
        raise FilterError(f"Unexpected {p.t[p.i][1]!r}")
    return pred
