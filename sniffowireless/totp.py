"""Time-based one-time passwords (RFC 6238, as every authenticator app does them): 6 digits, 30 second steps, SHA-1."""
import base64
import hashlib
import hmac
import os
import struct
import time
from urllib.parse import quote

STEP = 30
DIGITS = 6
WINDOW = 1  # steps either side of now that are accepted (clock drift of the phone)


def new_secret():
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _key(secret):
    s = secret.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def code_at(secret, step, digits=DIGITS):
    mac = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


def verify(secret, code, last_step=0, now=None):
    """The time step the code is valid for, or None. A step at or before `last_step` (already used) is refused, so a code
    that was seen once cannot be used again."""
    if not code or len(code) != DIGITS or not code.isdigit():
        return None
    now_step = int((time.time() if now is None else now) // STEP)
    for step in range(now_step - WINDOW, now_step + WINDOW + 1):
        if step > last_step and hmac.compare_digest(code_at(secret, step), code):
            return step
    return None


def uri(secret, account, issuer="sniffowireless"):
    return f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={STEP}"
