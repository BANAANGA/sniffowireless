"""HTTP hardening: security headers + Content-Security-Policy, request size limits, query range limits and an
optional host allow-list (protects against DNS rebinding when the UI is reachable without login)."""
import json
import math
from urllib.parse import parse_qsl

CSP = ("default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
       "frame-ancestors 'none'; form-action 'self'")
# Uploaded images (an SVG floor plan could contain script) are served inert and sandboxed.
UPLOAD_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox"
DOCS_PATHS = ("/api/docs", "/api/openapi.json")  # Swagger UI needs inline script + its CDN

MB = 1024 * 1024
BODY_LIMITS = [("/api/backup/restore", 4096 * MB), ("/api/backup/inspect", 4096 * MB), ("/api/ingest", 32 * MB), ("/api/floorplan", 8 * MB), ("/api/appearance/icon", 1 * MB),
               ("/api/backup/config", 16 * MB)]
DEFAULT_BODY_LIMIT = 1 * MB
# Query parameters that size work on the server: (min, max)
QUERY_LIMITS = {"hours": (1 / 60, 24 * 400), "days": (1 / 24, 400), "limit": (1, 1000), "offset": (0, 10 ** 7),
                "bucket": (60, 86400), "tz": (-1440, 1440), "active": (0, 86400 * 400)}


def body_limit(path):
    for prefix, n in BODY_LIMITS:
        if path.startswith(prefix):
            return n
    return DEFAULT_BODY_LIMIT


def headers_for(path, scheme_https):
    h = [(b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"no-referrer"),
         (b"x-frame-options", b"DENY"), (b"cross-origin-opener-policy", b"same-origin"),
         (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), usb=(), interest-cohort=()")]
    if path.startswith(("/api/floorplan/image", "/api/appearance/icon")):
        h.append((b"content-security-policy", UPLOAD_CSP.encode()))
    elif not path.startswith(DOCS_PATHS):
        h.append((b"content-security-policy", CSP.encode()))
    if path.startswith("/api/") or path in ("/metrics", "/login", "/"):
        h.append((b"cache-control", b"no-store"))
    if scheme_https:
        h.append((b"strict-transport-security", b"max-age=31536000"))
    return h


class SecurityMiddleware:
    """Pure ASGI middleware (wraps receive/send so it can enforce body limits on streamed uploads too)."""

    def __init__(self, app, allowed_hosts=()):
        self.app = app
        self.allowed = {h.lower() for h in allowed_hosts if h and h != "*"}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope["path"]
        hdrs = {k.decode().lower(): v.decode("latin-1") for k, v in scope["headers"]}

        async def reject(code, detail):
            body = json.dumps({"detail": detail}).encode()
            await send({"type": "http.response.start", "status": code,
                        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
                        + headers_for(path, False)})
            await send({"type": "http.response.body", "body": body})

        if self.allowed:
            host = hdrs.get("host", "").rsplit(":", 1)[0].strip("[]").lower()
            if host not in self.allowed:
                return await reject(421, "host not allowed (ALLOWED_HOSTS)")
        for k, v in parse_qsl(scope.get("query_string", b"").decode("latin-1"), keep_blank_values=True):
            if k in QUERY_LIMITS and v != "":
                lo, hi = QUERY_LIMITS[k]
                try:
                    f = float(v)
                except ValueError:
                    continue  # FastAPI reports the type error
                if not math.isfinite(f) or not lo <= f <= hi:
                    return await reject(400, f"{k} must be between {lo:g} and {hi:g}")
        limit = body_limit(path)
        try:
            if int(hdrs.get("content-length") or 0) > limit:
                return await reject(413, "request body too large")
        except ValueError:
            return await reject(400, "invalid content-length")

        received = 0

        async def limited_receive():
            nonlocal received
            msg = await receive()
            if msg["type"] == "http.request":
                received += len(msg.get("body", b""))
                if received > limit:
                    raise ValueError("request body too large")
            return msg

        https = scope.get("scheme") == "https"
        extra = headers_for(path, https)

        async def send_with_headers(msg):
            if msg["type"] == "http.response.start":
                existing = {k.lower() for k, _ in msg.get("headers", [])}
                msg = {**msg, "headers": list(msg.get("headers", [])) + [h for h in extra if h[0] not in existing]}
            await send(msg)

        try:
            await self.app(scope, limited_receive, send_with_headers)
        except ValueError as e:
            if str(e) == "request body too large":
                return await reject(413, "request body too large")
            raise
