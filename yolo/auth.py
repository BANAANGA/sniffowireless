"""Web authentication: user accounts, login sessions, API tokens and the first-run setup flow.

* Passwords are hashed with PBKDF2-SHA256 (600k iterations, per-user salt).
* Browser sessions use a random cookie; only its SHA-256 is stored.
* API tokens (Bearer) are for Prometheus, remote sensors and scripts.
* With no users and no WEB_USER/WEB_PASSWORD, the first visit shows a setup page that needs a
  one-time code printed in the container log, so nobody else on the network can claim the admin.
"""
import hashlib
import hmac
import logging
import secrets
import time
from collections import defaultdict, deque
from contextlib import closing

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

log = logging.getLogger("yolo.auth")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL COLLATE NOCASE, pw_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'viewer', created REAL, last_login REAL, from_env INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS auth_sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created REAL, expires REAL, user_agent TEXT);
CREATE TABLE IF NOT EXISTS api_tokens(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL,
  scope TEXT NOT NULL, sensor_id TEXT, created REAL, last_used REAL);
"""
ROLES = ("admin", "viewer")
SCOPES = ("metrics", "sensor", "read", "admin")
SESSION_DAYS = 14
COOKIE = "yolo_session"
PBKDF2_ITERATIONS = 600_000
PUBLIC_PATHS = ("/login", "/api/auth/", "/api/health", "/static/", "/vendor/", "/favicon")


def hash_password(pw, salt=None, iterations=PBKDF2_ITERATIONS):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(pw, stored):
    try:
        _, it, salt, dk = stored.split("$")
        cand = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(cand.hex(), dk)
    except (ValueError, AttributeError):
        return False


def _sha(token):
    return hashlib.sha256(token.encode()).hexdigest()


class User:
    def __init__(self, id, username, role, via="session"):
        self.id, self.username, self.role, self.via = id, username, role, via

    @property
    def is_admin(self):
        return self.role == "admin"

    def dict(self):
        return {"id": self.id, "username": self.username, "role": self.role}


class Auth:
    def __init__(self, cfg, connect):
        self.cfg, self.connect = cfg, connect
        self.disabled = cfg.auth_disabled
        self.setup_code = None
        self.failures = defaultdict(deque)  # ip -> timestamps of failed logins
        with closing(self.connect()) as c:
            c.executescript(SCHEMA)
            if cfg.web_user and cfg.web_password:
                row = c.execute("SELECT id FROM users WHERE username=?", (cfg.web_user,)).fetchone()
                h = hash_password(cfg.web_password)
                if row:
                    c.execute("UPDATE users SET pw_hash=?, role='admin', from_env=1 WHERE id=?", (h, row[0]))
                else:
                    c.execute("INSERT INTO users(username, pw_hash, role, created, from_env) VALUES(?,?,?,?,1)",
                              (cfg.web_user, h, "admin", time.time()))
                log.info("Admin account '%s' configured from WEB_USER/WEB_PASSWORD", cfg.web_user)
            c.execute("DELETE FROM auth_sessions WHERE expires < ?", (time.time(),))
        if self.disabled:
            log.warning("AUTH_DISABLED=1: the web interface and API are open to anyone who can reach them")
        elif self.needs_setup():
            self.setup_code = "-".join(secrets.token_hex(2).upper() for _ in range(3))
            log.warning("No accounts exist yet. Open the web UI and create the admin account with setup code: %s",
                        self.setup_code)

    def needs_setup(self):
        with closing(self.connect()) as c:
            return c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0

    # ------------------------------------------------------------- sessions
    def login(self, username, password, ip, user_agent=""):
        now = time.time()
        q = self.failures[ip]
        while q and now - q[0] > 300:
            q.popleft()
        if len(q) >= 8:
            raise HTTPException(429, "Too many failed logins; try again in a few minutes")
        with closing(self.connect()) as c:
            row = c.execute("SELECT id, username, pw_hash, role FROM users WHERE username=?", (username,)).fetchone()
            if not row or not verify_password(password, row[2]):
                q.append(now)
                raise HTTPException(401, "Invalid username or password")
            q.clear()
            token = secrets.token_urlsafe(32)
            c.execute("INSERT INTO auth_sessions VALUES(?,?,?,?,?)",
                      (_sha(token), row[0], now, now + SESSION_DAYS * 86400, user_agent[:200]))
            c.execute("UPDATE users SET last_login=? WHERE id=?", (now, row[0]))
            return token, User(row[0], row[1], row[3])

    def logout(self, token):
        with closing(self.connect()) as c:
            c.execute("DELETE FROM auth_sessions WHERE token_hash=?", (_sha(token),))

    def from_session(self, token):
        with closing(self.connect()) as c:
            row = c.execute("SELECT u.id, u.username, u.role, s.expires FROM auth_sessions s JOIN users u ON "
                            "u.id = s.user_id WHERE s.token_hash=?", (_sha(token),)).fetchone()
            if not row or row[3] < time.time():
                return None
            if row[3] - time.time() < (SESSION_DAYS - 1) * 86400:  # sliding expiry
                c.execute("UPDATE auth_sessions SET expires=? WHERE token_hash=?",
                          (time.time() + SESSION_DAYS * 86400, _sha(token)))
            return User(row[0], row[1], row[2])

    def from_token(self, token):
        with closing(self.connect()) as c:
            row = c.execute("SELECT id, name, scope, sensor_id FROM api_tokens WHERE token_hash=?",
                            (_sha(token),)).fetchone()
            if not row:
                return None
            c.execute("UPDATE api_tokens SET last_used=? WHERE id=?", (time.time(), row[0]))
            u = User(-row[0], f"token:{row[1]}", "admin" if row[2] == "admin" else "viewer", via="token")
            u.scope, u.sensor_id = row[2], row[3]
            return u

    def create_token(self, name, scope, sensor_id=None):
        token = "yolo_" + secrets.token_urlsafe(32)
        with closing(self.connect()) as c:
            cur = c.execute("INSERT INTO api_tokens(name, token_hash, scope, sensor_id, created) VALUES(?,?,?,?,?)",
                            (name, _sha(token), scope, sensor_id, time.time()))
            return cur.lastrowid, token

    # ----------------------------------------------------------- middleware
    def install(self, app):
        auth = self

        @app.middleware("http")
        async def authenticate(request: Request, call_next):
            path = request.url.path
            request.state.user = None
            if auth.disabled:
                request.state.user = User(0, "admin", "admin", via="disabled")
                return await call_next(request)
            user = None
            h = request.headers.get("authorization", "")
            if h.lower().startswith("bearer "):
                user = auth.from_token(h[7:].strip())
            elif request.cookies.get(COOKIE):
                user = auth.from_session(request.cookies[COOKIE])
                # Cookie-authenticated writes must carry a header cross-site forms can't set (CSRF).
                if user and request.method not in ("GET", "HEAD", "OPTIONS") and \
                        request.headers.get("x-yolo") != "1":
                    return JSONResponse({"detail": "missing X-Yolo header"}, status_code=403)
            request.state.user = user
            if user or path.startswith(PUBLIC_PATHS) or path == "/api/ingest":
                return await call_next(request)
            if path.startswith("/api/") or path == "/metrics":
                return JSONResponse({"detail": "authentication required"}, status_code=401,
                                    headers={"WWW-Authenticate": "Bearer"})
            return RedirectResponse("/login")


def current_user(request: Request):
    u = request.state.user
    if not u:
        raise HTTPException(401, "authentication required")
    if getattr(u, "scope", None) in ("sensor", "metrics"):
        raise HTTPException(403, "token scope does not allow this")
    return u


def require_admin(request: Request):
    u = current_user(request)
    if not u.is_admin:
        raise HTTPException(403, "admin role required")
    return u


class Credentials(BaseModel):
    username: str
    password: str


class SetupRequest(Credentials):
    code: str


class NewUser(BaseModel):
    username: str
    password: str
    role: str = "viewer"


class PasswordChange(BaseModel):
    current: str = ""
    password: str


class NewToken(BaseModel):
    name: str
    scope: str = "read"


def _check_password(pw):
    if len(pw) < 10:
        raise HTTPException(400, "Password must be at least 10 characters")


def routes(ctx):
    auth = ctx.auth
    r = APIRouter()

    def set_cookie(request, response, token):
        secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
        response.set_cookie(COOKIE, token, max_age=SESSION_DAYS * 86400, httponly=True, samesite="lax",
                            secure=secure, path="/")

    @r.get("/api/auth/state")
    def state(request: Request):
        u = request.state.user
        return {"user": u.dict() if u else None, "setup": not auth.disabled and auth.needs_setup(),
                "disabled": auth.disabled}

    @r.post("/api/auth/login")
    def login(body: Credentials, request: Request, response: Response):
        token, user = auth.login(body.username.strip(), body.password, request.client.host if request.client else "?",
                                 request.headers.get("user-agent", ""))
        set_cookie(request, response, token)
        return {"user": user.dict()}

    @r.post("/api/auth/setup")
    def setup(body: SetupRequest, request: Request, response: Response):
        if auth.disabled or not auth.needs_setup():
            raise HTTPException(409, "Setup has already been completed")
        if not auth.setup_code or not hmac.compare_digest(body.code.strip().upper(), auth.setup_code):
            raise HTTPException(403, "Wrong setup code (see the container log: docker compose logs yolo)")
        _check_password(body.password)
        if not body.username.strip():
            raise HTTPException(400, "Username required")
        with closing(ctx.wdb()) as c:
            c.execute("INSERT INTO users(username, pw_hash, role, created) VALUES(?,?,?,?)",
                      (body.username.strip(), hash_password(body.password), "admin", time.time()))
        auth.setup_code = None
        log.info("Admin account '%s' created via setup page", body.username.strip())
        token, user = auth.login(body.username.strip(), body.password, "setup")
        set_cookie(request, response, token)
        return {"user": user.dict()}

    @r.post("/api/auth/logout")
    def logout(request: Request, response: Response):
        if request.cookies.get(COOKIE):
            auth.logout(request.cookies[COOKIE])
        response.delete_cookie(COOKIE, path="/")
        return {"ok": True}

    @r.post("/api/me/password")
    def change_password(body: PasswordChange, user=Depends(current_user)):
        _check_password(body.password)
        with closing(ctx.wdb()) as c:
            row = c.execute("SELECT pw_hash, from_env FROM users WHERE id=?", (user.id,)).fetchone()
            if not row:
                raise HTTPException(400, "This account cannot change its password here")
            if row[1]:
                raise HTTPException(400, "This account's password comes from WEB_PASSWORD; change it there")
            if not verify_password(body.current, row[0]):
                raise HTTPException(403, "Current password is wrong")
            c.execute("UPDATE users SET pw_hash=? WHERE id=?", (hash_password(body.password), user.id))
            c.execute("DELETE FROM auth_sessions WHERE user_id=?", (user.id,))
        return {"ok": True}

    # ------------------------------------------------------------ users (admin)
    @r.get("/api/users")
    def users(_=Depends(require_admin)):
        return ctx.rows("SELECT id, username, role, created, last_login, from_env FROM users ORDER BY username")

    @r.post("/api/users")
    def add_user(body: NewUser, _=Depends(require_admin)):
        if body.role not in ROLES:
            raise HTTPException(400, "role must be admin or viewer")
        _check_password(body.password)
        try:
            with closing(ctx.wdb()) as c:
                c.execute("INSERT INTO users(username, pw_hash, role, created) VALUES(?,?,?,?)",
                          (body.username.strip(), hash_password(body.password), body.role, time.time()))
        except Exception:
            raise HTTPException(409, "A user with that name already exists")
        return {"ok": True}

    @r.delete("/api/users/{uid}")
    def delete_user(uid: int, me=Depends(require_admin)):
        if uid == me.id:
            raise HTTPException(400, "You can't delete your own account")
        with closing(ctx.wdb()) as c:
            admins = c.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND id != ?", (uid,)).fetchone()[0]
            if not admins:
                raise HTTPException(400, "At least one admin must remain")
            c.execute("DELETE FROM auth_sessions WHERE user_id=?", (uid,))
            c.execute("DELETE FROM users WHERE id=?", (uid,))
        return {"ok": True}

    @r.post("/api/users/{uid}/role")
    def set_role(uid: int, body: dict, me=Depends(require_admin)):
        role = body.get("role")
        if role not in ROLES or uid == me.id:
            raise HTTPException(400, "Invalid role change")
        with closing(ctx.wdb()) as c:
            c.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
        return {"ok": True}

    # ------------------------------------------------------------ API tokens
    @r.get("/api/tokens")
    def tokens(_=Depends(require_admin)):
        return ctx.rows("SELECT id, name, scope, sensor_id, created, last_used FROM api_tokens ORDER BY created DESC")

    @r.post("/api/tokens")
    def new_token(body: NewToken, _=Depends(require_admin)):
        if body.scope not in SCOPES or body.scope == "sensor":
            raise HTTPException(400, "scope must be metrics, read or admin (sensor tokens are made per sensor)")
        tid, token = auth.create_token(body.name.strip() or body.scope, body.scope)
        return {"id": tid, "token": token}

    @r.delete("/api/tokens/{tid}")
    def delete_token(tid: int, _=Depends(require_admin)):
        with closing(ctx.wdb()) as c:
            c.execute("DELETE FROM api_tokens WHERE id=?", (tid,))
        return {"ok": True}

    return r
