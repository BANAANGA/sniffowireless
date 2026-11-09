[← Back to the README](../README.md)

# Accounts & access

The web UI and API need a login.

- **First start without `WEB_USER`/`WEB_PASSWORD`:** the browser shows a *Create the admin account* page. To stop someone else on your network from claiming the admin account first, it asks for a one-time **setup code** printed in the container log:
  ```bash
  docker compose logs sniffowireless | grep "setup code"
  ```
- **With `WEB_USER` and `WEB_PASSWORD`:** that account is created (or reset) as an admin on every start, and no setup page is shown. Its password can only be changed through the environment.
- **Two-factor login:** under **Settings → Account** anyone can add a code from an authenticator app (any TOTP app) to their password: scan the QR code (or type the key), confirm with a code, and keep the ten **recovery codes** shown once (each works once). Sign-in then asks for the code after the password; wrong codes count toward the same lockout as wrong passwords, and a code works only once. Turning it on signs your other sessions out; turning it off asks for the password and a code. API tokens and sensors are not affected. **Lost phone and recovery codes:** an admin removes it under **Settings → Users → Reset 2FA**; if it is the only admin, start the container once with `RESET_2FA_USER=<username>` (then remove the variable again).
- **Roles:** *admins* can change settings, labels, groups, alert rules and the ignore list. *Viewers* can only look. Add users under **Settings → Users**.
- **API tokens** (Settings → API tokens) are sent as `Authorization: Bearer <token>`:
  - `metrics`: only `/metrics`
  - `read`: read-only API
  - `admin`: full API

  Remote sensors get their own tokens, created under Settings → Sensors.
- Passwords are stored as salted PBKDF2-SHA256 hashes. Sessions are HttpOnly cookies that expire after 14 days of inactivity. Logins are rate-limited per IP.
- **HTTPS:** put sniffowireless behind a reverse proxy (Caddy, Traefik, nginx) for TLS when you reach it from outside your LAN. The session cookie is marked `Secure` when the proxy sets `X-Forwarded-Proto: https`.
- `AUTH_DISABLED=1` turns login off entirely. Only use it on a network where you trust everyone, and set `ALLOWED_HOSTS` then; see below.

## Security hardening

sniffowireless treats everything it receives as untrusted. Device names and SSIDs are chosen by whoever is nearby, and remote sensors and API clients send data too.

- **Input validation:**
  - every API field has a type, a format (MACs, IPs, times, e-mail addresses, enums) and a length limit
  - names, SSIDs, labels and notification titles are stripped of control characters, which blocks newline/header injection and Unicode direction tricks
  - data pushed by remote sensors is re-validated field by field; unknown record types are refused and gzip bombs are capped
- **Output encoding:** the UI escapes every value it inserts into a page. A strict **Content-Security-Policy** (no inline or third-party scripts except the pinned Chart.js CDN fallback) stops script injection even if something slipped through.
- **Uploads:** floor plans are checked by content (PNG, JPEG, WebP or SVG), SVGs are stripped of scripts and event handlers, and the image is served sandboxed. Backups are verified (format, safe paths, database integrity) before restore.
- **Requests:** CSRF protection (custom header plus an Origin check, `SameSite` cookies), body size limits, limits on time ranges and page sizes, and security headers (`nosniff`, `DENY` framing, `no-referrer`, `no-store` for API responses, HSTS over HTTPS).
- **Login:**
  - salted PBKDF2 hashes
  - lockout per IP and per account after repeated failures
  - equal response times for unknown users, so usernames can't be probed
  - a rate-limited setup code
  - minimum password rules
- **Exports:** CSV cells that start with `=`, `+`, `-` or `@` are prefixed so spreadsheets don't run them as formulas.
- **Proxies and hosts:**
  - `TRUSTED_PROXIES` (default `127.0.0.1`): only these addresses may set `X-Forwarded-For`/`-Proto`, so clients can't fake their IP to dodge the lockout. Set it to your reverse proxy's address.
  - `ALLOWED_HOSTS` (e.g. `sniffowireless.lan,192.168.1.10`): refuses requests for any other host name, which protects against DNS-rebinding attacks from malicious websites, especially with `AUTH_DISABLED=1`.

The container needs `privileged`/host networking to capture, so run it on a machine you control and don't expose port 8080 to the internet; use a VPN or an authenticating reverse proxy with TLS for remote access.
