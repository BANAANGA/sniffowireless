[← Back to the README](../README.md)

# Hardening

What the application does to protect itself, what is checked on every change, and what to do on your side.

## Built in

- **Sign-in.** Passwords are required to be at least 10 characters, can be combined with two-factor codes, and sign-in attempts are throttled: after 8 wrong attempts from one address (or 10 for one account) within 5 minutes, further attempts are refused with *429* for a few minutes, even with the right password. Sessions are stored in the database (only a hash of the token is kept); the cookie is `HttpOnly`, `SameSite=Lax` and gets `Secure` when the page is served over HTTPS. A session lasts 14 days after it was last used, but never more than 90 days after sign-in, so a stolen cookie cannot be kept alive forever. At most 4 passwords are checked at a time (each check takes a deliberate fraction of a second of CPU), so a flood of sign-in attempts cannot starve capture; the rest wait up to 5 seconds and are then told to try again.
- **Everything needs a login except the pages that must work before one.** Every API read except the few below answers *401* without a session, and every request that changes something answers *401* or *403* unless an admin made it (apart from a user's own password and two-factor settings). A test walks all routes (170 at release 31) as a viewer and as an anonymous caller on every change, so a new endpoint that forgets the admin check fails the build. The rest are the sign-in page and application shell, the static scripts, `/api/health` (just `{"ok":true}`), `/api/auth/state` and `/api/appearance` (name, icon and colours, so the sign-in page can use them). Remote sensors authenticate with their own token. A sensor token reaches only `/api/ingest` (send readings, deliver a recording the server asked for) and, since release 34.2, the walk surveys of its own sensor under `/api/ingest/walk` (start, add points, close) and the floor plan they are drawn on; every other endpoint answers *403* to it.
- **Requests that change something need the app's own header and a same-origin request.** Another website cannot make your browser change settings, even while you are signed in.
- **Response headers.** A strict Content-Security-Policy (scripts only from this server, no inline scripts, no plugins, no framing), `X-Content-Type-Options`, `X-Frame-Options: DENY`, no referrer, a locked-down permissions policy, `Cache-Control: no-store` for API responses and `Strict-Transport-Security` over HTTPS. `Cross-Origin-Resource-Policy: same-origin` and `X-Permitted-Cross-Domain-Policies: none`. Uploaded images are served sandboxed.
- **Scripts are verified at build time.** The charting, QR-code and flasher libraries are downloaded when the image is built and checked against pinned SHA-256 hashes; a changed or unreachable download fails the build instead of shipping unverified code, and the image never loads scripts from a CDN.
- **Limits.** Request bodies are limited (1 MB by default, larger only for backups, sensor uploads and floor plans), and the query parameters that size work on the server are bounded.
- **Input from remote sensors is cleaned** before it is stored (text, numbers, lists and nesting depth are bounded) and cannot create arbitrary event types.
- **No shell.** Commands to the system (`iw`, `ip`) are run with an argument list, never through a shell, and adapter names are validated first. Notification URLs must be `http://` or `https://`.
- **Radio text is never markup.** Network names, device names, vendors, notes and everything else heard over the air or typed in is escaped before it is shown; the CSP blocks inline scripts as a second line. Checked by planting HTML in every such field and opening every page.
- **Stored file names are not trusted as paths.** The floor plan and app icon are only served or deleted under the names the app itself writes, also after restoring a configuration backup made elsewhere.
- **Transmitting is for admins.** *Play sound* and *read exact version* make the sensor connect to a Bluetooth device, so viewers cannot use them.
- **Backups without secrets leave out the secrets.** A configuration backup made without secrets leaves out notification secrets, the MQTT password, the key for pseudonymised MAC addresses and two-factor login secrets; restoring it keeps this server's own, so nobody's two-factor login is switched off. If it includes the user accounts it does hold their password *hashes* (needed to sign in after a restore), so keep backups private either way.
- **A backup can only put back what the app wrote.** A restore puts back the database and, of the files, only the floor plan, the app icon and handshake captures under the names the app gives them; anything else in the archive is skipped, so a backup made by someone else cannot replace the database or plant files. A backup that would not fit on the disk once unpacked is refused before it is unpacked.
- **Proxy headers only from your proxy.** `X-Forwarded-For`, `-Proto` and `-Host` are believed only from the addresses in `TRUSTED_PROXIES`; from anyone else they are ignored, for sign-in throttling, the same-origin check and the cookie's `Secure` flag alike.
- **API docs.** `/api/docs` needs a sign-in and loads one pinned version of Swagger UI under its own Content-Security-Policy (nothing else can be loaded and the page cannot be framed).
- **DNS-rebinding protection** with `ALLOWED_HOSTS` (see below), also for IPv6 addresses such as `[::1]`.

## Checked on every change

GitHub Actions runs on every pull request and push to `main` and `stable`, and once a week:
- the test suite (more than 560 tests, including the security tests for sign-in, request checks, headers, uploads and limits) on Python 3.12, the version the image uses,
- `ruff` for syntax errors, undefined names and unused code,
- `pip-audit` against `requirements.txt`, so a newly published vulnerability in a dependency shows up within a week,
- the GitHub Actions in the workflows are pinned to a commit, not a tag that could be moved; Dependabot proposes their updates,
- a build of the image for 64-bit and 32-bit Raspberry Pi systems.

One advisory is accepted on purpose: scapy `GHSA-cq46-m9x9-j8w2` is about loading a pickled session file in scapy's interactive shell. The application never starts that shell or loads sessions, so it is not reachable. The fixed scapy version renames packet-flag names that the capture code relies on, so it is not adopted until it has been tried against real captures.

## What you should do

- **Set `ALLOWED_HOSTS`** to the names and addresses you use to open the interface. Without it every `Host` header is accepted, which leaves the interface open to DNS-rebinding tricks from a web page in your network.
- **Do not expose the interface to the internet.** If you need remote access, put it behind a reverse proxy that serves HTTPS, set `TRUSTED_PROXIES` to the proxy's address, or use a VPN.
- **Use a long unique password and turn on two-factor sign-in** (Settings → Account), at least for admins.
- **Know what the container can do.** To switch adapters into monitor mode and open raw Bluetooth sockets, the container runs as root with host networking, normally with `privileged: true`. That means a flaw in the application would reach the host. [Less privilege](deploy.md#less-privilege) describes a narrower setup (`NET_ADMIN`, `NET_RAW`) that works for many systems; it has not been tried on every adapter. Keep the interface reachable only from networks you trust.
- **Keep it updated** ([Updating](updating.md)), and make backups ([Backup & restore](backup.md)).
- **Sensors:** each remote sensor has its own token; delete a sensor under Settings → Sensors to revoke it.

## Not covered

- It is a passive monitor that sees what any radio nearby can see. Anything it stores about the people and devices around you is personal data in many places; the [privacy settings](privacy.md) (hashed storage, retention, anonymising, clearing data) are there for that, and every page carries a notice to respect the law and people's privacy.
- The size of the daily-use database is not limited by security settings; see retention in the settings.
- This has not had an independent security audit.

Reporting a problem: see the [security policy](../SECURITY.md).
