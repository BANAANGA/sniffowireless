[← Back to the README](../README.md)

# Backup & restore

**Settings → Backup**:

- **Configuration backup (JSON):** includes:
  - settings, my networks and the ignore list
  - labels, groups and alert rules
  - notification channels (secrets only if you tick the box; the same goes for the MQTT password and the key for pseudonymised MAC addresses, and restoring a backup without them keeps this server's)
  - sensors, without their tokens: re-create those
  - users, as password hashes

  It contains no measurement history and is small. When you restore it you **choose which parts** to bring back (a list with how much of each the file holds); those replace what is set now and apply immediately, which makes it handy for moving to a new server or putting a configuration under version control.
- **Full backup (`.tar.gz`):** all data: the whole database (history, sessions, traffic, settings, users, API tokens), the floor plan and icon, and the handshake captures. It's taken with SQLite's online backup, so it's consistent while sniffowireless keeps capturing. *Back up now* writes one to `data/backups/`, and **daily scheduled backups** with retention can be switched on.
- **Restore a full backup:** pick one from the list or upload a file. sniffowireless checks the archive (format, safe paths, database integrity), shows what it holds, and asks what to restore:
  - **Everything** replaces the whole database with the backup's.
  - **Only what I choose** restores just the parts you tick and leaves the rest as it is: settings, device labels & links, groups, alert rules, notification channels, remote sensors, users, API tokens, device history, security findings & alert log, LAN / Zigbee / channel data, floor plan & icon, and handshake captures. Labels and groups, and alert rules and notification channels, refer to each other, so restore them together (links to anything left out are cleared rather than left dangling), and restoring *Users* never leaves you without an account.

  Either way it stages the restore and restarts; on startup it applies it, keeping the previous database as `data/backups/pre-restore-….db`. The restart relies on Docker's restart policy, which the compose file and the `docker run` example set (`restart: unless-stopped`).

Copy `data/backups` off the machine as well, e.g. with a nightly `rsync`, since a backup on the same disk doesn't survive a dead disk.
