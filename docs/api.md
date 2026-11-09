[← Back to the README](../README.md)

# API

Interactive docs (all endpoints) are at `/api/docs`. Every endpoint needs a login session or `Authorization: Bearer <token>`. Main read endpoints:

| Endpoint | Description |
|---|---|
| `GET /api/summary` | Counts per type, recent events |
| `GET /api/timeline?hours=24` | Active devices per type and connected clients per time bucket |
| `GET /api/devices?kind=&active=&q=&vendor=&brand=&dev_type=&os=&wifi_gen=&era=&fp=&ssid=&probe=&bssid=&channel=&band=&randomized=&connected=&sort=&order=&limit=&offset=` | Device list (`band`: `2.4`/`5`/`6`; `wifi_gen`: `3` legacy, `4`–`7`, `66` = 6E) |
| `GET /api/devices/{mac}` | Device detail, identification (`ident`), stats, peers, probes, events |
| `GET /api/devices/{mac}/rssi?hours=` | Signal history |
| `GET /api/devices/{mac}/sessions?hours=&as_peer=1` | Visits/connections (`as_peer=1`: client sessions on an AP) |
| `GET /api/devices/{mac}/clients?hours=` | Connected clients over time for an AP |
| `GET /api/devices/{mac}/heatmap?days=28&tz=` | Weekday × hour presence matrix |
| `GET /api/stats?days=7` | All statistics shown on the Statistics page |
| `GET /api/events?type=&mac=&kind=&before=` | Event log |
| `GET /api/status` | Sensor and store health, host CPU / memory, database and disk size |
| `GET /api/appearance` · `PUT /api/appearance` · `POST`/`DELETE /api/appearance/icon` | App name, icon and colours (read without login; changes admin only) |
| `GET /api/export/devices.csv`, `/api/export/sessions.csv?days=7` | CSV export |
| `GET /api/search?q=&section=&limit=` | Search all records (devices, groups, networks, probes, dns, events, alerts, findings, sensors) |
| `GET /api/matching` · `GET /api/devices/{mac}/matches` · `POST /api/links` · `DELETE /api/links/{a}/{b}` | Bluetooth↔Wi-Fi match suggestions, per-device matches, and confirming/rejecting/removing a link (admin) |
| `GET /api/ssids?q=` | All seen SSIDs with access points, clients, devices looking for them, and mine/ignored/investigated flags |
| `GET /api/investigations` · `GET /api/investigations/{ssid}` · `PUT /api/settings/investigate` | Networks under investigation, per-network dossier, and the list itself (admin) |
| `GET /api/groups`, `/api/groups/{id}` | Groups and combined presence |
| `GET /api/alerts`, `/api/alert-rules` | Alert history and rules |
| `GET /api/security` | Findings, my-network BSSIDs, security events |
| `GET /api/channels?hours=24` | Channel survey and recommendations |
| `GET /api/mynet?days=7` | Health of my networks |
| `GET /api/map`, `/api/sensors` | Device rooms/positions, sensors |
| `GET /api/reports/occupancy?days=7` | Occupancy report data |
| `GET /api/lan?hours=24` | LAN overview: devices online, throughput, top talkers, destinations, services, DNS, DHCP servers |
| `GET /api/devices/{mac}/lan?hours=24` | Device traffic, peers and DNS lookups |
| `GET /api/interference?days=7` | Interference episodes |
| `GET /api/dfs?days=7` | Radar hits per DFS channel, channel switch history and access points on DFS channels |
| `GET /api/trackers` | Tracker tags and who they move with |
| `GET /api/backup/config` · `POST /api/backup/config` | Download / restore the configuration (admin); `POST /api/backup/config/inspect` lists what a file holds, and `?sections=a,b` restores only those parts |
| `POST /api/backup/full` · `GET /api/backup/list` · `GET /api/backup/files/{name}` | Create, list and download full backups (admin) |
| `GET /api/backup/files/{name}/sections` · `POST /api/backup/inspect` | List what a stored / uploaded full backup holds, per section (admin) |
| `POST /api/backup/restore-selected` | Restore a stored (`source`: its name) or just-inspected (`"upload"`) backup, all (`"sections": "all"`) or only the listed sections, then restart (admin) |
| `GET /api/about` | Version, commit, build time, runtime and start time of this server |
| `GET /api/channel-settings` · `PUT` / `DELETE /api/channel-settings/{target}` | Wi-Fi channel settings of this server (`local`) or a remote sensor (its id), with the adapters each reports (admin) |
| `POST /api/backup/files/{name}/restore` · `POST /api/backup/restore` | Restore a whole stored / uploaded full backup, then restart (admin) |
| `GET /api/logs?after=` · `GET /api/logs/stream` · `PUT /api/logs/level` | Recent log lines, live log stream (Server-Sent Events) and runtime log level (admin) |
| `GET /metrics` | Prometheus metrics |
| `POST /api/ingest` | Remote sensors push observations here (sensor token) |
