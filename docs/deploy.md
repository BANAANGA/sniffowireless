[← Back to the README](../README.md)

# Deploying: other ways

## Without compose

```bash
docker build -t sniffowireless .
docker run -d --name sniffowireless --restart unless-stopped \
  --network host --privileged \
  -v "$PWD/data:/data" \
  -e WIFI_INTERFACES=wlan1 -e BT_DEVICES=hci0 -e TZ=Europe/Amsterdam \
  sniffowireless
```

## Deploying with Arcane

[Arcane](https://getarcane.app) is a web UI for managing Docker and Compose projects. sniffowireless can run as an Arcane project. Arcane can pull the [published image](#prebuilt-image) straight from the registry, or run an image you built from source on the Docker host.

> Arcane's documentation doesn't mention `network_mode: host` or `privileged: true` containers, and these steps haven't been verified on a real Arcane install yet. If your Arcane behaves differently, the plain [`docker compose`](../README.md#3-start-it) route above always works.

**1. Install Arcane** by following its [installation guide](https://getarcane.app/docs/get-started/installation.html). Two things from that guide are worth repeating:
- set your own `ENCRYPTION_KEY` (for example from `openssl rand -hex 32`) instead of relying on the development default;
- sign in with the default login the guide lists and change the password when Arcane asks. Arcane controls Docker through its socket, so treat access to it like root access to the host.

Arcane uses port 3552, so it doesn't clash with sniffowireless on 8080.

**2. Prepare the adapters on the host** as described in [Connecting USB Wi-Fi / Bluetooth adapters](adapters.md#connecting-usb-wi-fi--bluetooth-adapters). Arcane doesn't change anything on the host's network side.

**3. Get the image.** Nothing to do for the published image: Arcane pulls it when you deploy in step 5. To build from source instead, on the Docker host (the machine Arcane manages):

```bash
git clone https://github.com/BANAANGA/sniffowireless.git
```

```bash
cd sniffowireless && docker build -t sniffowireless:latest .
```

and use `image: sniffowireless:latest` in the compose file below.

**4. Create the project in Arcane.** Open **Projects → Create Project**, name it `sniffowireless`, paste this compose file, and fill in the **Environment Configuration (.env)** editor with your adapters:

```yaml
services:
  sniffowireless:
    image: ghcr.io/banaanga/sniffowireless:latest
    container_name: sniffowireless
    restart: unless-stopped
    network_mode: host
    privileged: true
    env_file:
      - path: .env
        required: false
    environment:
      WIFI_INTERFACES: ${WIFI_INTERFACES:-}
      WIFI_CHANNELS: ${WIFI_CHANNELS:-}
      WIFI_REGDOMAIN: ${WIFI_REGDOMAIN:-}
      BT_DEVICES: ${BT_DEVICES:-}
      ETH_INTERFACES: ${ETH_INTERFACES:-}
      ZIGBEE_DEVICES: ${ZIGBEE_DEVICES:-}
      WEB_PORT: ${WEB_PORT:-8080}
      WEB_USER: ${WEB_USER:-}
      WEB_PASSWORD: ${WEB_PASSWORD:-}
      ALLOWED_HOSTS: ${ALLOWED_HOSTS:-}
      TRUSTED_PROXIES: ${TRUSTED_PROXIES:-127.0.0.1}
      TZ: ${TZ:-UTC}
    volumes:
      - /opt/sniffowireless/data:/data
```

For example, in the `.env` editor:

```
WIFI_INTERFACES=wlan1
BT_DEVICES=hci0
TZ=Europe/Amsterdam
```

The data folder is an absolute host path on purpose, so you know exactly what to back up (it holds the database, floor plan and handshake captures) no matter where Arcane keeps its project files. Change `/opt/sniffowireless/data` if you like. The other settings in [Configuration](../README.md#configuration) go in the same `.env` editor.

**5. Deploy** the project from its page, then open `http://<host>:8080`. Don't close the *Watch output* window while a deploy is running: Arcane's documentation warns that doing so stops the project. The first sign-in asks for a one-time setup code, which is in the container's log:

```bash
docker logs sniffowireless
```

**Updating.** With the published image, click **Redeploy** on the project: Arcane pulls the latest image and restarts it. If you built the image yourself, rebuild it on the host:

```bash
cd sniffowireless && git pull && docker build -t sniffowireless:latest .
```

then recreate the container from Arcane's **Deploy** options, with *force recreate* ticked and a pull policy that doesn't pull. That image only exists on the host, so *Redeploy*, which pulls the latest images first, isn't what you want there.

**Alternative: build inside Arcane from Git.** Arcane can also create a project straight from this repository. Add the repository under **Customization → Git Repositories**, then **Projects → From Git Repo → Pull** with branch `main`, **Compose File Path** `docker-compose.yml`, and **Sync Files** on, so the `Dockerfile` is next to the compose file. Set your adapters in the project's `.env` editor (the compose file of a Pull project is read-only), then use **Build & Deploy**, which Arcane offers for services that have a `build:` section. Use **Auto Sync** to pick up new versions. This is the less proven route; if the build doesn't start, use the steps above.

## Prebuilt image

Released versions are published to the GitHub Container Registry for `linux/amd64`, `linux/arm64` and `linux/arm/v7` (so also a Raspberry Pi, with a 64-bit or a 32-bit OS; `uname -m` says `aarch64` or `armv7l`), which saves building on the host:

```bash
docker pull ghcr.io/banaanga/sniffowireless:latest
```

The tags are `latest` (the newest release that isn't a pre-release), the release's own tag (for example `11`), `sha-<commit>`, and `edge` (a manual build of a branch). To use it with compose, replace the `build: .` and `image:` lines of `docker-compose.yml` with `image: ghcr.io/banaanga/sniffowireless:latest`, then:

```bash
docker compose pull && docker compose up -d
```

With plain `docker run` (see above), use the same image name instead of `sniffowireless`.

## Less privilege

`privileged: true` is the simplest option that works. If you prefer, replace it with:

```yaml
    cap_add: [NET_ADMIN, NET_RAW]
    security_opt: ["seccomp=unconfined"]   # some Docker versions block AF_BLUETOOTH sockets
```
