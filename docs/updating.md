[← Back to the README](../README.md)

# Updating

## Updating

**First take a backup** (*Settings → Backup → Back up now*). The database schema is created and upgraded automatically on start, and that only goes forward: to go back to an older version you restore the backup as well. Your data lives in `./data`, so recreating the container loses nothing.

**What am I running?** *Settings → About* shows the version (the release tag, with a link to its notes), the commit, when the image was built and how long it has been running. *Settings → Sensors* shows each remote sensor's version next to the server's, and marks one that **differs from the server**. A sensor that shows *not reported* is offline, or runs a version from before this was added; a sensor that is offline shows the version it last reported, marked *as of* when. Images from the published registry carry this information; a build from source records it when you update with `./scripts/update.sh`. A page that was open while the server was updated offers a *Reload* button, since it still runs the old scripts.

### The main server

Pick the way you run it:

- **Built from source** (the default `docker-compose.yml`). The script pulls, rebuilds, and records the version so *Settings → About* shows it:

  ```bash
  cd sniffowireless && ./scripts/update.sh
  ```

  Without it (`git pull && docker compose up -d --build`) everything works, but the build is labelled `source` with no number.

- **Prebuilt image** (compose with `image: ghcr.io/banaanga/sniffowireless:latest`, see [Prebuilt image](deploy.md#prebuilt-image)):

  ```bash
  docker compose pull && docker compose up -d
  ```

  Compose only recreates the container when the image changed.

- **Plain `docker run`:** pull the new image, remove the container, and start it again with the same options you used before (keep that command in a script):

  ```bash
  docker pull ghcr.io/banaanga/sniffowireless:latest
  ```

  ```bash
  docker rm -f sniffowireless
  ```

- **Arcane:** click **Redeploy** on the project, see [Deploying with Arcane](deploy.md#deploying-with-arcane).

Capture stops for a few seconds while the container restarts. After a big update the first start can take longer on a large database (it re-identifies devices when the identification rules changed); follow it with `docker compose logs -f`. To pin a version instead of `latest`, use a release tag such as `ghcr.io/banaanga/sniffowireless:11`, which also makes going back easy.

### Remote sensors

A sensor keeps no data, so updating it means getting the new image and recreating its container with the same settings. Update the **server first**: a newer server works with older sensors, while a newer sensor can send things an older server doesn't know yet. Features that need both ends, such as [changing channels from the web UI](sensors.md#wi-fi-channels-from-the-web-ui), work once both are updated.

The token in the `docker run` command is shown only once, so keep your sensor's command. The simplest way to make later updates a one-liner is to run the sensor from a small compose file on the sensor machine instead (for example `~/sniffowireless-sensor/docker-compose.yml`):

```yaml
services:
  sniffowireless-sensor:
    image: ghcr.io/banaanga/sniffowireless:latest
    container_name: sniffowireless-sensor
    restart: unless-stopped
    network_mode: host
    privileged: true
    environment:
      SNIFFOWIRELESS_MODE: sensor
      SERVER_URL: http://192.168.1.10:8080
      SENSOR_TOKEN: sniffowireless_...
      WIFI_INTERFACES: wlan1
      BT_DEVICES: hci0
```

Start it once (`docker rm -f sniffowireless-sensor` first if you ran it with `docker run` before), and from then on:

```bash
docker compose pull && docker compose up -d
```

If you run the sensor with plain `docker run`, update it like this:

```bash
docker pull ghcr.io/banaanga/sniffowireless:latest
```

```bash
docker rm -f sniffowireless-sensor
```

and then run the same `docker run` command as when you set it up (the one in [Multiple sensors & the map](sensors.md#multiple-sensors--the-map)). If you built the image from source on the sensor, run `git pull` and `docker build -t sniffowireless:latest .` instead of the pull.

The sensor is down for a few seconds, and whatever it had not yet sent (at most a couple of seconds of captures) is lost. Afterwards check **Settings → Sensors**, where it should show as online with a recent *last report*, or `docker logs sniffowireless-sensor` on the sensor machine. Old images pile up over time: `docker image prune` removes the ones no container uses.
