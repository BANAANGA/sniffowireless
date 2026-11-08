FROM python:3.12-slim

# apt-get upgrade pulls in Debian security fixes (zlib1g: CVE-2026-76844, CVE-2026-85091, CVE-2026-27171) that the base image
# has not picked up yet. pip is upgraded for its own advisories (pip is only used at build time, but it ships in the image).
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends iw iproute2 wireless-tools rfkill usbutils tcpdump curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade "pip>=26.1.2" \
 && pip install --no-cache-dir -r requirements.txt

# OUI vendor database + charting library, fetched at build time so the UI works offline.
RUN mkdir -p /app/data /app/vendor \
 && (curl -fsSL --retry 3 https://www.wireshark.org/download/automated/data/manuf -o /app/data/manuf \
     || echo "WARNING: could not download OUI database; vendor names will be unavailable") \
 && (curl -fsSL --retry 3 https://cdn.jsdelivr.net/npm/chart.js@4.4.6/dist/chart.umd.min.js -o /app/vendor/chart.umd.min.js \
     || echo "WARNING: could not download Chart.js; the UI will load it from the CDN") \
 && (curl -fsSL --retry 3 https://cdn.jsdelivr.net/npm/esptool-js@0.5.7/bundle.js -o /app/vendor/esptool.bundle.js \
     || echo "WARNING: could not download esptool-js; the LoRa flasher will load it from the CDN") \
 && (curl -fsSL --retry 3 https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.js -o /app/vendor/qrcode.js \
     || echo "WARNING: could not download qrcode-generator; the two-factor setup will load it from the CDN")

COPY sniffowireless /app/sniffowireless

# Which build this is (shown on Settings -> About and in a sensor's report). Last, so a new commit doesn't redo the layers above.
ARG VERSION=dev
ARG COMMIT=
ARG BUILD_DATE=
ENV SNIFFOWIRELESS_VERSION=$VERSION \
    SNIFFOWIRELESS_COMMIT=$COMMIT \
    SNIFFOWIRELESS_BUILD_DATE=$BUILD_DATE

ENV DB_PATH=/data/sniffowireless.db \
    WEB_PORT=8080 \
    PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
  CMD curl -fs "http://127.0.0.1:${WEB_PORT}/api/health" || exit 1

CMD ["python", "-m", "sniffowireless"]
