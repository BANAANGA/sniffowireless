FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends iw iproute2 wireless-tools rfkill usbutils tcpdump curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# OUI vendor database + charting library, fetched at build time so the UI works offline.
RUN mkdir -p /app/data /app/vendor \
 && (curl -fsSL --retry 3 https://www.wireshark.org/download/automated/data/manuf -o /app/data/manuf \
     || echo "WARNING: could not download OUI database; vendor names will be unavailable") \
 && (curl -fsSL --retry 3 https://cdn.jsdelivr.net/npm/chart.js@4.4.6/dist/chart.umd.min.js -o /app/vendor/chart.umd.min.js \
     || echo "WARNING: could not download Chart.js; the UI will load it from the CDN")

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
