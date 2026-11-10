FROM python:3.12-slim

# apt-get upgrade pulls in Debian security fixes (zlib1g: CVE-2026-76844, CVE-2026-85091, CVE-2026-27171) that the base image
# has not picked up yet. pip is upgraded for its own advisories, then removed once the requirements are installed: it bundles an old setuptools (70.3.0) that scanners flag, and nothing needs it at runtime.
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends iw iproute2 wireless-tools rfkill usbutils tcpdump curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade "pip>=26.1.2" \
 && pip install --no-cache-dir -r requirements.txt \
 && pip uninstall -y pip

# OUI vendor database (optional) and the three browser libraries, fetched at build time so the UI works offline. The
# libraries are checked against pinned SHA-256 hashes: a changed or unreachable download fails the build, so an image
# never ships (or loads from a CDN at run time) a script nobody verified. Bumping a version means updating its hash here.
RUN mkdir -p /app/data /app/vendor \
 && (curl -fsSL --retry 3 https://www.wireshark.org/download/automated/data/manuf -o /app/data/manuf \
     || echo "WARNING: could not download OUI database; vendor names will be unavailable") \
 && curl -fsSL --retry 3 https://cdn.jsdelivr.net/npm/chart.js@4.4.6/dist/chart.umd.min.js -o /app/vendor/chart.umd.min.js \
 && curl -fsSL --retry 3 https://cdn.jsdelivr.net/npm/esptool-js@0.5.7/bundle.js -o /app/vendor/esptool.bundle.js \
 && curl -fsSL --retry 3 https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.js -o /app/vendor/qrcode.js \
 && cd /app/vendor && printf '%s  %s\n' \
      9653a0813db743bbe78332a3896e28c7bc7546e4fff51e7e979e908d1f0471d1 chart.umd.min.js \
      a2bc5bcbb3811e48781de165f2267f9c9c51e63fac7e8866765745e8a197cec0 esptool.bundle.js \
      18ae399f81182bc9de916e9c77b195df20cc58d6f2d55a62b085a299f1bf1780 qrcode.js | sha256sum -c -

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
