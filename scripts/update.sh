#!/usr/bin/env bash
# Update a build from source: pull the latest code and rebuild, recording which version this is so that
# Settings -> About (and a sensor's entry on Settings -> Sensors) show a real number instead of "source".
# Usage (from the repository folder):  ./scripts/update.sh
# Anything after the script name is passed to `docker compose up -d --build` (for example a service name).
set -euo pipefail
cd "$(dirname "$0")/.."

# Tags too: a release made on GitHub is a tag on a commit you may already have, which a plain pull doesn't fetch,
# and the version shown comes from the nearest tag.
git pull --tags --force
SNIFFOWIRELESS_VERSION="$(git describe --tags --always)" \
GIT_COMMIT="$(git rev-parse --short HEAD)" \
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  docker compose up -d --build "$@"

echo "Now running $(git describe --tags --always) ($(git rev-parse --short HEAD)). Check it under Settings -> About."
