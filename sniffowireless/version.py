"""Which version and build this process is.

An image is built with VERSION, COMMIT and BUILD_DATE build arguments (the release workflow sets them to the release
tag, the commit and the time), which the Dockerfile turns into the SNIFFOWIRELESS_* variables read here. Without them
(running from a checkout, tests) the version reads "dev"; a compose build from source says "source" unless told more.
"""
import os
import platform
import re
import sys
import time

REPO_URL = "https://github.com/BANAANGA/sniffowireless"
STARTED = time.time()
RELEASE_RX = re.compile(r"^v?\d+(\.\d+)*$")


def info():
    """{version, commit, built, release}: what was baked into this build, for the About page and sensor reports."""
    version = os.environ.get("SNIFFOWIRELESS_VERSION", "").strip() or "dev"
    return {"version": version[:40], "commit": os.environ.get("SNIFFOWIRELESS_COMMIT", "").strip()[:40],
            "built": os.environ.get("SNIFFOWIRELESS_BUILD_DATE", "").strip()[:40], "release": bool(RELEASE_RX.match(version))}


def runtime():
    return {"python": sys.version.split()[0], "platform": platform.platform(), "arch": platform.machine(), "started": STARTED}
