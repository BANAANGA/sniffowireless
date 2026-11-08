#!/usr/bin/env python3
"""Build firmware/lora-sniffer and store it as one flashable image for the web flasher (Settings -> LoRa flasher).

    python3 scripts/build_firmware.py

Needs PlatformIO (`pip install platformio`). Writes sniffowireless/firmware/lora-sniffer-heltec-v3.bin (the whole flash
from address 0: bootloader, partition table, boot_app0 and the application) and firmware.json next to it. The manifest
records a hash of the firmware source, and a test fails when the source changes without this script being run again.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "firmware" / "lora-sniffer"
OUT = ROOT / "sniffowireless" / "firmware"
NAME = "lora-sniffer-heltec-v3"
ENV = "heltec_v3"


def source_hash():
    h = hashlib.sha256()
    for f in sorted([SRC / "platformio.ini", *(SRC / "src").glob("*")]):
        h.update(f.name.encode() + b"\0" + f.read_bytes() + b"\0")
    return h.hexdigest()


def firmware_version():
    m = re.search(r"FW_VERSION\s*=\s*(\d+)", (SRC / "src" / "main.cpp").read_text())
    if not m:
        sys.exit("FW_VERSION not found in main.cpp")
    return int(m.group(1))


def run(cmd, **kw):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    subprocess.run([str(c) for c in cmd], check=True, **kw)


def main():
    pio = shutil.which("pio") or shutil.which("platformio")
    if not pio:
        sys.exit("PlatformIO not found: pip install platformio")
    with tempfile.TemporaryDirectory() as build:
        env = {**os.environ, "PLATFORMIO_BUILD_DIR": build}
        run([pio, "run", "-d", SRC], env=env)
        out = Path(build) / ENV
        home = Path(json.loads(subprocess.check_output([pio, "system", "info", "--json-output"], text=True))["core_dir"]["value"])
        boot_app0 = next((home / "packages").glob("framework-arduinoespressif32*/tools/partitions/boot_app0.bin"))
        esptool = next((home / "packages").glob("tool-esptoolpy*/esptool.py"))
        OUT.mkdir(exist_ok=True)
        image = OUT / f"{NAME}.bin"
        run([sys.executable, esptool, "--chip", "esp32s3", "merge_bin", "-o", image, "--flash_mode", "keep", "--flash_freq", "keep",
             "--flash_size", "8MB", "0x0", out / "bootloader.bin", "0x8000", out / "partitions.bin", "0xe000", boot_app0,
             "0x10000", out / "firmware.bin"])
    data = image.read_bytes()
    manifest = {"name": NAME, "title": "LoRa sniffer for the Heltec WiFi LoRa 32 V3", "chip": "ESP32-S3", "version": firmware_version(), "address": 0, "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(), "source_sha256": source_hash(), "built": time.strftime("%Y-%m-%d", time.gmtime()),
                "file": image.name}
    (OUT / "firmware.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"{image} {len(data)} bytes, sha256 {manifest['sha256'][:12]}")


if __name__ == "__main__":
    main()
