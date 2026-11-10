"""MAC vendor (OUI) and Bluetooth company identifier lookups."""
import json
import logging
import os

log = logging.getLogger("sniffowireless.oui")

# Small subset of Bluetooth SIG company identifiers seen most often in the wild.
BT_COMPANIES = {
    0x0006: "Microsoft", 0x000F: "Broadcom", 0x001D: "Qualcomm", 0x004C: "Apple",
    0x0059: "Nordic Semiconductor", 0x0075: "Samsung", 0x0087: "Garmin",
    0x009E: "Bose", 0x00C4: "LG Electronics", 0x00D2: "Dialog Semiconductor",
    0x00E0: "Google", 0x00ED: "Tile", 0x010F: "Huawei", 0x0131: "Cypress",
    0x0157: "Anhui Huami (Amazfit)", 0x0171: "Amazon", 0x0180: "Gigaset",
    0x01DA: "Logitech", 0x0225: "Nike", 0x02E5: "Espressif", 0x0301: "Sennheiser",
    0x038F: "Xiaomi", 0x0499: "Ruuvi", 0x04F7: "Govee", 0x05A7: "Sonos",
    0x0822: "adidas", 0x0D80: "Fitbit", 0x0310: "SGL Italia", 0x0078: "Nike",
    0x0001: "Nokia", 0x000A: "Qualcomm (CSR)", 0x0002: "Intel", 0x005D: "Realtek",
    0x0046: "MediaTek", 0x0030: "ST Microelectronics", 0x0047: "Bluegiga",
    0x02FF: "Silicon Labs", 0x0397: "LEGO", 0x0154: "Pebble", 0x0067: "GN Netcom (Jabra)",
    0x0057: "Harman", 0x00F0: "Belkin", 0x01A9: "Canon", 0x0434: "Hu-Do",
}


def _load_companies():
    """Full Bluetooth SIG company list (bundled); the short names above win where both exist."""
    try:
        with open(os.path.join(os.path.dirname(__file__), "data", "bt_companies.json"), encoding="utf-8") as f:
            full = {int(k, 16): v for k, v in json.load(f).items()}
    except (OSError, ValueError):
        log.warning("Bluetooth company list not found; only common vendors are named")
        full = {}
    full.update(BT_COMPANIES)
    return full


_COMPANIES = _load_companies()


def bt_company(cid):
    if cid is None:
        return None
    return _COMPANIES.get(cid, f"Company 0x{cid:04X}")


class VendorLookup:
    """Lookup of IEEE OUI assignments using Wireshark's `manuf` file."""

    def __init__(self, path):
        self.tables = {24: {}, 28: {}, 36: {}}
        if path and os.path.exists(path):
            self._load(path)
        else:
            log.warning("OUI database %s not found; vendor names unavailable", path)

    def _load(self, path):
        n = 0
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip() or line.startswith("#"):
                    continue
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 2:
                    continue
                prefix = parts[0].strip()
                name = (parts[2] if len(parts) > 2 and parts[2].strip() else parts[1]).strip()
                bits = 24
                if "/" in prefix:
                    prefix, b = prefix.split("/", 1)
                    try:
                        bits = int(b)
                    except ValueError:
                        continue
                hexs = prefix.replace(":", "").replace("-", "").upper()
                if bits not in self.tables:
                    continue
                self.tables[bits][hexs[: bits // 4]] = name
                n += 1
        log.info("Loaded %d OUI entries", n)

    def lookup(self, mac):
        if not mac:
            return None
        h = mac.replace(":", "").upper()
        for bits in (36, 28, 24):
            v = self.tables[bits].get(h[: bits // 4])
            if v:
                return v
        return None
