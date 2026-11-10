"""Access point models of TP-Link, Ubiquiti and HPE Aruba, from the text an AP announces about itself.

Where the text comes from (all of it is broadcast by the AP; nothing is sent):
* the vendor-specific "AP name" element in beacons - Ubiquiti (OUI 00:15:6d, type 1) and Aruba (OUI 00:0b:86, subtype 3); the layouts
  are the ones Wireshark decodes (epan/dissectors/packet-ieee80211.c, dissect_vendor_ie_ubiquiti / dissect_vendor_ie_aruba);
* the WPS model name / number / device name of routers that broadcast WPS (many TP-Link units do);
* the network name and any LLDP system name.

A name is only a name: an administrator can call an access point anything. So a model is only claimed when the text matches the
maker's own naming, and when the Wi-Fi generation that model has (where it is certain) agrees with what the beacons advertise: an AP
called "U6 Pro" that shows no Wi-Fi 6 capabilities is not reported as one.
"""
import re

AP_NAME_MAX = 48
# Aruba's published model numbers (campus / Instant access points). A bare "AP-101" is an administrator's room number, not a model.
ARUBA_MODELS = {
    "103", "105", "114", "115", "124", "125", "134", "135", "175", "203", "205", "207", "214", "215", "224", "225", "228", "274", "275", "277",
    "303", "304", "305", "314", "315", "318", "324", "325", "334", "335", "344", "345", "365", "367", "374", "375", "377", "387",
    "503", "504", "505", "509", "514", "515", "518", "534", "535", "555", "565", "567", "575", "577", "584", "585", "587",
    "615", "635", "655", "675",
}


def _flags(rx):
    return re.compile(rx, re.I)


WORDS = {"lite": "Lite", "lr": "LR", "pro": "Pro", "hd": "HD", "shd": "SHD", "m": "M", "iw": "IW", "mesh": "Mesh", "outdoor": "Outdoor",
         "outdoor+": "Outdoor+", "max": "Max", "wall": "Wall", "xg": "XG", "enterprise": "Enterprise", "extender": "Extender"}


def _words(text, sep):
    return sep.join(WORDS.get(w.lower(), w) for w in re.split(r"[- _]+", text.strip()) if w)


def _ubnt_u(m):
    return "U" + m.group(1) + " " + _words(m.group(2), " ")


def _ubnt_uap(m):
    return "UAP-" + ("AC-" if m.group(1) else "") + _words(m.group(2), "-")


def _archer(m):
    return "Archer " + m.group(1).upper()


def _aruba(m):
    num = m.group(1).upper()
    return "AP-" + num


def _deco(m):
    return "Deco " + m.group(1).upper()


# (compiled regex, brand, model formatter, product line, expected Wi-Fi generation or None / callable(match) -> generation)
RULES = [
    (_flags(r"\b(?:UniFi[ _-]*)?U([67])[- _](Lite|LR|Pro(?:[- _](?:Max|Wall|XG))?|Mesh|Enterprise(?:[- _]IW)?|IW|Outdoor|Extender|XG)\b"),
     "Ubiquiti", _ubnt_u, "UniFi", lambda m: int(m.group(1))),
    (_flags(r"\b(?:UniFi[ _-]*)?UAP[- _](AC[- _])?(Lite|LR|Pro|HD|SHD|M[- _]Pro|M|IW[- _]Pro|IW|Mesh[- _]Pro|Mesh|Outdoor\+?)\b"),
     "Ubiquiti", _ubnt_uap, "UniFi", lambda m: 5 if m.group(1) else 4),
    (_flags(r"\b(nanoHD|FlexHD|BeaconHD)\b"), "Ubiquiti", lambda m: {"nanohd": "nanoHD", "flexhd": "FlexHD", "beaconhd": "BeaconHD"}[m.group(1).lower()],
     "UniFi", 5),
    (_flags(r"\b(NanoStation|NanoBeam|LiteBeam|PowerBeam|airCube)(?:[- _]?(AC|5AC|M\d|Loco\w*|Gen2))?\b"), "Ubiquiti",
     lambda m: (m.group(1) + (" " + m.group(2) if m.group(2) else "")), "airMAX / airCube", None),
    (_flags(r"\bArcher[ _-]?([A-Z]{1,3}\d{1,5}[A-Za-z]*)"), "TP-Link", _archer, "Archer",
     lambda m: 7 if m.group(1).upper().startswith("BE") else 6 if m.group(1).upper().startswith(("AX", "GX")) else None),
    (_flags(r"\b(TL-(?:WR|WA|WDR|MR|WPA|ER|SG|SL|SF|PA)\d{2,5}[A-Za-z]*)\b"), "TP-Link", lambda m: m.group(1).upper(), "TL-", None),
    (_flags(r"\bEAP[ -]?(\d{3}[A-Za-z]*(?:-(?:Outdoor|Wall))?)\b"), "TP-Link", lambda m: "EAP" + re.sub(r"-(outdoor|wall)$", lambda x: "-" + x.group(1).capitalize(), m.group(1).upper(), flags=re.I).replace("-OUTDOOR", "-Outdoor").replace("-WALL", "-Wall"), "Omada",
     lambda m: 4 if m.group(1).startswith("11") else 5 if m.group(1)[0] == "2" else 6 if m.group(1)[0] == "6" else None),
    (_flags(r"\bDeco[ _-]?((?:X|XE|BE|M|E)\d{1,3}[A-Za-z]*)\b"), "TP-Link", _deco, "Deco",
     lambda m: 7 if m.group(1).upper().startswith("BE") else 6 if m.group(1).upper().startswith("X") else 5),
]
ARUBA_RX = _flags(r"\b(?:Aruba[ _-]*)?(?:IAP|AP)[ _-]?(\d{3})([A-Z]{0,2})\b")


def recognize(text):
    """(brand, model, product line, expected Wi-Fi generation or None) when `text` contains a model name, else None."""
    if not text or len(text) > 160:
        return None
    for rx, brand, fmt, line, gen in RULES:
        m = rx.search(text)
        if m:
            return brand, fmt(m), line, gen(m) if callable(gen) else gen
    m = ARUBA_RX.search(text)
    if m and m.group(1) in ARUBA_MODELS:
        num = m.group(1)
        return "HPE Aruba", "AP-" + num + m.group(2).upper(), "Aruba", 6 if num[0] in "56" else None
    return None


def clean_name(raw):
    """The AP name from a vendor element: printable text only, trimmed and bounded."""
    s = bytes(raw).decode("utf-8", "replace").replace("\x00", "").strip()
    s = "".join(ch for ch in s if ch.isprintable())
    return s[:AP_NAME_MAX] or None


def vendor_ap_name(info):
    """(vendor, name or None, aruba subtype or None) from a vendor-specific element body (OUI first); None if it is neither."""
    oui = bytes(info[:3])
    if oui == b"\x00\x15\x6d" and len(info) >= 5 and info[3] == 1:   # Ubiquiti: OUI, type 1 = AP name, the name
        return "Ubiquiti", clean_name(info[4:]), 1
    if oui == b"\x00\x0b\x86" and len(info) >= 5:                      # Aruba: OUI, type, subtype, [one byte], the name for subtype 3
        sub = info[4]
        return "Aruba", (clean_name(info[6:]) if sub == 3 and len(info) >= 7 else None), sub
    return None


ARUBA_SUBTYPES = {1: "CAC", 2: "Mesh", 3: "AP name", 4: "ARM (adaptive radio management)", 5: "SLB", 6: "SJ loop protect", 7: "Auto mesh", 8: "LCI",
                  9: "GPS ellipse", 10: "AP health"}


def model_evidence(ev, texts, observed_gen, hint_brand=None):
    """Add model evidence for the access point described by `texts` [(text, where, confidence)]. observed_gen: Wi-Fi generation the
    beacons advertise (None if unknown); a model whose generation is certain and differs is not claimed."""
    for text, where, conf in texts:
        found = recognize(text)
        if not found:
            continue
        brand, model, line, expected = found
        if expected is not None and observed_gen is not None and expected != observed_gen:
            ev.add("feature", f"{where} “{text}” looks like {brand} {model}, but the beacons show Wi-Fi {observed_gen}", 30, where)
            continue
        # a model name found in a name of the right brand is stronger than the same words in an unrelated one
        norm = lambda x: re.sub(r"[^a-z]", "", (x or "").lower())  # noqa: E731
        boost = 8 if norm(hint_brand) and (norm(hint_brand) in norm(brand) or norm(brand) in norm(hint_brand)) else 0
        src = f"{where} “{text}”"
        ev.add("brand", brand, min(88, conf + boost), src)
        ev.add("model", model, min(90, conf + boost), src)
        ev.add("type", "router", min(60, conf), src)
        return True
    return False
