"""Which Bluetooth version a device implements, as far as a passive listener can tell.

Almost nothing in an advertisement says "Bluetooth 5.2". There are two sources, and the label says which one it is:

* **Exact** ("5.4"): the host's own Bluetooth stack asked the device (Read Remote Version Information) because the device
  is connected to the machine the adapter is in. Only those devices have it.
* **From the model** ("5.3"): the manufacturer's published specification of a model the identifier recognises (MODEL_VERSIONS).
  A list I could check against the maker's own pages, so it is short; a model that is not in it is simply not looked up.
* **At least** ("5.2+"): the strongest feature the device advertises, since a feature exists only from a given Core
  version on: extended advertising (5.0), an LE Audio broadcast (5.2), encrypted advertising data and Electronic Shelf
  Labels (both 5.4). A device that advertises only the old way is "4.0+", the first version with LE at all.

Classic (BR/EDR) devices have nothing to go on until something connects to them, so they stay unknown.
"""

BASIS_REPORTED = "reported by the device"

# Services that only exist with LE Audio (Core 5.2): Volume Control, Coordinated Set Identification, Audio Stream Control,
# Published Audio Capabilities, Common Audio and Telephony and Media Audio. A device that lists one in its advertisement has them.
LE_AUDIO_SERVICES = {"1844", "1846", "184e", "1850", "1853", "1855"}

# Model name (as identify.py names it) -> (Bluetooth version, where it is published). Only versions confirmed on the maker's
# own specification page, or by a teardown, are listed: a wrong entry would be shown as fact.
MODEL_VERSIONS = {
    "AirPods": ("4.2", "Wikipedia, AirPods (1st generation)"),
    "AirPods (2nd gen)": ("5.0", "support.apple.com / apple.com/airpods-2nd-generation/specs"),
    "AirPods (3rd gen)": ("5.0", "apple.com/airpods-3rd-generation/specs"),
    "AirPods Pro (2nd gen)": ("5.3", "support.apple.com/111851"),
    "AirPods Pro (2nd gen, USB-C)": ("5.3", "support.apple.com/111834"),
}


def _key(label):
    try:
        major, _, minor = label.rstrip("+").partition(".")
        return int(major), int(minor)
    except ValueError:
        return (0, 0)


def derive(kind, extra, model=None):
    """(label, basis) for a Bluetooth device's `extra` dict (and the model identify.py named, if any), or None when nothing is known."""
    reported = extra.get("bt_version")
    if isinstance(reported, str) and reported:
        return reported, BASIS_REPORTED
    best = None
    for have, version, why in ((kind == "ble", "4.0", "LE advertising"),
                               (extra.get("ext_adv") or extra.get("phy"), "5.0", "extended advertising"),
                               (extra.get("auracast"), "5.2", "LE Audio broadcast"),
                               (LE_AUDIO_SERVICES.intersection(extra.get("uuids") or ()), "5.2", "LE Audio services"),
                               (extra.get("encrypted_ad"), "5.4", "encrypted advertising data"),
                               (extra.get("esl"), "5.4", "Electronic Shelf Label advertising")):
        if have and (best is None or _key(version) > _key(best[0])):
            best = (version, why)
    spec = MODEL_VERSIONS.get(model)
    if spec and (best is None or _key(spec[0]) >= _key(best[0])):  # a spec lower than what the device does is not credible
        return spec[0], f"manufacturer's specification for the {model}"
    return (best[0] + "+", best[1]) if best else None


def apply(kind, extra, model=None):
    """Set bt_ver / bt_basis in `extra` from what it holds. True when something changed."""
    found = derive(kind, extra, model)
    if not found:
        return False
    if extra.get("bt_ver") == found[0] and extra.get("bt_basis") == found[1]:
        return False
    extra["bt_ver"], extra["bt_basis"] = found
    return True
