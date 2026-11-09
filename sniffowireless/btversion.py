"""Which Bluetooth version a device implements, as far as a passive listener can tell.

Almost nothing in an advertisement says "Bluetooth 5.2". There are two sources, and the label says which one it is:

* **Exact** ("5.4"): the host's own Bluetooth stack asked the device (Read Remote Version Information) because the device
  is connected to the machine the adapter is in. Only those devices have it.
* **At least** ("5.2+"): the strongest feature the device advertises, since a feature exists only from a given Core
  version on: extended advertising (5.0), an LE Audio broadcast (5.2), encrypted advertising data and Electronic Shelf
  Labels (both 5.4). A device that advertises only the old way is "4.0+", the first version with LE at all.

Classic (BR/EDR) devices have nothing to go on until something connects to them, so they stay unknown.
"""

BASIS_REPORTED = "reported by the device"


def _key(label):
    try:
        major, _, minor = label.rstrip("+").partition(".")
        return int(major), int(minor)
    except ValueError:
        return (0, 0)


def derive(kind, extra):
    """(label, basis) for a Bluetooth device's `extra` dict, or None when nothing is known."""
    reported = extra.get("bt_version")
    if isinstance(reported, str) and reported:
        return reported, BASIS_REPORTED
    best = None
    for have, version, why in ((kind == "ble", "4.0", "LE advertising"),
                               (extra.get("ext_adv") or extra.get("phy"), "5.0", "extended advertising"),
                               (extra.get("auracast"), "5.2", "LE Audio broadcast"),
                               (extra.get("encrypted_ad"), "5.4", "encrypted advertising data"),
                               (extra.get("esl"), "5.4", "Electronic Shelf Label advertising")):
        if have and (best is None or _key(version) > _key(best[0])):
            best = (version, why)
    return (best[0] + "+", best[1]) if best else None


def apply(kind, extra):
    """Set bt_ver / bt_basis in `extra` from what it holds. True when something changed."""
    found = derive(kind, extra)
    if not found:
        return False
    if extra.get("bt_ver") == found[0] and extra.get("bt_basis") == found[1]:
        return False
    extra["bt_ver"], extra["bt_basis"] = found
    return True
