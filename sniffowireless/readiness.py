"""Client readiness: what the clients of my networks can do, and which of them a change would leave behind.

Every client says what it can do in its probe and association requests (identify.wifi_fingerprint and wifiattrs.client_caps):
the Wi-Fi generation, spatial streams, channel width, the bands (its operating classes), 802.11k/v/r, and in an association
request the key management it chose and whether it does management frame protection (PMF). From that, per question:

* WPA3 only: clients that chose WPA2 (PSK) on a network that also offered WPA3 can't do WPA3; those that chose SAE can.
* No more 2.4 GHz: clients that show no sign of 5 GHz (Wi-Fi 5 or newer, a 5 GHz operating class, or ever heard on 5 or 6 GHz).
* 6 GHz: clients with a 6 GHz operating class, Wi-Fi 6E, or ever heard on 6 GHz.
* PMF required: clients that do not do PMF.
* No 802.11b rates: clients that offer nothing but 802.11b rates.

A client that never sent the element a question needs is "not known", not a yes or a no.
"""
import json
import time

from fastapi import APIRouter, Depends

from .auth import current_user

SAE = {"SAE", "FT-SAE", "SAE-EXT", "FT-SAE-EXT"}
PSK = {"PSK", "FT-PSK", "PSK-SHA256", "PSK-SHA384", "FT-PSK-SHA384"}
GEN_LABEL = {7: "Wi-Fi 7", 66: "Wi-Fi 6E", 6: "Wi-Fi 6", 5: "Wi-Fi 5", 4: "Wi-Fi 4", 3: "802.11a/b/g"}


def _caps(dev):
    try:
        ident = json.loads(dev["ident"] or "{}")
    except ValueError:
        ident = {}
    wc = ident.get("wifi_caps") or {}
    return wc, wc.get("capinfo") or {}


def assess(dev, wc, ci, used_sae, offered_sae, bands_seen):
    caps = set(ci.get("caps") or [])
    opcls = set(ci.get("opcls") or [])
    akm = set(ci.get("akm") or [])
    gen = dev["wifi_gen"]
    # Wi-Fi 5 and newer always do 5 GHz; a Wi-Fi 4 or older client only says so with its operating classes (or by being heard there)
    five = True if (gen and gen >= 5) or opcls & set(range(115, 131)) or bands_seen & {"5", "6"} else (False if opcls else None)
    six = True if gen == 66 or opcls & set(range(131, 138)) or "6" in bands_seen else (False if opcls or (gen and gen <= 5) else None)
    if used_sae or akm & SAE:
        wpa3 = True
    elif akm & PSK and offered_sae:
        wpa3 = False   # it was offered WPA3 and chose WPA2
    else:
        wpa3 = None
    pmf = {"required": True, "optional": True, "off": False}.get(ci.get("pmf"))
    return {"gen": gen, "gen_label": GEN_LABEL.get(gen), "ss": wc.get("ss"), "width": wc.get("width"), "five": five, "six": six,
            "wpa3": wpa3, "pmf": pmf, "b_only": True if ci.get("b_only") else (False if ci.get("dsss") is not None else None),
            "k": "802.11k radio measurement" in caps, "v": "802.11v BSS transition" in caps, "r": "802.11r fast roaming" in caps}


def analyze(ctx, since):
    n = ctx.settings.get("networks")
    my_ssids, trusted = set(n["ssids"]), set(n["trusted_bssids"])
    mine = {r["mac"]: r for r in ctx.rows("SELECT mac, ssid, extra FROM devices WHERE kind='ap'")
            if r["ssid"] in my_ssids and (not trusted or r["mac"] in trusted)}
    offered_sae = False
    for r in mine.values():
        try:
            akms = set(((json.loads(r["extra"] or "{}").get("ap") or {}).get("rsn") or {}).get("akm") or [])
        except ValueError:
            akms = set()
        offered_sae |= bool(akms & SAE)
    if mine:
        q = f"SELECT DISTINCT mac FROM sessions WHERE type='assoc' AND end_ts >= ? AND peer IN ({','.join('?' * len(mine))})"
        macs = [r["mac"] for r in ctx.rows(q, [since, *mine])]
    else:
        macs = [r["mac"] for r in ctx.rows("SELECT DISTINCT mac FROM sessions WHERE type='assoc' AND end_ts >= ?", (since,))]
    if not macs:
        return {"clients": [], "questions": [], "summary": {}, "scope": "mine" if mine else "all", "offered_sae": offered_sae}
    ph = ",".join("?" * len(macs))
    devs = {d["mac"]: d for d in ctx.rows(f"SELECT mac, name, vendor, brand, model, dev_type, wifi_gen, ident, band FROM devices WHERE mac IN ({ph})", macs)}
    bands = {}
    for r in ctx.rows(f"SELECT s.mac, d.band FROM sessions s JOIN devices d ON d.mac = s.peer WHERE s.type='assoc' AND s.mac IN ({ph})", macs):
        bands.setdefault(r["mac"], set()).add(r["band"])
    sae_users = set()
    try:
        sae_users = {r["mac"] for r in ctx.rows(f"SELECT DISTINCT mac FROM join_events WHERE step='auth' AND algo=3 AND mac IN ({ph})", macs)}
    except Exception:
        pass   # no connection steps table (an older database)
    clients = []
    for mac in macs:
        d = devs.get(mac)
        if not d:
            continue
        wc, ci = _caps(d)
        a = assess(d, wc, ci, mac in sae_users, offered_sae, bands.get(mac, set()) | ({d["band"]} if d["band"] else set()))
        a.update(mac=mac, name=d["name"] or " ".join(x for x in (d["brand"], d["model"]) if x) or d["vendor"], type=d["dev_type"])
        clients.append(a)

    def question(key, title, field, bad, explain):
        drop = [c for c in clients if c[field] is bad]
        unknown = [c for c in clients if c[field] is None]
        return {"key": key, "title": title, "explain": explain, "ready": len(clients) - len(drop) - len(unknown), "drop": len(drop),
                "unknown": len(unknown), "drop_clients": [{k: c[k] for k in ("mac", "name", "type", "gen_label")} for c in drop][:50]}

    questions = [
        question("wpa3", "WPA3 only", "wpa3", False,
                 "Clients that chose WPA2 where WPA3 was offered too would no longer connect. Known only for clients that connected to a "
                 "network that offers WPA3 (transition mode)." if offered_sae else
                 "Your networks don't offer WPA3 yet, so it is only known for clients that used WPA3 elsewhere. Switching to WPA3 + WPA2 "
                 "transition mode first shows which clients choose WPA3."),
        question("no24", "No more 2.4 GHz", "five", False, "Clients with no sign of 5 GHz support would lose the network."),
        question("six", "6 GHz", "six", False, "Clients that can use a 6 GHz network (Wi-Fi 6E or 7). The others stay on 2.4 / 5 GHz."),
        question("pmf", "PMF required", "pmf", False, "Clients without management frame protection could no longer connect. Required for WPA3."),
        question("nob", "No 802.11b rates", "b_only", True,
                 "Clients that offer nothing but 802.11b rates (1–11 Mb/s) would lose the network when 12 Mb/s is the lowest basic rate."),
    ]
    questions[2]["ready"], questions[2]["drop"] = sum(1 for c in clients if c["six"]), sum(1 for c in clients if c["six"] is False)

    def count(field, fmt=str):
        out = {}
        for c in clients:
            k = fmt(c[field]) if c[field] is not None else "not known"
            out[k] = out.get(k, 0) + 1
        return out
    summary = {"generations": count("gen_label"), "streams": count("ss"), "widths": count("width", lambda w: f"{w} MHz"),
               "roaming": {"802.11k": sum(c["k"] for c in clients), "802.11v": sum(c["v"] for c in clients), "802.11r": sum(c["r"] for c in clients)}}
    return {"clients": sorted(clients, key=lambda c: (c["gen"] or 0, c["name"] or "")), "questions": questions, "summary": summary,
            "scope": "mine" if mine else "all", "offered_sae": offered_sae}


def routes(ctx):
    r = APIRouter()

    @r.get("/api/readiness")
    def readiness(days: float = 30, _=Depends(current_user)):
        """What the clients of my networks (seen connected in the last `days`) can do, and who each change would leave behind."""
        return analyze(ctx, time.time() - days * 86400)

    return r
