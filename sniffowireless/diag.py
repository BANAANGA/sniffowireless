"""Wi-Fi capture diagnostics: tune an adapter to each channel, listen briefly and report what arrives.

    docker compose stop sniffowireless
    docker compose run --rm sniffowireless python -m sniffowireless.diag                 # 6 GHz PSC channels on WIFI_INTERFACES[0]
    docker compose run --rm sniffowireless python -m sniffowireless.diag wlan1 --channels 6g:37,36,6 --dwell 5
    docker compose start sniffowireless

Stop the running sniffowireless first: it hops the same adapter and would retune it under this test.
"""
import argparse
import collections
import os
import platform
import re
import sys
import time

from .config import Config, band_of, chan_label, parse_channels


def main(argv=None):
    from scapy.all import sniff
    from scapy.layers.dot11 import Dot11

    from .wifi import (_radio, ensure_monitor, global_regdomain, parse_frame, regulatory_warning, run_cmd, set_freq,
                       set_regdomain)

    cfg = Config.from_env()
    ap = argparse.ArgumentParser(prog="python -m sniffowireless.diag", description=__doc__.split("\n\n")[0])
    ap.add_argument("iface", nargs="?", default=(cfg.wifi_interfaces or [None])[0])
    ap.add_argument("--channels", default="6ghz", help="channel spec as in WIFI_CHANNELS (default: 6ghz)")
    ap.add_argument("--dwell", type=float, default=3.0, help="seconds per channel (default 3)")
    a = ap.parse_args(argv)
    if not a.iface:
        sys.exit("No interface: pass one or set WIFI_INTERFACES")

    print(f"kernel {platform.release()}")
    try:
        drv = os.path.basename(os.readlink(f"/sys/class/net/{a.iface}/device/driver"))
        phy = os.path.basename(os.readlink(f"/sys/class/net/{a.iface}/phy80211"))
        print(f"{a.iface}: driver {drv}, {phy}")
    except OSError:
        phy = None
        print(f"{a.iface}: driver unknown (interface missing?)")
    if cfg.wifi_regdomain:
        set_regdomain(cfg.wifi_regdomain)
        time.sleep(2)
    print("regulatory domain:", " / ".join(re.findall(r"country (\S+?):", run_cmd("iw", "reg", "get")[1])) or "?")
    hint = regulatory_warning(global_regdomain(), cfg.wifi_regdomain,
                              any(band_of(f) == "6" for f in parse_channels(a.channels)))
    if hint:
        print("  !", hint)
    if phy:
        info = run_cmd("iw", "phy", phy, "info")[1]
        six = re.findall(r"\* (59[5-9]\d|6\d{3}|70\d\d|71[01]\d)(?:\.\d+)? MHz \[(\d+)\](.*)", info)
        usable = [c for _, c, rest in six if "disabled" not in rest]
        print(f"6 GHz channels in phy info: {len(six)}, enabled: {len(usable)}"
              + (f" ({','.join(usable[:12])}{'…' if len(usable) > 12 else ''})" if usable else ""))
        print("monitor mode supported:", "yes" if re.search(r"Supported interface modes:(?:\n\s+\*.*)*\n\s+\* monitor", info) else "no")

    mon = ensure_monitor(a.iface, True)
    print(f"capturing on {mon}\n")
    print(f"{'channel':>8} {'tune':>4} {'frames':>7} {'beacons':>7} {'APs':>4} {'clients':>7}  radiotap MHz seen / SSIDs")
    total = collections.Counter()
    for f in parse_channels(a.channels):
        ok, out = set_freq(mon, f)
        if not ok:
            print(f"{chan_label(f):>8} {'FAIL':>4}  {out.strip()[:90]}")
            continue
        time.sleep(0.2)
        st = {"frames": 0, "beacons": 0, "rt": collections.Counter(), "aps": set(), "clients": set(), "ssids": set()}

        def handle(pkt, f=f, st=st):
            if not pkt.haslayer(Dot11):
                return
            st["frames"] += 1
            rt = _radio(pkt)[1]
            st["rt"][rt] += 1
            d = pkt[Dot11]
            if d.type == 0 and d.subtype == 8:
                st["beacons"] += 1
            for o in parse_frame(pkt, None, f):
                if o["t"] == "wifi_ap":
                    st["aps"].add(o["mac"])
                    if o.get("ssid"):
                        st["ssids"].add(o["ssid"])
                elif o["t"] == "wifi_client":
                    st["clients"].add(o["mac"])

        sniff(iface=mon, prn=handle, store=False, timeout=a.dwell)
        rts = ", ".join(f"{k or 'none'}×{v}" for k, v in st["rt"].most_common(3))
        wrong = sum(v for k, v in st["rt"].items() if k and band_of(k) != band_of(f))
        print(f"{chan_label(f):>8} {'ok':>4} {st['frames']:>7} {st['beacons']:>7} {len(st['aps']):>4} {len(st['clients']):>7}  "
              f"{rts or '-'}{'  ← driver reports another band' if wrong else ''}"
              + (f"\n{'':>36}{', '.join(sorted(st['ssids']))[:120]}" if st["ssids"] else ""))
        total.update({"frames": st["frames"], "aps": len(st["aps"]), "wrong": wrong})
    print()
    if not total["frames"]:
        print("No frames at all on these channels. The adapter tunes but receives nothing: typical for a driver/"
              "firmware without 6 GHz monitor support (update the kernel and linux-firmware), an antenna problem, "
              "or no 6 GHz transmitters on these channels.")
    elif not total["aps"]:
        print("Frames arrive but none are beacons from access points; try a longer --dwell or other channels.")
    else:
        print(f"OK: {total['aps']} access point(s) seen." + (" The driver mislabels the frequency; sniffowireless now corrects "
                                                             "this." if total["wrong"] else ""))


if __name__ == "__main__":
    main()
