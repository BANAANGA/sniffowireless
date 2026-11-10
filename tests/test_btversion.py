"""The Bluetooth version of a device: exact when the host's stack read it, otherwise "at least" from the features it advertises."""
import json
import threading
import time

from sniffowireless.bluetooth import BluetoothSensor, parse_event
from sniffowireless.btversion import apply, derive
from sniffowireless.config import Config

from tests.test_bluetooth6 import Store, ad, ext_report
from tests.test_lora import ctx  # noqa: F401
from tests.test_lora_select import admin_client


def test_derive_from_the_evidence():
    assert derive("ble", {}) == ("4.0+", "LE advertising")
    assert derive("ble", {"ext_adv": True}) == ("5.0+", "extended advertising")
    assert derive("ble", {"phy": "Coded"})[0] == "5.0+"
    assert derive("ble", {"ext_adv": True, "auracast": {"name": "TV"}}) == ("5.2+", "LE Audio broadcast")
    assert derive("ble", {"ext_adv": True, "encrypted_ad": True, "auracast": {}}) == ("5.4+", "encrypted advertising data")
    assert derive("ble", {"esl": True})[0] == "5.4+"
    # a classic device has nothing to go on, and a reported version beats every inference, even a lower one
    assert derive("bt_classic", {"class": "phone"}) is None
    assert derive("bt_classic", {"bt_version": "5.2"}) == ("5.2", "reported by the device")
    assert derive("ble", {"bt_version": "4.2", "ext_adv": True, "encrypted_ad": True}) == ("4.2", "reported by the device")


def test_apply_reports_changes_only():
    ex = {"ext_adv": True}
    assert apply("ble", ex) is True and ex["bt_ver"] == "5.0+" and ex["bt_basis"] == "extended advertising"
    assert apply("ble", ex) is False
    ex["encrypted_ad"] = True
    assert apply("ble", ex) is True and ex["bt_ver"] == "5.4+"
    assert apply("bt_classic", {}) is False


def test_the_sensor_flags_extended_advertising():
    st = Store()
    sensor = BluetoothSensor("hci9", Config(), st)
    sensor.stop = threading.Event()
    (e,) = parse_event(ext_report(addr=b"\x11\x22\x33\x44\x55\xc6", data=ad((0x30, b"Stage"))))
    sensor._handle(e, 100.0)
    assert st[0]["extra"]["ext_adv"] is True
    (e,) = parse_event(ext_report(addr=b"\x11\x22\x33\x44\x55\xc7", prim=1, sec=2, evt=0x0010))  # a legacy PDU: not extended
    sensor._handle(e, 101.0)
    assert st[1]["extra"]["ext_adv"] is None and st[1]["extra"]["phy"] is None


def bt(mac, ts, kind="ble", **extra):
    return {"t": "bt", "kind": kind, "ts": ts, "mac": mac, "rssi": -60, "name": None, "randomized": False, "extra": extra}


def extra_of(ctx, mac):
    return json.loads(ctx.one("SELECT extra FROM devices WHERE mac=?", (mac,))["extra"])


def test_the_store_keeps_the_strongest_evidence_and_a_reported_version_wins(ctx):
    t = time.time()
    m = "aa:bb:cc:00:00:01"
    ctx.store.process(bt(m, t, connectable=True))
    ctx.store.flush()
    assert extra_of(ctx, m)["bt_ver"] == "4.0+"
    ctx.store.process(bt(m, t + 1, ext_adv=True, phy="1M"))
    ctx.store.process(bt(m, t + 2, connectable=True))            # a later legacy advert does not lower it
    ctx.store.flush()
    assert extra_of(ctx, m)["bt_ver"] == "5.0+"
    ctx.store.process(bt(m, t + 3, encrypted_ad=True))
    ctx.store.flush()
    assert extra_of(ctx, m)["bt_ver"] == "5.4+" and extra_of(ctx, m)["bt_basis"] == "encrypted advertising data"
    ctx.store.process(bt(m, t + 4, bt_version="5.2", chip="Intel"))
    ctx.store.flush()
    assert extra_of(ctx, m)["bt_ver"] == "5.2" and extra_of(ctx, m)["bt_basis"] == "reported by the device"
    c = "00:11:22:00:00:02"
    ctx.store.process(bt(c, t, kind="bt_classic", **{"class": "phone"}))
    ctx.store.flush()
    assert "bt_ver" not in extra_of(ctx, c)


def test_devices_stored_before_are_filled_in_once(ctx):
    ctx.execute("INSERT INTO devices(mac, kind, first_seen, last_seen, extra) VALUES('d0:00:00:00:00:01', 'ble', 1, ?, ?)",
                (time.time(), json.dumps({"phy": "2M", "auracast": {"name": "TV"}})))
    ctx.execute("INSERT INTO devices(mac, kind, first_seen, last_seen, extra) VALUES('d0:00:00:00:00:02', 'bt_classic', 1, ?, '{}')", (time.time(),))
    ctx.execute("DELETE FROM meta WHERE key='bt_versions'")
    with ctx.wdb() as c:
        ctx.store.conn = c
        ctx.store._migrate()
    assert extra_of(ctx, "d0:00:00:00:00:01")["bt_ver"] == "5.2+"
    assert "bt_ver" not in extra_of(ctx, "d0:00:00:00:00:02")
    assert ctx.one("SELECT value FROM meta WHERE key='bt_versions'")


def test_the_list_filter_and_statistics(ctx):
    t = time.time()
    for i, ex in enumerate(({}, {"ext_adv": True}, {"ext_adv": True}, {"bt_version": "5.3"})):
        ctx.store.process(bt(f"aa:00:00:00:00:{i:02x}", t, **ex))
    ctx.store.process(bt("bb:00:00:00:00:01", t, kind="bt_classic"))
    ctx.store.flush()
    c = admin_client(ctx)
    items = c.get("/api/devices", params={"kind": "ble", "slim": 1}).json()["items"]
    assert sorted(i["bt_ver"] for i in items) == ["4.0+", "5.0+", "5.0+", "5.3"] and all("extra" not in i for i in items)
    assert c.get("/api/devices", params={"bt_ver": "5.0+"}).json()["total"] == 2
    assert c.get("/api/devices", params={"bt_ver": "5.3"}).json()["total"] == 1
    assert c.get("/api/devices", params={"bt_ver": "Unknown"}).json()["items"][0]["mac"] == "bb:00:00:00:00:01"
    assert c.get("/api/export/devices.csv", params={"bt_ver": "5.0+"}).status_code == 200
    s = c.get("/api/stats").json()["bt_ver"]
    assert {(r["v"], r["kind"]): r["n"] for r in s} == {("4.0+", "ble"): 1, ("5.0+", "ble"): 2, ("5.3", "ble"): 1, (None, "bt_classic"): 1}


def test_bt_company_uses_full_sig_list():
    from sniffowireless.oui import bt_company
    assert bt_company(0x0160) == "AwoX"
    assert bt_company(0x0211)  # Telink, not in the old short list
    assert bt_company(0x004C) == "Apple"  # short names still win


def test_telink_mac_with_awox_company_id_is_awox():
    from sniffowireless.identify import identify
    d = {"kind": "ble", "mac": "a4:c1:38:4c:a5:bc", "vendor": "Telink Semiconductor (Taipei) Co. Ltd.", "randomized": 0,
         "extra": {"company": "AwoX"}}
    assert identify(d)["brand"] == "AwoX"  # AwoX smartlights use Telink chips: the advertised company is the product maker


def test_stored_company_ids_get_their_name_on_migration(tmp_path):
    import json
    from sniffowireless.config import Config
    from sniffowireless.oui import VendorLookup
    from sniffowireless.store import Store
    cfg = Config(db_path=str(tmp_path / "t.db"))
    s = Store(cfg, VendorLookup(None))
    s.process({"t": "wifi_client", "ts": 100, "mac": "a4:c1:38:4c:a5:bc", "frame": "probe", "fp": {"src": "probe"}})
    s.flush()
    s.conn.execute("UPDATE devices SET kind='ble', extra=? WHERE mac='a4:c1:38:4c:a5:bc'", (json.dumps({"company": "Company 0x0160"}),))
    s.conn.execute("DELETE FROM meta WHERE key='bt_company_names'")
    s.conn.commit()
    s._migrate()
    ex = json.loads(s.conn.execute("SELECT extra FROM devices WHERE mac='a4:c1:38:4c:a5:bc'").fetchone()[0])
    assert ex["company"] == "AwoX"


def test_company_from_an_old_sensor_is_named_on_ingest(tmp_path):
    import json
    from sniffowireless.config import Config
    from sniffowireless.oui import VendorLookup
    from sniffowireless.store import Store
    s = Store(Config(db_path=str(tmp_path / "t.db")), VendorLookup(None))
    s.process({"t": "bt", "kind": "ble", "ts": 100, "mac": "a4:c1:38:4c:a5:bc", "rssi": -60,
               "extra": {"company": "Company 0x0160", "addr_type": "public"}})
    s.flush()
    ex = json.loads(s.conn.execute("SELECT extra FROM devices WHERE mac='a4:c1:38:4c:a5:bc'").fetchone()[0])
    assert ex["company"] == "AwoX"


def test_every_service_the_identifier_knows_has_a_hover_explanation():
    import re, pathlib
    from sniffowireless.identify import BLE_UUIDS
    from sniffowireless.btversion import LE_AUDIO_SERVICES
    js = (pathlib.Path(__file__).resolve().parent.parent / "sniffowireless" / "static" / "btservices.js").read_text()
    keys = set(re.findall(r"^\s*'([0-9a-f]{4})':", js, re.M))
    assert (set(BLE_UUIDS) | LE_AUDIO_SERVICES) <= keys


def test_classic_profile_services_are_explained():
    import re, pathlib
    js = (pathlib.Path(__file__).resolve().parent.parent / "sniffowireless" / "static" / "btservices.js").read_text()
    keys = set(re.findall(r"^\s*'([0-9a-f]{4})':", js, re.M))
    assert {"1105", "110a", "110c", "110e", "1112", "1115", "1116", "112f", "1200"} <= keys


def test_risk_notes_only_for_services_that_are_explained():
    import re, pathlib
    js = (pathlib.Path(__file__).resolve().parent.parent / "sniffowireless" / "static" / "btservices.js").read_text()
    risk = js[js.index("const BT_RISK"):js.index("function btServiceInfo")]
    services = js[js.index("const BT_SERVICES"):js.index("const BT_RISK")]
    rk = set(re.findall(r"^\s*'([0-9a-f]{4})':", risk, re.M))
    sk = set(re.findall(r"^\s*'([0-9a-f]{4})':", services, re.M))
    assert rk and rk <= sk
