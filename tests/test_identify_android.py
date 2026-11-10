"""Recognising Samsung phones and Google Pixels: names with hyphens (hostnames cannot hold spaces), Samsung model numbers."""
import pytest

from sniffowireless.identify import IDENT_VERSION, identify, samsung_model_evidence, tidy_model, Evidence


def by_name(name, kind="ble"):
    r = identify({"kind": kind, "name": name, "extra": {}})
    return r["brand"], r["dev_type"], r["model"], r["os"]


@pytest.mark.parametrize("name,model,typ", [
    ("Galaxy S23 Ultra", "Galaxy S23 Ultra", "phone"),
    ("Galaxy-S23-Ultra", "Galaxy S23 Ultra", "phone"),
    ("galaxy-s23-ultra", "Galaxy S23 Ultra", "phone"),
    ("Galaxy_A54_5G", "Galaxy A54 5G", "phone"),
    ("Galaxy S21+", "Galaxy S21+", "phone"),
    ("Galaxy S24 FE", "Galaxy S24 FE", "phone"),
    ("Galaxy Z Flip5", "Galaxy Z Flip5", "phone"),
    ("Galaxy-Z-Fold4", "Galaxy Z Fold4", "phone"),
    ("Galaxy Tab S9", "Galaxy Tab S9", "tablet"),
    ("Galaxy Tab S9 Ultra", "Galaxy Tab S9 Ultra", "tablet"),
    ("Galaxy-Watch6-Classic", "Galaxy Watch6 Classic", "watch"),
    ("Galaxy-Watch5", "Galaxy Watch5", "watch"),
    ("Galaxy Buds2 Pro", "Galaxy Buds2 Pro", "headphones"),
])
def test_samsung_names(name, model, typ):
    brand, t, m, _ = by_name(name)
    assert (brand, t, m) == ("Samsung", typ, model)


@pytest.mark.parametrize("name,model,typ", [
    ("Pixel 7", "Pixel 7", "phone"),
    ("Pixel-7-Pro", "Pixel 7 Pro", "phone"),
    ("pixel-8a", "Pixel 8a", "phone"),
    ("Pixel_6a", "Pixel 6a", "phone"),
    ("Pixel 9 Pro XL", "Pixel 9 Pro XL", "phone"),
    ("Pixel 9 Pro Fold", "Pixel 9 Pro Fold", "phone"),
    ("Pixel 4 XL", "Pixel 4 XL", "phone"),
    ("Pixel Fold", "Pixel Fold", "phone"),
    ("Pixel-Tablet", "Pixel Tablet", "tablet"),
    ("Pixel Watch 2", "Pixel Watch", "watch"),
    ("Pixel Buds Pro", "Pixel Buds", "headphones"),
])
def test_pixel_names(name, model, typ):
    brand, t, m, _ = by_name(name)
    assert (brand, t, m) == ("Google", typ, model)


def test_names_that_are_not_these_phones():
    assert by_name("Galaxy")[0] is None and by_name("My Galaxy Note")[2] is None
    assert by_name("Pixelmator")[0] is None and by_name("pixels 4 all")[0] is None
    assert by_name("Galaxy Z")[0] is None


def test_tidy_model():
    assert tidy_model("Galaxy-S23-Ultra") == "Galaxy S23 Ultra" and tidy_model("pixel_7_pro") == "Pixel 7 Pro"
    assert tidy_model("pixel-9-pro-xl") == "Pixel 9 Pro XL" and tidy_model("galaxy-a54-5g") == "Galaxy A54 5G"
    assert tidy_model("Pixel 7a") == "Pixel 7a"        # mixed case is left as it was


def wps(model=None, number=None, name=None, manufacturer="Samsung Electronics Co.,Ltd.", randomized=1):
    return {"kind": "wifi_client", "randomized": randomized,
            "extra": {"fp": {"wifi": {"wps": {"manufacturer": manufacturer, "model": model, "model_number": number, "device_name": name}}}}}


def test_a_samsung_model_number_gets_its_marketing_name():
    r = identify(wps(model="SM-S918B"))
    assert (r["brand"], r["model"], r["dev_type"], r["os"], r["era"]) == ("Samsung", "Galaxy S23 Ultra", "phone", "Android", 2023)
    assert identify(wps(model="SM-G991B"))["model"] == "Galaxy S21"
    assert identify(wps(model="SM-F741U1"))["model"] == "Galaxy Z Flip6"
    assert identify(wps(name="SM-S928B"))["model"] == "Galaxy S24 Ultra"
    r = identify({"kind": "ble", "name": "SM-S911B", "extra": {}})            # also from a Bluetooth name
    assert (r["brand"], r["model"], r["dev_type"]) == ("Samsung", "Galaxy S23", "phone")


def test_an_unlisted_samsung_model_number_keeps_the_number_and_the_kind_of_device():
    r = identify(wps(model="SM-A546B"))
    assert (r["brand"], r["model"], r["dev_type"], r["os"]) == ("Samsung", "SM-A546B", "phone", "Android")
    assert identify(wps(model="SM-T870"))["dev_type"] == "tablet" and identify(wps(model="SM-X710"))["dev_type"] == "tablet"
    r = identify(wps(model="SM-R190", randomized=0))     # a line without a type: only the brand
    assert r["brand"] == "Samsung" and r["model"] == "SM-R190" and r["dev_type"] != "phone"


def test_not_a_samsung_model_number():
    ev = Evidence()
    for text in ("SM-XYZ", "ESM-S918B", "SM-S91", "SM-S9181234", "", None, "Galaxy"):
        assert samsung_model_evidence(ev, [], text, "x") is False
    assert ev.items == []


def test_the_rules_are_versioned_so_stored_devices_are_looked_at_again():
    assert IDENT_VERSION >= 5


def test_the_store_ends_up_with_the_marketing_name(tmp_path):
    from sniffowireless.config import Config
    from sniffowireless.oui import VendorLookup
    from sniffowireless.store import Store
    s = Store(Config(db_path=str(tmp_path / "t.db")), VendorLookup(None))
    fp = {"gen": 6, "wps": {"manufacturer": "Samsung Electronics Co.,Ltd.", "model": "SM-S918B"}}
    s.process({"t": "wifi_client", "ts": 100, "mac": "da:00:00:00:00:09", "frame": "probe", "fp": {"wifi": fp, "src": "probe"}})
    s.flush()
    r = s.conn.execute("SELECT brand, model, dev_type, os, era FROM devices WHERE mac='da:00:00:00:00:09'").fetchone()
    assert tuple(r) == ("Samsung", "Galaxy S23 Ultra", "phone", "Android", 2023)
