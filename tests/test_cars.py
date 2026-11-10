"""Cars: Teslas, Mercedes and other makes; and the look-alikes that are not cars."""
import pytest

from sniffowireless.identify import identify


def dev(**kw):
    base = {"kind": "wifi_client", "mac": "4c:fc:aa:00:00:01", "randomized": 0, "extra": {}}
    base.update(kw)
    return base


@pytest.mark.parametrize("vendor, brand", [
    ("Tesla,Inc.", "Tesla"), ("Tesla, Inc.", "Tesla"), ("Tesla Inc", "Tesla"),
    ("Mercedes-Benz USA, LLC", "Mercedes-Benz"), ("Daimler AG", "Mercedes-Benz"),
    ("Volkswagen Group of America", "Volkswagen"), ("Dr. Ing. h.c. F. Porsche AG", "Porsche"), ("Bmw Ag", "BMW"),
    ("Ford Motor Company", "Ford"), ("Volvo Car Corporation", "Volvo"), ("Woven By Toyota U.S., Inc.", "Toyota"), ("Rivian Automotive, LLC", "Rivian"),
])
def test_a_car_makers_mac_vendor_means_a_car(vendor, brand):
    r = identify(dev(vendor=vendor))
    assert r["brand"] == brand and r["dev_type"] == "car", vendor


@pytest.mark.parametrize("vendor", ["TESLA, a.s.", "Tesla Controls", "Pico-Tesla Magnetic Therapies", "Meridian Audio Limited", "Harrison Audio, LLC",
                                    "Toyota Motorsport GmbH", "Lucid Vision Labs", "Hyundai Digital Technology Co.,Ltd.", "Polestar Corp."])
def test_look_alike_vendors_are_not_cars(vendor):
    r = identify(dev(vendor=vendor))
    assert r["dev_type"] != "car" and r["brand"] not in ("Tesla", "Mercedes-Benz", "Toyota", "Ford", "Audi"), (vendor, r["brand"], r["dev_type"])


def test_daimler_trucks_are_named_but_not_called_a_car():
    r = identify(dev(vendor="Daimler Truck AG"))
    assert r["brand"] == "Daimler Truck" and r["dev_type"] != "car"


@pytest.mark.parametrize("ssid, brand", [
    ("Tesla Model 3", "Tesla"), ("Mercedes-Benz C300", "Mercedes-Benz"), ("Mercedes", "Mercedes-Benz"), ("BMW_5A2B", "BMW"), ("AUDI Q5", "Audi"),
    ("VW_Golf", "Volkswagen"), ("Volvo XC60", "Volvo"), ("Ford SYNC", "Ford"), ("Ford Mustang", "Ford"), ("Polestar 2", "Polestar"),
])
def test_a_hotspot_named_after_a_car_is_one(ssid, brand):
    r = identify({"kind": "ap", "mac": "02:00:00:00:00:01", "randomized": 1, "ssid": ssid, "extra": {}})
    assert r["dev_type"] == "car" and r["brand"] == brand, ssid


@pytest.mark.parametrize("ssid", ["Audio Room", "AudioBar", "Stanford Guest", "Oxford Wifi", "Fordham", "Crawford", "Claudia", "Volvoline", "BMWorld5"])
def test_words_that_merely_contain_a_make_are_not_cars(ssid):
    r = identify({"kind": "ap", "mac": "02:00:00:00:00:01", "randomized": 1, "ssid": ssid, "extra": {}})
    assert r["dev_type"] != "car", ssid


def test_teslas_own_gear_is_not_a_car():
    wc = identify({"kind": "ap", "mac": "02:00:00:00:00:01", "randomized": 1, "ssid": "TeslaWallConnector_5A2B1C", "extra": {}})
    assert wc["brand"] == "Tesla" and wc["dev_type"] == "charger"
    pw = identify({"kind": "ap", "mac": "02:00:00:00:00:01", "randomized": 1, "ssid": "TeslaPW_ABC123", "extra": {}})
    assert pw["brand"] == "Tesla" and pw["dev_type"] == "smart_home"


def test_a_tesla_is_recognised_by_its_documented_bluetooth_name():
    r = identify({"kind": "ble", "mac": "c1:22:33:44:55:66", "randomized": 1, "name": "S1a2b3c4d5e6f7a8bC", "extra": {}})
    assert r["brand"] == "Tesla" and r["dev_type"] == "car" and r["ident"]["fields"]["type"]["level"] == "high"
    for name in ("S1a2b3c4d5e6f7a8b", "S1a2b3c4d5e6f7a8bcC", "Sensor", "S1a2b3c4d5e6f7a8bCx", "T1a2b3c4d5e6f7a8bC"):
        assert identify({"kind": "ble", "mac": "c1:22:33:44:55:66", "randomized": 1, "name": name, "extra": {}})["brand"] != "Tesla", name


@pytest.mark.parametrize("company, brand", [("Tesla, Inc.", "Tesla"), ("Mercedes-Benz Group AG", "Mercedes-Benz"), ("Audi AG", "Audi"), ("Rivian Automotive, LLC", "Rivian")])
def test_a_car_makers_bluetooth_company_id_means_a_car(company, brand):
    r = identify({"kind": "ble", "mac": "c1:22:33:44:55:66", "randomized": 1, "extra": {"company": company}})
    assert r["dev_type"] == "car" and r["brand"] == brand


def test_an_audio_company_is_not_a_car():
    r = identify({"kind": "ble", "mac": "c1:22:33:44:55:66", "randomized": 1, "extra": {"company": "Tivoli Audio, LLC"}})
    assert r["dev_type"] != "car"
