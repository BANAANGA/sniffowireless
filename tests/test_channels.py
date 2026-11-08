import json
import threading

import pytest

from sniffowireless import channels, status, wifi
from sniffowireless.channels import WifiControl, check_spec, clean_override, effective
from sniffowireless.config import Config, band_of, chan_label, parse_channels
from sniffowireless.main import build
from sniffowireless.sanitize import remote_status
from sniffowireless.sensors import Forwarder

G24 = set(parse_channels("2.4ghz"))
G5 = set(parse_channels("5ghz"))
G6 = set(parse_channels("6all"))


def test_check_spec_and_clean_override():
    assert check_spec("1,6,11") == parse_channels("1,6,11") and check_spec("6g:37")
    for bad in ("", "  ", "abc", "1,,x", "999", "6g:999", "x" * 201):
        with pytest.raises(ValueError):
            check_spec(bad)
    ok = clean_override({"channels": " default,6ghz ", "per_iface": {"wlan1": "1,6,11", "wlan2": "", "wlan3": None},
                         "regdomain": "nl", "hop_interval": "1.5", "junk": 1})
    assert ok == {"channels": "default,6ghz", "per_iface": {"wlan1": "1,6,11", "wlan2": ""}, "regdomain": "NL", "hop_interval": 1.5}
    assert clean_override(None) == {"channels": None, "per_iface": {}, "regdomain": None, "hop_interval": None}
    for bad in ({"regdomain": "NLD"}, {"regdomain": "1!"}, {"hop_interval": 0.01}, {"hop_interval": 999}, {"hop_interval": "fast"},
                {"per_iface": {"wlan 1": "1"}}, {"per_iface": {"wlan1": "nope"}}, {"channels": "999"}):
        with pytest.raises(ValueError):
            clean_override(bad)


def test_effective_layers_the_override_on_the_environment():
    cfg = Config(wifi_interfaces=["wlan1", "wlan2"], wifi_channels=parse_channels("1,6,11"), wifi_regdomain="DE", wifi_hop_interval=0.5,
                 wifi_channels_per_iface={"wlan2": parse_channels("36")})
    env = effective(cfg)
    assert env["channels"] == parse_channels("1,6,11") and env["per_iface"] == {"wlan2": parse_channels("36")}
    assert env["regdomain"] == "DE" and env["hop_interval"] == 0.5
    over = effective(cfg, {"channels": "6ghz", "regdomain": "nl", "hop_interval": 2,
                           "per_iface": {"wlan1": "1,6", "wlan2": ""}})  # "" = share the list, dropping the environment's wlan2 list
    assert over["channels"] == parse_channels("6ghz") and over["per_iface"] == {"wlan1": parse_channels("1,6")}
    assert over["regdomain"] == "NL" and over["hop_interval"] == 2.0
    # Nothing set: the environment stands, including a per-adapter list the override doesn't mention.
    assert effective(cfg, {"channels": None, "per_iface": {"wlan1": None}})["per_iface"] == {"wlan2": parse_channels("36")}


@pytest.fixture
def control(monkeypatch):
    """Two adapters: wlanA (2.4 + 5 GHz only) and wlanB (also 6 GHz), no real hardware or threads."""
    sup = {"wlanA": G24 | G5, "wlanB": G24 | G5 | G6}
    monkeypatch.setattr(wifi, "supported_freqs", lambda i: sup[i])
    monkeypatch.setattr(wifi.WifiSensor, "start", lambda self, stop: None)
    monkeypatch.setattr(wifi, "global_regdomain", lambda: "NL")
    calls = []
    monkeypatch.setattr(wifi, "set_regdomain", lambda c: calls.append(c))
    monkeypatch.setattr(channels.time, "sleep", lambda s: None)

    class Inline:  # a regulatory-domain change normally continues on a thread; run it in place
        def __init__(self, target, args=(), **kw):
            self.target, self.args = target, args

        def start(self):
            self.target(*self.args)
    monkeypatch.setattr(channels.threading, "Thread", Inline)
    cfg = Config(wifi_interfaces=["wlanA", "wlanB"], wifi_channels=parse_channels("default"))
    ctl = WifiControl(cfg, sink=None)
    ctl.start(threading.Event())
    ctl.reg_calls = calls
    return ctl


def chans(ctl, iface):
    return next(s for s in ctl.sensors if s.iface == iface).channels


def test_apply_replans_the_adapters_while_running(control):
    ctl = control
    assert {f for s in ctl.sensors for f in s.channels} == set(parse_channels("default"))  # from the environment
    # Add 6 GHz: only the adapter that can tune it gets those channels; the others are split between both.
    ctl.apply({"channels": "default,6ghz"}, rev=1)
    assert set(chans(ctl, "wlanB")) >= set(parse_channels("6ghz")) and not set(chans(ctl, "wlanA")) & G6
    assert status.SENSORS["wifi:wlanB"]["chan_rev"] == 1 and status.SENSORS["wifi:wlanA"]["chan_rev"] == 1
    assert status.SENSORS["wifi:wlanB"]["supported_bands"] == ["2.4", "5", "6"]
    assert status.SENSORS["wifi:wlanA"]["supported_bands"] == ["2.4", "5"]
    assert all(s._changed.is_set() for s in ctl.sensors)  # the hoppers were woken
    # A per-adapter list overrides the shared one; a single channel locks the adapter.
    ctl.apply({"channels": "default", "per_iface": {"wlanA": "2g:6"}, "hop_interval": 2}, rev=2)  # (a bare 6 means all of 6 GHz)
    assert chans(ctl, "wlanA") == [2437] and len(chans(ctl, "wlanA")) == 1
    assert set(chans(ctl, "wlanB")) == set(parse_channels("default")) and all(s.hop_interval == 2 for s in ctl.sensors)
    # Back to the environment.
    ctl.apply({}, rev=3)
    assert {f for s in ctl.sensors for f in s.channels} == set(parse_channels("default")) and ctl.sensors[0].hop_interval == 0.5
    assert ctl.rev == 3 and status.SENSORS["wifi:wlanA"]["chan_rev"] == 3
    # An invalid setting changes nothing.
    with pytest.raises(ValueError):
        ctl.apply({"channels": "banana"}, rev=4)
    assert ctl.rev == 3


def test_regdomain_is_set_and_the_supported_channels_reread(control, monkeypatch):
    ctl = control
    ctl.apply({"channels": "6ghz", "regdomain": "nl"}, rev=1)
    assert ctl.reg_calls == ["NL"] and ctl.regdomain == "NL"
    assert status.SENSORS["wifi:wlanB"]["regdomain"] == "NL"
    ctl.apply({"channels": "all", "regdomain": "NL"}, rev=2)  # same country: not set again
    assert ctl.reg_calls == ["NL"]
    # The country blocks 6 GHz: the warning says so, and it reaches the status.
    monkeypatch.setattr(wifi, "global_regdomain", lambda: "00")
    ctl.apply({"channels": "6ghz"}, rev=3)
    assert "00" in status.SENSORS["wifi:wlanB"]["warning"]


def test_remote_settings_apply_once_per_revision(control, caplog):
    ctl = control
    conf = {"rev": 5, "channels": "6ghz", "per_iface": {}, "regdomain": None, "hop_interval": None}
    ctl.apply_remote(conf)
    assert ctl.rev == 5 and set(chans(ctl, "wlanB")) == set(parse_channels("6ghz"))
    ctl.sensors[0]._changed.clear()
    ctl.apply_remote(conf)  # same revision again: nothing happens
    assert not ctl.sensors[0]._changed.is_set()
    # Garbage from the server is ignored (and reported once), never applied.
    for bad in ({"rev": 6, "channels": "banana"}, {"rev": "7"}, {"channels": "1"}, None, "x"):
        ctl.apply_remote(bad)
    ctl.apply_remote({"rev": 6, "channels": "banana"})
    assert ctl.rev == 5 and sum("revision 6" in m for m in caplog.messages) == 1
    # Clearing on the server is a new revision with nothing set: the sensor goes back to its environment.
    ctl.apply_remote({"rev": 7, "channels": None, "per_iface": {}, "regdomain": None, "hop_interval": None})
    assert ctl.rev == 7 and {f for s in ctl.sensors for f in s.channels} == set(parse_channels("default"))


def test_forwarder_hands_the_servers_channel_settings_to_the_sensor():
    f = Forwarder(Config(server_url="http://x", sensor_token="t"))
    got = []
    f._handle_reply(json.dumps({"accepted": 1, "channel_config": {"rev": 1}}).encode())  # nobody listening yet
    f.on_channel_config = got.append
    f._handle_reply(json.dumps({"accepted": 1}).encode())          # none configured
    f._handle_reply(b"not json")
    f._handle_reply(json.dumps({"channel_config": {"rev": 2, "channels": "6ghz"}}).encode())
    assert got == [{"rev": 2, "channels": "6ghz"}]
    f.on_channel_config = lambda c: 1 / 0  # a failing handler must not break forwarding
    f._handle_reply(json.dumps({"channel_config": {"rev": 3}}).encode())


def test_wifi_sensor_set_channels_wakes_the_hopper():
    s = wifi.WifiSensor("wlanW", parse_channels("1,6"), Config(), store=None)
    s.stop = threading.Event()
    s.set_channels(parse_channels("36,40"), 2.0)
    assert s.channels == parse_channels("36,40") and s.hop_interval == 2.0 and s._changed.is_set()
    assert status.SENSORS["wifi:wlanW"]["channels"] == ["36", "40"] and status.SENSORS["wifi:wlanW"]["bands"] == ["5"]
    import time
    t0 = time.monotonic()
    s._pause(30)  # returns at once because the settings changed, instead of sleeping the 30 s of a locked adapter
    assert time.monotonic() - t0 < 1
    s._changed.clear()
    s.stop.set()
    t0 = time.monotonic()
    s._pause(30)  # and on shutdown
    assert time.monotonic() - t0 < 1


def test_remote_status_keeps_the_channel_fields():
    st = remote_status({"name": "wifi:wlan1", "chan_rev": "4", "regdomain": "NL", "channels": ["1", "6G:37", 5, "<b>x</b>"],
                        "bands": ["2.4", "6", "9"], "supported_bands": ["5", "<i>"], "skipped": ["165"]})
    assert st["chan_rev"] == 4 and st["regdomain"] == "NL" and st["channels"] == ["1", "6G:37", "<b>x</b>"]
    assert st["bands"] == ["2.4", "6"] and st["supported_bands"] == ["5"] and st["skipped"] == ["165"]
    assert "chan_rev" not in remote_status({"name": "x", "chan_rev": "many"})


def test_the_server_applies_saved_settings_and_follows_changes(tmp_path, control, monkeypatch):
    ctx = build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path), wifi_interfaces=["wlanA", "wlanB"]))
    ctx.settings.set("channels", {"local": {"rev": 2, "channels": "6ghz"}, "sensors": {}})
    ctl = channels.attach(ctx)  # starts from what was saved
    assert ctl.rev == 2 and ctl.override["channels"] == "6ghz"
    ctl.start(threading.Event())
    assert set(chans(ctl, "wlanB")) == set(parse_channels("6ghz"))
    ctx.settings.set("channels", {"local": {"rev": 3, "channels": "1,6,11"}, "sensors": {}})  # a later change applies live
    assert ctl.rev == 3 and {f for s in ctl.sensors for f in s.channels} == set(parse_channels("1,6,11"))
    # A value this version rejects (say from a restored backup) is ignored, not fatal.
    ctx.settings.set("channels", {"local": {"rev": 4, "channels": "banana"}, "sensors": {}})
    assert ctl.rev == 3
    ctx.settings.set("channels", {"local": {"rev": 9, "channels": "banana"}, "sensors": {}})
    bad = channels.attach(ctx)
    bad.start(threading.Event())
    assert bad.rev == 0 and {f for s in bad.sensors for f in s.channels} == set(parse_channels("default"))


def test_apply_without_adapters_only_keeps_the_settings(monkeypatch):
    """A server with no Wi-Fi adapter must not touch the host's regulatory domain because an admin saved one."""
    calls = []
    monkeypatch.setattr(wifi, "set_regdomain", lambda c: calls.append(c))
    ctl = WifiControl(Config(), sink=None)
    ctl.apply({"channels": "6ghz", "regdomain": "nl"}, rev=1)
    assert ctl.rev == 1 and ctl.override["channels"] == "6ghz" and calls == []


# ---- the sensor keeps one connection open to the server instead of reconnecting for every batch
def _ingest_server(status=200, close_after=None):
    import http.server, threading

    seen = {"conns": 0, "posts": 0, "bodies": []}

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            seen["conns"] += 1
            self.n = 0

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            seen["posts"] += 1
            seen["bodies"].append((self.path, self.headers["Authorization"], body))
            self.n += 1
            out = b'{"ok": true}'
            self.send_response(status)
            self.send_header("Content-Length", str(len(out)))
            if close_after and self.n >= close_after:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, seen


def test_forwarder_reuses_one_connection(monkeypatch):
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        monkeypatch.delenv(k, raising=False)
    srv, seen = _ingest_server()
    try:
        f = Forwarder(Config(server_url=f"http://127.0.0.1:{srv.server_port}/", sensor_token="tok"))
        for _ in range(5):
            assert f._post(b"x") == b'{"ok": true}'
        assert seen["posts"] == 5 and seen["conns"] == 1
        assert seen["bodies"][0][:2] == ("/api/ingest", "Bearer tok")
    finally:
        f._close()
        srv.shutdown()


def test_forwarder_reconnects_when_the_server_closes_the_connection(monkeypatch):
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        monkeypatch.delenv(k, raising=False)
    srv, seen = _ingest_server(close_after=2)
    try:
        f = Forwarder(Config(server_url=f"http://127.0.0.1:{srv.server_port}", sensor_token="t"))
        for _ in range(5):
            f._post(b"x")
        assert seen["posts"] == 5 and seen["conns"] == 3
    finally:
        f._close()
        srv.shutdown()


def test_forwarder_raises_on_http_errors_and_unreachable_server(monkeypatch):
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        monkeypatch.delenv(k, raising=False)
    srv, seen = _ingest_server(status=401)
    try:
        f = Forwarder(Config(server_url=f"http://127.0.0.1:{srv.server_port}", sensor_token="t"))
        with pytest.raises(OSError, match="401"):
            f._post(b"x")
        assert f._conn is None and seen["posts"] == 1  # an error answer is not retried
    finally:
        srv.shutdown()
    with pytest.raises(OSError):
        f._post(b"x")  # nothing is listening any more
