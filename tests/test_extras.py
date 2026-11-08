import json
import os
import time

import pytest

from sniffowireless.backup import (apply_staged_restore, config_sections, create_full_backup, export_config, import_config,
                                   inspect_full_backup, restore_sections, validate_full_backup)
from sniffowireless.config import Config
from sniffowireless.main import build
from sniffowireless.trackers import score

PHONE = "a4:83:e7:01:00:01"
TAG = "7b:4f:00:00:00:01"


@pytest.fixture
def ctx(tmp_path):
    return build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))


# ----------------------------------------------------------------- interference
def stats(c, minute, freq, noise, retry_ratio, frames=600, util=0.15):
    c.execute("INSERT OR REPLACE INTO channel_stats VALUES(?,?,?,?,?,?,?,?,?,?)",
              (minute, "local", freq, 2500, frames, frames * 300, int(util * 2500 * 1000), int(frames * retry_ratio),
               noise * 10, 10))


def test_interference_episode_microwave(ctx):
    now = (time.time() // 60) * 60
    with ctx.wdb() as c:
        for m in range(int(now - 86400), int(now - 1800), 60):  # quiet baseline
            for freq in (2412, 2437, 2462):
                stats(c, m, freq, -95, 0.06)
        for m in range(int(now - 600), int(now), 60):  # noise + retries on channels 6 and 11
            stats(c, m, 2412, -95, 0.06)
            for freq in (2437, 2462):
                stats(c, m, freq, -82, 0.45)
    det, s = ctx.interference, ctx.store
    det.sweep(s, now)
    s.flush()
    ep = ctx.one("SELECT * FROM interference")
    assert ep["band"] == "2.4" and json.loads(ep["channels"]) == [6, 11] and ep["open"] == 1
    assert ep["kind"] == "Microwave oven likely" and ep["peak_noise_delta"] >= 10
    assert ctx.one("SELECT type FROM events WHERE mac='rf:2.4'")["type"] == "interference"
    with ctx.wdb() as c:  # back to normal: the episode closes after the quiet period
        for m in range(int(now), int(now + 1800), 60):
            for freq in (2412, 2437, 2462):
                stats(c, m, freq, -95, 0.06)
    det.last_run = 0
    det.sweep(s, now + 1800)
    s.flush()
    assert ctx.one("SELECT open FROM interference")["open"] == 0


# -------------------------------------------------------------------- trackers
def test_tracker_score():
    person = [[0, 3600], [10000, 14000]]
    follows = [[60, 3500], [10100, 13900]]
    resident = [[0, 20000]]
    assert score(follows, person)["following"]
    assert not score(resident, person)["following"]  # present when the person is away too
    assert not score([[100, 400]], person)["following"]  # too short


def test_tracker_following_person(ctx):
    s = ctx.store
    now = time.time()
    with ctx.wdb() as c:
        gid = c.execute("INSERT INTO groups(name, kind) VALUES('Alex', 'person')").lastrowid
        c.execute("INSERT INTO device_meta(mac, known, group_id) VALUES(?, 1, ?)", (PHONE, gid))
    for start in (now - 30000, now - 12000):  # two visits; the tag arrives and leaves with the phone
        for i in range(0, 3600, 60):
            s.process({"t": "wifi_client", "ts": start + i, "mac": PHONE, "frame": "probe", "rssi": -50})
            s.process({"t": "bt", "kind": "ble", "ts": start + i + 20, "mac": TAG, "rssi": -70, "randomized": True,
                       "addr_random": True, "fp": {"ble": {"company": 0x004C, "apple": [0x12]}}})
        s.sweep(start + 3600 + 400)
    s.flush()
    assert ctx.one("SELECT dev_type FROM devices WHERE mac=?", (TAG,))["dev_type"] == "tag"
    t = [x for x in ctx.trackers.evaluate(now) if x["mac"] == TAG][0]
    assert t["following"] and t["tracker"] == "AirTag / Find My" and t["match"]["person_name"] == "Alex"
    ctx.trackers.sweep(s, now)
    s.flush()
    f = ctx.one("SELECT type, severity, status FROM findings WHERE key=?", (f"tracker:{TAG}",))
    assert f == {"type": "unknown_tracker", "severity": "high", "status": "open"}
    assert ctx.one("SELECT COUNT(*) n FROM events WHERE type='tracker_following'")["n"] == 1
    with ctx.wdb() as c:  # marking it as yours clears the suspicion
        c.execute("INSERT INTO device_meta(mac, known) VALUES(?, 1)", (TAG,))
    assert not [x for x in ctx.trackers.evaluate(now) if x["mac"] == TAG][0]["following"]


# ---------------------------------------------------------------------- backup
def seed(ctx):
    with ctx.wdb() as c:
        gid = c.execute("INSERT INTO groups(name, kind) VALUES('Sam', 'person')").lastrowid
        c.execute("INSERT INTO device_meta(mac, label, known, group_id) VALUES(?, 'Sam phone', 1, ?)", (PHONE, gid))
        c.execute("INSERT INTO notifiers(name, type, config) VALUES('tg', 'telegram', ?)",
                  (json.dumps({"bot_token": "SECRET", "chat_id": "42"}),))
        c.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('admin', 'x$1$aa$bb', 'admin', 0)")
    ctx.settings.set("networks", {"ssids": ["HomeNet"], "trusted_bssids": []})


def test_config_backup_roundtrip(ctx, tmp_path):
    seed(ctx)
    data = export_config(ctx)
    assert "SECRET" not in json.dumps(data) and data["tables"]["users"][0]["username"] == "admin"
    assert "SECRET" in json.dumps(export_config(ctx, include_secrets=True))
    other = build(Config(db_path=str(tmp_path / "o.db"), data_dir=str(tmp_path / "o")))
    restored = import_config(other, json.loads(json.dumps(data)))
    assert restored["device_meta"] == 1 and restored["groups"] == 1
    assert other.one("SELECT label FROM device_meta")["label"] == "Sam phone"
    assert other.settings.get("networks")["ssids"] == ["HomeNet"]
    assert PHONE in other.store.important  # labels applied without restart
    with pytest.raises(ValueError):
        import_config(other, {"format": "nope"})
    # restoring onto the original keeps secrets that weren't in the export
    import_config(ctx, data)
    assert json.loads(ctx.one("SELECT config FROM notifiers")["config"])["bot_token"] == "SECRET"


def test_full_backup_and_staged_restore(ctx, tmp_path):
    seed(ctx)
    ctx.store.process({"t": "wifi_client", "ts": time.time(), "mac": PHONE, "frame": "probe", "rssi": -50})
    ctx.store.flush()
    with open(os.path.join(ctx.cfg.data_dir, "floorplan.svg"), "w") as fh:
        fh.write("<svg/>")
    path = create_full_backup(ctx)
    assert validate_full_backup(path)["format"] == "sniffowireless-full"
    target = Config(db_path=str(tmp_path / "r" / "sniffowireless.db"), data_dir=str(tmp_path / "r"))
    os.makedirs(target.data_dir)
    import shutil
    shutil.copyfile(path, os.path.join(target.data_dir, "restore-pending.tar.gz"))
    assert apply_staged_restore(target)
    restored = build(target)
    assert restored.one("SELECT mac FROM devices")["mac"] == PHONE
    assert os.path.exists(os.path.join(target.data_dir, "floorplan.svg"))
    assert not os.path.exists(os.path.join(target.data_dir, "restore-pending.tar.gz"))


def _two_servers(tmp_path):
    """A source with data worth restoring (and its full backup), and a different target that already has its own."""
    src = build(Config(db_path=str(tmp_path / "s.db"), data_dir=str(tmp_path / "s")))
    seed(src)
    src.store.process({"t": "wifi_client", "ts": time.time(), "mac": PHONE, "frame": "probe", "rssi": -50})
    src.store.flush()
    src.store.conn.execute("ANALYZE")  # creates SQLite's own sqlite_stat1, which must not show up as "other data"
    os.makedirs(os.path.join(src.cfg.data_dir, "handshakes"), exist_ok=True)
    with open(os.path.join(src.cfg.data_dir, "handshakes", "abc.pcap"), "wb") as fh:
        fh.write(b"pcap")
    with open(os.path.join(src.cfg.data_dir, "floorplan.svg"), "w") as fh:
        fh.write("<svg/>")
    path = create_full_backup(src)
    tcfg = Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path / "t"))
    tgt = build(tcfg)
    with tgt.wdb() as c:
        c.execute("INSERT INTO groups(name, kind) VALUES('Mine', 'thing')")
        c.execute("INSERT INTO device_meta(mac, label, known) VALUES('aa:aa:aa:00:00:01', 'Mine', 0)")
        c.execute("INSERT INTO users(username, pw_hash, role, created) VALUES('target', 'x$1$aa$bb', 'admin', 0)")
    tgt.settings.set("networks", {"ssids": ["TargetNet"], "trusted_bssids": []})
    tgt.store.process({"t": "wifi_client", "ts": time.time(), "mac": "a4:83:e7:aa:00:01", "frame": "probe"})
    tgt.store.flush()
    return src, path, tgt, tcfg


def test_backup_lists_what_it_holds(tmp_path):
    src, path, _, _ = _two_servers(tmp_path)
    info = {s["id"]: s for s in inspect_full_backup(path)["sections"]}
    assert info["labels"]["count"] == 1 and info["groups"]["count"] == 1 and info["users"]["count"] == 1
    assert info["history"]["count"] >= 2 and info["files"]["count"] == 1 and info["handshakes"]["count"] == 1
    assert info["tokens"]["count"] == 0 and "other" not in info
    # A backup from before the counts were recorded is counted by looking inside it.
    import json as _json, tarfile, io
    old = str(tmp_path / "old.tar.gz")
    with tarfile.open(path) as tin, tarfile.open(old, "w:gz") as tout:
        for m in tin.getmembers():
            if m.name == "manifest.json":
                man = _json.load(tin.extractfile(m))
                man.pop("sections")
                data = _json.dumps(man).encode()
                m.size = len(data)
                tout.addfile(m, io.BytesIO(data))
            else:
                tout.addfile(m, tin.extractfile(m) if m.isfile() else None)
    assert {s["id"]: s["count"] for s in inspect_full_backup(old)["sections"]} == {k: v["count"] for k, v in info.items()}


def test_restore_only_chosen_sections(tmp_path):
    src, path, tgt, tcfg = _two_servers(tmp_path)
    q = lambda sql: tgt.rows(sql)
    # Labels and groups only: replaced by the backup's; everything else of the target's own is left alone.
    done = restore_sections(tcfg, path, ["labels", "groups"])
    assert done == {"labels": 1, "groups": 1}
    assert [r["label"] for r in q("SELECT label FROM device_meta")] == ["Sam phone"]
    assert [r["name"] for r in q("SELECT name FROM groups")] == ["Sam"]
    assert q("SELECT group_id FROM device_meta")[0]["group_id"] == q("SELECT id FROM groups")[0]["id"]
    assert [r["username"] for r in q("SELECT username FROM users")] == ["target"]
    assert json.loads(q("SELECT value FROM settings WHERE key='networks'")[0]["value"])["ssids"] == ["TargetNet"]
    assert [r["mac"] for r in q("SELECT mac FROM devices")] == ["a4:83:e7:aa:00:01"]
    assert not os.path.exists(os.path.join(tcfg.data_dir, "floorplan.svg"))
    assert any(f.startswith("pre-restore-") for f in os.listdir(os.path.join(tcfg.data_dir, "backups")))

    # Labels without their groups: the group links are cleared rather than left pointing at nothing.
    with tgt.wdb() as c:
        c.execute("DELETE FROM groups")
    restore_sections(tcfg, path, ["labels"])
    assert q("SELECT group_id FROM device_meta")[0]["group_id"] is None

    # Users: replaced, and sessions of accounts that no longer exist are dropped. Settings and files come across too.
    restore_sections(tcfg, path, ["users", "settings", "files", "handshakes"])
    assert [r["username"] for r in q("SELECT username FROM users")] == ["admin"]
    assert json.loads(q("SELECT value FROM settings WHERE key='networks'")[0]["value"])["ssids"] == ["HomeNet"]
    assert os.path.exists(os.path.join(tcfg.data_dir, "floorplan.svg"))
    assert open(os.path.join(tcfg.data_dir, "handshakes", "abc.pcap"), "rb").read() == b"pcap"

    # History: the devices are the backup's, the hourly roll-up is rebuilt for them, and identification is redone.
    restore_sections(tcfg, path, ["history"])
    assert [r["mac"] for r in q("SELECT mac FROM devices")] == [PHONE]
    assert q("SELECT COUNT(*) n FROM presence_hours")[0]["n"] == 1
    assert not q("SELECT 1 FROM meta WHERE key='ident_version'")


def test_restore_users_never_empties_the_accounts(tmp_path):
    src, _, tgt, tcfg = _two_servers(tmp_path)
    with src.wdb() as c:
        c.execute("DELETE FROM users")
    path = create_full_backup(src)
    restore_sections(tcfg, path, ["users"])
    assert [r["username"] for r in tgt.rows("SELECT username FROM users")] == ["target"]


def test_staged_partial_restore_at_startup(tmp_path):
    import shutil
    _, path, tgt, tcfg = _two_servers(tmp_path)
    staged = os.path.join(tcfg.data_dir, "restore-pending.tar.gz")
    shutil.copyfile(path, staged)
    with open(os.path.join(tcfg.data_dir, "restore-pending.json"), "w") as fh:
        json.dump({"sections": ["groups", "bogus"]}, fh)
    assert apply_staged_restore(tcfg)
    assert [r["name"] for r in tgt.rows("SELECT name FROM groups")] == ["Sam"]
    assert tgt.rows("SELECT label FROM device_meta")[0]["label"] == "Mine"  # not chosen: untouched
    assert not os.path.exists(staged) and not os.path.exists(os.path.join(tcfg.data_dir, "restore-pending.json"))
    # An uploaded backup nobody chose from is cleaned up at startup, and a stray sidecar doesn't linger.
    open(os.path.join(tcfg.data_dir, "restore-upload.tar.gz"), "wb").write(b"x")
    open(os.path.join(tcfg.data_dir, "restore-pending.json"), "w").write("{}")
    assert not apply_staged_restore(tcfg)
    assert not os.path.exists(os.path.join(tcfg.data_dir, "restore-upload.tar.gz"))
    assert not os.path.exists(os.path.join(tcfg.data_dir, "restore-pending.json"))


def test_config_restore_only_chosen_sections(ctx, tmp_path):
    seed(ctx)
    data = json.loads(json.dumps(export_config(ctx)))
    counts = {s["id"]: s["count"] for s in config_sections(data)}
    assert counts["labels"] == 1 and counts["groups"] == 1 and counts["settings"] >= 1 and counts["notifiers"] == 1
    other = build(Config(db_path=str(tmp_path / "o.db"), data_dir=str(tmp_path / "o")))
    assert import_config(other, data, {"labels"}) == {"device_meta": 1, "radio_watch": 0}
    assert other.one("SELECT label, group_id FROM device_meta") == {"label": "Sam phone", "group_id": None}  # its group wasn't restored
    assert not other.rows("SELECT 1 FROM groups") and not other.rows("SELECT 1 FROM notifiers")
    assert other.settings.get("networks")["ssids"] == []
    assert import_config(other, data, {"settings", "groups"}) == {"groups": 1}
    assert other.settings.get("networks")["ssids"] == ["HomeNet"]


def test_bad_backup_rejected(tmp_path):
    import tarfile
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(bad, "w:gz") as tar:
        p = tmp_path / "x.txt"
        p.write_text("hi")
        tar.add(p, arcname="../../etc/x")
    with pytest.raises(ValueError):
        validate_full_backup(str(bad))


# -------------------------------------------------------------- investigations
def test_investigation_events_and_catalogue(ctx):
    from sniffowireless.investigate import ssid_catalogue
    s = ctx.store
    ctx.settings.set("investigate", {"ssids": [{"ssid": "FreeWiFi", "note": "rogue?", "added": 1}]})
    ctx.settings.set("networks", {"ssids": ["HomeNet"], "trusted_bssids": []})
    t = time.time()
    s.process({"t": "wifi_ap", "ts": t, "mac": "0a:00:00:00:00:01", "ssid": "FreeWiFi", "enc": "OPN", "channel": 6})
    s.process({"t": "wifi_ap", "ts": t + 30, "mac": "0a:00:00:00:00:01", "ssid": "FreeWiFi", "enc": "OPN"})  # no repeat
    s.process({"t": "wifi_ap", "ts": t, "mac": "24:a4:3c:00:00:01", "ssid": "HomeNet", "enc": "WPA2/PSK"})
    s.process({"t": "wifi_client", "ts": t + 5, "mac": PHONE, "bssid": "0a:00:00:00:00:01", "frame": "data"})
    s.process({"t": "wifi_client", "ts": t + 6, "mac": PHONE, "bssid": "0a:00:00:00:00:01", "frame": "data"})  # no repeat
    s.process({"t": "wifi_client", "ts": t + 7, "mac": "da:00:00:00:00:02", "frame": "probe", "probe": "FreeWiFi"})
    s.process({"t": "wifi_client", "ts": t + 8, "mac": "da:00:00:00:00:02", "frame": "probe", "probe": "OtherNet"})
    s.flush()
    ev = [(r["type"], r["mac"], r["peer"]) for r in ctx.rows(
        "SELECT type, mac, peer FROM events WHERE type LIKE 'investigated_%' ORDER BY id")]
    assert ev == [("investigated_seen", "0a:00:00:00:00:01", "ssid:FreeWiFi"),
                  ("investigated_connect", PHONE, "ssid:FreeWiFi"),
                  ("investigated_probe", "da:00:00:00:00:02", "ssid:FreeWiFi")]
    cat = {x["ssid"]: x for x in ssid_catalogue(ctx)}
    assert cat["FreeWiFi"]["investigated"] and cat["FreeWiFi"]["aps"] == 1 and cat["FreeWiFi"]["probers"] == 1
    assert cat["HomeNet"]["mine"] and cat["OtherNet"]["aps"] == 0 and cat["OtherNet"]["probers"] == 1
    assert ctx.one("SELECT name FROM alert_rules WHERE name='Networks under investigation'")  # rule added once
    ctx.alerts.handle({"type": "investigated_seen", "mac": "0a:00:00:00:00:01", "ts": t, "peer": "ssid:FreeWiFi",
                       "detail": "“FreeWiFi” on the air"})
    assert ctx.one("SELECT rule_name FROM alert_log")["rule_name"] == "Networks under investigation"


# ----------------------------------------------------------------- DFS / radar
def test_dfs_radar_events(ctx):
    s = ctx.store
    ctx.settings.set("networks", {"ssids": ["HomeNet"], "trusted_bssids": []})
    mine, nb = "24:a4:3c:00:00:05", "0a:00:00:00:00:07"
    t = time.time() - 600
    ap = lambda mac, ssid, ts, ch, csa=None: s.process({"t": "wifi_ap", "ts": ts, "mac": mac, "ssid": ssid, "band": "5",
                                                         "channel": ch, "csa": csa})
    ap(mine, "HomeNet", t, 100)
    for i in range(3):  # CSA repeated in several beacons: one announcement
        ap(mine, "HomeNet", t + 1 + i, 100, {"mode": 1, "new_channel": 36, "count": 5 - i})
    for i in range(3):
        ap(mine, "HomeNet", t + 10 + i, 36)
    ap(nb, "Buren", t, 52)
    ap(nb, "Buren", t + 5, 44)  # single stray sighting: not a change
    ap(nb, "Buren", t + 6, 52)
    for i in range(3):  # unannounced move off a DFS channel
        ap(nb, "Buren", t + 20 + i, 149)
    s.flush()
    ev = [(r["type"], r["mac"]) for r in ctx.rows(
        "SELECT type, mac FROM events WHERE type IN ('dfs_radar', 'channel_switch_announced', 'channel_change') ORDER BY id")]
    assert ev == [("channel_switch_announced", mine), ("dfs_radar", mine), ("channel_change", mine),
                  ("channel_change", nb), ("dfs_radar", nb)]
    rows = ctx.rows("SELECT mac, from_ch, to_ch, csa, dfs, mine FROM dfs_events ORDER BY id")
    assert [(r["from_ch"], r["to_ch"], r["csa"], r["dfs"], r["mine"]) for r in rows] == [(100, 36, 1, 1, 1), (52, 149, 0, 1, 0)]
    assert ctx.one("SELECT 1 FROM alert_rules WHERE name='Radar (DFS) on my networks'")
    for mac in (mine, nb):
        ctx.alerts.handle({"type": "dfs_radar", "mac": mac, "ts": t, "peer": None, "detail": "x"})
    assert [r["mac"] for r in ctx.rows("SELECT mac FROM alert_log")] == [mine]  # "mine" target
    from fastapi.testclient import TestClient
    from sniffowireless.web import create_app
    ctx.auth.disabled = True
    d = TestClient(create_app(ctx), base_url="http://sniffowireless.test").get("/api/dfs?days=1").json()
    per = {c["channel"]: c for c in d["channels"]}
    assert per[100]["radar"] == 1 and per[52]["radar"] == 1 and per[100]["closed_until"] and d["mine_radar"] == 1


# ------------------------------------------------------------------ BT ↔ Wi-Fi matching
def test_bt_wifi_matching(ctx):
    from sniffowireless.matching import mac_adjacent, name_score, suggestions
    assert mac_adjacent("5c:0a:5b:01:00:03", "5c:0a:5b:01:00:04") and not mac_adjacent("5c:0a:5b:01:00:03", "5c:0a:5b:01:00:99")
    assert name_score("Sam's iPhone", "Sams-iPhone") == 1.0 and name_score("MacBook Pro", "Robins-MacBook-Pro") >= 0.7
    s = ctx.store
    base = time.time() - 4 * 3600
    wifi, bt, buds, other_bt = "a4:83:e7:01:00:01", "a4:83:e7:01:00:02", "4c:11:aa:02:00:01", "6e:11:aa:02:00:99"
    for start in (base, base + 7200):  # two visits of 50 minutes
        for i in range(0, 3000, 60):
            t = start + i
            rs = -50 - (i // 300)  # walking away: both radios fade together
            s.process({"t": "wifi_client", "ts": t, "mac": wifi, "frame": "probe", "rssi": rs, "vendor": "Apple"})
            s.process({"t": "bt", "kind": "bt_classic", "ts": t + 5, "mac": bt, "name": "Sam's iPhone", "rssi": rs - 8})
            s.process({"t": "bt", "kind": "ble", "ts": t + 7, "mac": buds, "name": "AirPods Pro", "rssi": rs,
                       "extra": {"appearance": "audio sink"}})
        s.sweep(start + 3000 + 400)
    for i in range(0, 3000, 60):  # an unrelated phone, present at other times
        s.process({"t": "bt", "kind": "ble", "ts": base + 4000 + i, "mac": other_bt, "rssi": -70,
                   "fp": {"ble": {"company": 0x004C, "apple": [0x0C, 0x10]}}})
    s.sweep(base + 7600)
    s.flush()
    sug = suggestions(ctx)
    pairs = {(x["bt"]["mac"], x["wifi"]["mac"]): x for x in sug}
    assert (bt, wifi) in pairs and pairs[(bt, wifi)]["level"] == "high"
    assert any("adjacent hardware addresses" in r for r in pairs[(bt, wifi)]["reasons"])
    assert not any(x["bt"]["mac"] == buds for x in sug)  # earbuds move with the phone but are a separate device
    assert not any(x["bt"]["mac"] == other_bt for x in sug)
    with ctx.wdb() as c:
        gid = c.execute("INSERT INTO groups(name, kind) VALUES('Sam', 'person')").lastrowid
        c.execute("INSERT INTO device_meta(mac, known, group_id) VALUES(?, 1, ?)", (wifi, gid))
    from fastapi.testclient import TestClient  # noqa: F401  (route logic exercised directly below)
    from sniffowireless.matching import pair
    ctx.execute("INSERT INTO device_links VALUES(?,?,?,?,?)", (*pair(bt, wifi), "rejected", 0.9, time.time()))
    assert not any((x["bt"]["mac"], x["wifi"]["mac"]) == (bt, wifi) for x in suggestions(ctx))  # rejected stays hidden
