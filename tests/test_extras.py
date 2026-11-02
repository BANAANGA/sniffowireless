import json
import os
import time

import pytest

from yolo.backup import apply_staged_restore, create_full_backup, export_config, import_config, validate_full_backup
from yolo.config import Config
from yolo.main import build
from yolo.trackers import score

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
    assert validate_full_backup(path)["format"] == "yolo-full"
    target = Config(db_path=str(tmp_path / "r" / "yolo.db"), data_dir=str(tmp_path / "r"))
    os.makedirs(target.data_dir)
    import shutil
    shutil.copyfile(path, os.path.join(target.data_dir, "restore-pending.tar.gz"))
    assert apply_staged_restore(target)
    restored = build(target)
    assert restored.one("SELECT mac FROM devices")["mac"] == PHONE
    assert os.path.exists(os.path.join(target.data_dir, "floorplan.svg"))
    assert not os.path.exists(os.path.join(target.data_dir, "restore-pending.tar.gz"))


def test_bad_backup_rejected(tmp_path):
    import tarfile
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(bad, "w:gz") as tar:
        p = tmp_path / "x.txt"
        p.write_text("hi")
        tar.add(p, arcname="../../etc/x")
    with pytest.raises(ValueError):
        validate_full_backup(str(bad))
