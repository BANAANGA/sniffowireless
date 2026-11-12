"""The indexes the overview and statistics queries rely on exist, also on a database made by an older release."""
import sqlite3

from sniffowireless.config import Config
from sniffowireless.main import build


def indexes(path):
    with sqlite3.connect(path) as c:
        return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='index'")}


def test_new_database_has_the_indexes(tmp_path):
    build(Config(db_path=str(tmp_path / "t.db"), data_dir=str(tmp_path)))
    got = indexes(tmp_path / "t.db")
    assert {"idx_events_ts_type", "idx_devices_join"} <= got
    assert "idx_events_ts" not in got


def test_older_database_is_brought_up_to_date(tmp_path):
    path = tmp_path / "old.db"
    build(Config(db_path=str(path), data_dir=str(tmp_path)))
    with sqlite3.connect(path) as c:  # as release 32 left it
        c.execute("DROP INDEX idx_events_ts_type")
        c.execute("DROP INDEX idx_devices_join")
        c.execute("CREATE INDEX idx_events_ts ON events(ts)")
        c.execute("INSERT INTO events(ts, type) VALUES(1, 'new_device')")
    build(Config(db_path=str(path), data_dir=str(tmp_path)))
    got = indexes(path)
    assert {"idx_events_ts_type", "idx_devices_join"} <= got and "idx_events_ts" not in got
    with sqlite3.connect(path) as c:
        plan = " ".join(r[3] for r in c.execute("EXPLAIN QUERY PLAN SELECT type, COUNT(*) FROM events WHERE ts>=0 GROUP BY type"))
        assert "COVERING INDEX idx_events_ts_type" in plan
        assert c.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
