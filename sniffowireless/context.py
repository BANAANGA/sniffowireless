"""Shared application context handed to every API module."""
import json
from contextlib import closing

from .store import connect


class Ctx:
    def __init__(self, cfg, store, settings=None):
        self.cfg, self.store, self.settings = cfg, store, settings
        self.auth = self.alerts = self.security = self.survey = self.location = self.reports = self.lan = None
        self.interference = self.trackers = self.backups = self.investigate = self.dfs = self.handshake = None
        self.mqtt = self.zigbee = self.wifi = None

    def db(self):
        return connect(self.cfg.db_path, readonly=True)

    def wdb(self):
        return connect(self.cfg.db_path)

    def rows(self, sql, params=()):
        with closing(self.db()) as c:
            return [dict(r) for r in c.execute(sql, params)]

    def one(self, sql, params=()):
        r = self.rows(sql, params)
        return r[0] if r else None

    def execute(self, sql, params=()):
        with closing(self.wdb()) as c:
            return c.execute(sql, params).rowcount

    @staticmethod
    def jsonf(d, *keys):
        for k in keys:
            if d and isinstance(d.get(k), str):
                d[k] = json.loads(d[k] or "null")
        return d
