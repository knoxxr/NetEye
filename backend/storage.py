"""SQLite persistence for assets, links and alerts (JSON documents keyed by id)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import Lock


SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS links (key TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    key TEXT UNIQUE NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS alerts_last_seen ON alerts(last_seen);
CREATE TABLE IF NOT EXISTS baseline (kind TEXT NOT NULL, key TEXT NOT NULL, PRIMARY KEY (kind, key));
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)

    def load(self) -> tuple[list[dict], list[dict], list[dict]]:
        with self._lock:
            assets = [json.loads(r[0]) for r in self._conn.execute("SELECT data FROM assets")]
            links = [json.loads(r[0]) for r in self._conn.execute("SELECT data FROM links")]
            alerts = [json.loads(r[0]) for r in self._conn.execute("SELECT data FROM alerts ORDER BY id")]
        return assets, links, alerts

    def save(self, assets: list[dict], links: list[tuple[str, dict]], alerts: list[dict],
             deleted_assets: list[str], deleted_links: list[str]) -> None:
        if not (assets or links or alerts or deleted_assets or deleted_links):
            return
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT INTO assets(id, data) VALUES(?, ?) ON CONFLICT(id) DO UPDATE SET data=excluded.data",
                [(a["id"], json.dumps(a, ensure_ascii=False)) for a in assets])
            self._conn.executemany(
                "INSERT INTO links(key, data) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET data=excluded.data",
                [(k, json.dumps(l, ensure_ascii=False)) for k, l in links])
            self._conn.executemany(
                "INSERT INTO alerts(id, key, severity, status, last_seen, data) VALUES(?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET severity=excluded.severity, status=excluded.status, "
                "last_seen=excluded.last_seen, data=excluded.data",
                [(a["id"], a["key"], a["severity"], a["status"], a["last_seen"],
                  json.dumps(a, ensure_ascii=False)) for a in alerts])
            self._conn.executemany("DELETE FROM assets WHERE id=?", [(i,) for i in deleted_assets])
            self._conn.executemany("DELETE FROM links WHERE key=?", [(k,) for k in deleted_links])

    def load_baseline(self) -> tuple[dict | None, list[tuple[str, str]]]:
        with self._lock:
            row = self._conn.execute("SELECT v FROM meta WHERE k='baseline'").fetchone()
            items = [(kind, key) for kind, key in self._conn.execute("SELECT kind, key FROM baseline")]
        return (json.loads(row[0]) if row else None), items

    def save_baseline(self, items: list[tuple[str, str]], replace: bool, meta: dict | None) -> None:
        if not (items or replace or meta):
            return
        with self._lock, self._conn:
            if replace:
                self._conn.execute("DELETE FROM baseline")
            self._conn.executemany("INSERT OR IGNORE INTO baseline(kind, key) VALUES(?, ?)", items)
            if meta is not None:
                self._conn.execute(
                    "INSERT INTO meta(k, v) VALUES('baseline', ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                    (json.dumps(meta),))

    def clear(self) -> None:
        with self._lock, self._conn:
            for table in ("assets", "links", "alerts"):
                self._conn.execute(f"DELETE FROM {table}")

    def close(self) -> None:
        with self._lock:
            self._conn.close()


