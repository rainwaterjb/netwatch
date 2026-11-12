"""SQLite storage for devices and events."""
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac            TEXT PRIMARY KEY,
    ip             TEXT,
    hostname       TEXT,
    vendor         TEXT,
    nickname       TEXT,
    first_seen     REAL,
    last_seen      REAL,
    online         INTEGER NOT NULL DEFAULT 0,
    online_since   REAL,
    missed_scans   INTEGER NOT NULL DEFAULT 0,
    notify_phone   INTEGER NOT NULL DEFAULT 0,
    notify_email   INTEGER NOT NULL DEFAULT 0,
    notify_return  INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      REAL NOT NULL,
    mac     TEXT,
    ip      TEXT,
    kind    TEXT NOT NULL,
    detail  TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
"""

DEVICE_COLUMNS = {
    "ip", "hostname", "vendor", "nickname", "first_seen", "last_seen", "online",
    "online_since", "missed_scans", "notify_phone", "notify_email", "notify_return",
}


class Store:
    def __init__(self, path):
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def _query(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def _exec(self, sql, args=()):
        with self.lock:
            cur = self.conn.execute(sql, args)
            self.conn.commit()
            return cur.rowcount

    # Devices
    def get_device(self, mac):
        rows = self._query("SELECT * FROM devices WHERE mac = ?", (mac,))
        return rows[0] if rows else None

    def all_devices(self):
        return self._query("SELECT * FROM devices")

    def online_devices(self):
        return self._query("SELECT * FROM devices WHERE online = 1")

    def insert_device(self, mac, **fields):
        fields = {k: v for k, v in fields.items() if k in DEVICE_COLUMNS}
        cols = ["mac", *fields]
        self._exec(
            f"INSERT INTO devices ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
            (mac, *fields.values()),
        )

    def update_device(self, mac, **fields):
        fields = {k: v for k, v in fields.items() if k in DEVICE_COLUMNS}
        if not fields:
            return 0
        sets = ", ".join(f"{k} = ?" for k in fields)
        return self._exec(f"UPDATE devices SET {sets} WHERE mac = ?", (*fields.values(), mac))

    def delete_device(self, mac):
        return self._exec("DELETE FROM devices WHERE mac = ?", (mac,))

    # Events
    def add_event(self, kind, mac=None, ip=None, detail=None, ts=None):
        self._exec(
            "INSERT INTO events (ts, mac, ip, kind, detail) VALUES (?, ?, ?, ?, ?)",
            (ts or time.time(), mac, ip, kind, detail),
        )

    def events(self, limit=200, mac=None):
        if mac:
            return self._query(
                "SELECT * FROM events WHERE mac = ? ORDER BY ts DESC LIMIT ?", (mac, limit))
        return self._query("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))

    def prune_events(self, older_than_ts):
        return self._exec("DELETE FROM events WHERE ts < ?", (older_than_ts,))
