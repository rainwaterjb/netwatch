"""SQLite storage for devices, events, service checks, outages and settings.

Schema changes are additive only (new columns with defaults, new tables), so
older NetWatch versions can still open the database after an upgrade. That is
what keeps ./update.sh <older-version> safe.
"""
import json
import logging
import os
import sqlite3
import threading
import time

_activity_log = logging.getLogger("netwatch.activity")
LOG_ACTIVITY = os.getenv("LOG_ACTIVITY", "false").lower() in ("1", "true", "yes", "on")

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
CREATE INDEX IF NOT EXISTS idx_events_mac_ts ON events(mac, ts);

CREATE TABLE IF NOT EXISTS settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_alerts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    title    TEXT NOT NULL,
    message  TEXT NOT NULL,
    phone    INTEGER NOT NULL DEFAULT 0,
    email    INTEGER NOT NULL DEFAULT 0,
    reason   TEXT
);
CREATE TABLE IF NOT EXISTS checks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL,            -- tcp | http | ping
    mac             TEXT,                     -- follow this device's current IP
    host            TEXT,                     -- or a fixed host/IP
    port            INTEGER,
    path            TEXT,
    https           INTEGER NOT NULL DEFAULT 0,
    verify_tls      INTEGER NOT NULL DEFAULT 1,
    interval        INTEGER NOT NULL DEFAULT 60,
    timeout         REAL NOT NULL DEFAULT 5,
    fail_after      INTEGER NOT NULL DEFAULT 2,
    notify_phone    INTEGER NOT NULL DEFAULT 0,
    notify_email    INTEGER NOT NULL DEFAULT 0,
    enabled         INTEGER NOT NULL DEFAULT 1,
    state           TEXT NOT NULL DEFAULT 'unknown',
    since           REAL,
    last_check      REAL,
    last_latency_ms REAL,
    last_error      TEXT,
    fails           INTEGER NOT NULL DEFAULT 0,
    created         REAL
);
CREATE TABLE IF NOT EXISTS check_results (
    check_id    INTEGER NOT NULL,
    ts          REAL NOT NULL,
    ok          INTEGER NOT NULL,
    latency_ms  REAL
);
CREATE INDEX IF NOT EXISTS idx_check_results ON check_results(check_id, ts);
CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL DEFAULT 'viewer',    -- admin | viewer
    created        REAL,
    last_login     REAL,
    disabled       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    id_hash     TEXT PRIMARY KEY,                     -- SHA-256 of the cookie value
    user_id     INTEGER NOT NULL,                     -- 0 = built-in admin from .env
    cred_tag    TEXT NOT NULL,                        -- changes when the password does
    created     REAL NOT NULL,
    last_seen   REAL NOT NULL,
    expires     REAL NOT NULL,
    ip          TEXT,
    user_agent  TEXT
);
CREATE TABLE IF NOT EXISTS api_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,                 -- SHA-256 of the token
    prefix      TEXT NOT NULL,                        -- first characters, to recognise it
    role        TEXT NOT NULL DEFAULT 'viewer',
    created_by  INTEGER,
    created     REAL,
    expires     REAL,
    last_used   REAL,
    revoked     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS alert_channels (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,                        -- discord | slack | telegram | gotify | ntfy | webhook | mqtt
    config      TEXT NOT NULL DEFAULT '{}',           -- JSON; includes secrets
    enabled     INTEGER NOT NULL DEFAULT 1,
    created     REAL,
    last_sent   REAL,
    last_result TEXT
);
CREATE TABLE IF NOT EXISTS alert_rules (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL,
    enabled           INTEGER NOT NULL DEFAULT 1,
    event             TEXT NOT NULL,                  -- device_offline | device_new | service_down | internet_down | chatty
    scope             TEXT NOT NULL DEFAULT '{}',     -- JSON: which devices / checks
    delay_min         INTEGER NOT NULL DEFAULT 0,     -- only alert if it lasts this long
    channels          TEXT NOT NULL DEFAULT '[]',     -- JSON: "phone", "email", channel ids
    notify_resolved   INTEGER NOT NULL DEFAULT 0,
    ignore_quiet      INTEGER NOT NULL DEFAULT 0,
    escalate_min      INTEGER NOT NULL DEFAULT 0,     -- 0 = no escalation
    escalate_channels TEXT NOT NULL DEFAULT '[]',
    created           REAL
);
CREATE TABLE IF NOT EXISTS alert_incidents (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id       INTEGER NOT NULL,
    event         TEXT NOT NULL,
    subject       TEXT NOT NULL,                      -- device MAC, check:<id> or internet
    mac           TEXT,
    title         TEXT NOT NULL,
    message       TEXT NOT NULL,
    critical      INTEGER NOT NULL DEFAULT 0,
    created       REAL NOT NULL,
    due           REAL,                               -- when to send (NULL = wait for the end of an outage)
    state         TEXT NOT NULL,                      -- pending | sent | resolved | cancelled
    attempts      INTEGER NOT NULL DEFAULT 0,
    sent_at       REAL,
    acked_at      REAL,
    acked_by      TEXT,
    escalated_at  REAL,
    resolved_at   REAL,
    result        TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_open ON alert_incidents(state, subject);
CREATE TABLE IF NOT EXISTS fingerprints (
    mac         TEXT NOT NULL,
    key         TEXT NOT NULL,                        -- e.g. dhcp:hostname, mdns:services, ssdp:modelName
    value       TEXT,
    first_seen  REAL,
    last_seen   REAL,
    PRIMARY KEY (mac, key)
);
CREATE TABLE IF NOT EXISTS identity_links (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    mac         TEXT NOT NULL,                        -- the newer (private) address
    other       TEXT NOT NULL,                        -- the device it seems to be
    state       TEXT NOT NULL,                        -- suggested | confirmed | rejected
    score       INTEGER,
    reason      TEXT,
    created     REAL,
    decided     REAL,
    decided_by  TEXT,
    UNIQUE (mac, other)
);
CREATE TABLE IF NOT EXISTS push_subscriptions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint    TEXT NOT NULL UNIQUE,                 -- the browser's push-service address
    p256dh      TEXT NOT NULL,                        -- the browser's public key (messages are encrypted to it)
    auth        TEXT NOT NULL,
    username    TEXT,
    user_id     INTEGER,
    label       TEXT,                                 -- e.g. "iPhone · Safari"
    created     REAL,
    last_ok     REAL,
    last_error  TEXT,
    fails       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS user_prefs (
    owner       TEXT PRIMARY KEY,                     -- "user:<id>" (0 = built-in admin), "token:<id>" or "open"
    prefs       TEXT NOT NULL,                        -- JSON: theme, status colors, home layout, pinned devices
    updated     REAL
);
CREATE TABLE IF NOT EXISTS outages (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    start   REAL NOT NULL,
    end     REAL,
    cause   TEXT NOT NULL,                    -- internet | router
    detail  TEXT
);
"""

# Columns added to the users table (v1.8.0) by later versions.
USER_MIGRATIONS = [
    ("sso_issuer", "TEXT"),     # v1.9.0: set for single sign-on accounts
    ("sso_subject", "TEXT"),
]

# Columns added after v1.4.0: (name, definition). Existing devices count as
# already known (acknowledged=1); new ones are inserted with acknowledged=0.
DEVICE_MIGRATIONS = [
    ("acknowledged", "INTEGER NOT NULL DEFAULT 1"),
    ("tags", "TEXT NOT NULL DEFAULT ''"),
    ("snooze_until", "REAL"),
    ("critical", "INTEGER NOT NULL DEFAULT 0"),
    # v1.11.0: recognition and private-address linking
    ("device_type", "TEXT"),
    ("model", "TEXT"),
    ("os", "TEXT"),
    ("type_source", "TEXT"),
    ("type_manual", "INTEGER NOT NULL DEFAULT 0"),
    ("same_as", "TEXT"),                    # set on an old address linked to a newer one
]
CHECK_COLUMNS = {
    "name", "kind", "mac", "host", "port", "path", "https", "verify_tls", "interval", "timeout",
    "fail_after", "notify_phone", "notify_email", "enabled", "state", "since", "last_check",
    "last_latency_ms", "last_error", "fails", "created",
}

DEVICE_COLUMNS = {
    "ip", "hostname", "vendor", "nickname", "first_seen", "last_seen", "online",
    "online_since", "missed_scans", "notify_phone", "notify_email", "notify_return",
    "acknowledged", "tags", "snooze_until", "critical",
    "device_type", "model", "os", "type_source", "type_manual", "same_as",
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
            have = {r[1] for r in self.conn.execute("PRAGMA table_info(devices)")}
            for name, definition in DEVICE_MIGRATIONS:
                if name not in have:
                    self.conn.execute(f"ALTER TABLE devices ADD COLUMN {name} {definition}")
            have = {r[1] for r in self.conn.execute("PRAGMA table_info(users)")}
            for name, definition in USER_MIGRATIONS:
                if name not in have:
                    self.conn.execute(f"ALTER TABLE users ADD COLUMN {name} {definition}")
            self.conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_sso ON users(sso_issuer, sso_subject) "
                              "WHERE sso_subject IS NOT NULL")
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
        if LOG_ACTIVITY:                       # also send Activity entries to the logs (e.g. for Loki)
            _activity_log.info("%s: %s", kind, detail or "", extra={"event": kind, "mac": mac, "ip": ip})

    def events(self, limit=200, mac=None):
        if mac:
            return self._query(
                "SELECT * FROM events WHERE mac = ? ORDER BY ts DESC LIMIT ?", (mac, limit))
        return self._query("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))

    def prune_events(self, older_than_ts):
        return self._exec("DELETE FROM events WHERE ts < ?", (older_than_ts,))

    def events_between(self, mac, since, until, kinds=None):
        q = "SELECT * FROM events WHERE mac = ? AND ts >= ? AND ts <= ?"
        args = [mac, since, until]
        if kinds:
            q += f" AND kind IN ({','.join('?' * len(kinds))})"
            args += list(kinds)
        return self._query(q + " ORDER BY ts", args)

    def last_event_before(self, mac, ts, kinds):
        rows = self._query(
            f"SELECT * FROM events WHERE mac = ? AND ts < ? AND kind IN ({','.join('?' * len(kinds))}) "
            "ORDER BY ts DESC LIMIT 1", (mac, ts, *kinds))
        return rows[0] if rows else None

    def backup_to(self, path):
        """Consistent copy of the live database (safe while NetWatch is running)."""
        with self.lock:
            dest = sqlite3.connect(path)
            try:
                self.conn.backup(dest)
            finally:
                dest.close()

    # Per-person preferences (appearance, home layout)
    def get_prefs(self, owner):
        rows = self._query("SELECT prefs FROM user_prefs WHERE owner = ?", (owner,))
        return json.loads(rows[0]["prefs"]) if rows else None

    def set_prefs(self, owner, prefs):
        self._exec("INSERT INTO user_prefs (owner, prefs, updated) VALUES (?, ?, ?) "
                   "ON CONFLICT(owner) DO UPDATE SET prefs = excluded.prefs, updated = excluded.updated",
                   (owner, json.dumps(prefs, separators=(",", ":")), time.time()))

    def delete_prefs(self, owner):
        self._exec("DELETE FROM user_prefs WHERE owner = ?", (owner,))

    # Settings
    def get_settings(self):
        return {r["key"]: json.loads(r["value"]) for r in self._query("SELECT * FROM settings")}

    def set_settings(self, values):
        with self.lock:
            for k, v in values.items():
                self.conn.execute("INSERT INTO settings (key, value) VALUES (?, ?) "
                                  "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                                  (k, json.dumps(v)))
            self.conn.commit()

    # Pending (held) alerts
    def add_pending(self, title, message, phone, email, reason, ts=None):
        self._exec("INSERT INTO pending_alerts (ts, title, message, phone, email, reason) "
                   "VALUES (?, ?, ?, ?, ?, ?)",
                   (ts or time.time(), title, message, int(phone), int(email), reason))

    def take_pending(self):
        with self.lock:
            rows = [dict(r) for r in self.conn.execute("SELECT * FROM pending_alerts ORDER BY ts")]
            self.conn.execute("DELETE FROM pending_alerts")
            self.conn.commit()
            return rows

    def count_pending(self):
        return self._query("SELECT COUNT(*) AS n FROM pending_alerts")[0]["n"]

    # Service checks
    def checks(self):
        return self._query("SELECT * FROM checks ORDER BY name COLLATE NOCASE")

    def get_check(self, check_id):
        rows = self._query("SELECT * FROM checks WHERE id = ?", (check_id,))
        return rows[0] if rows else None

    def insert_check(self, **fields):
        fields = {k: v for k, v in fields.items() if k in CHECK_COLUMNS}
        with self.lock:
            cur = self.conn.execute(
                f"INSERT INTO checks ({', '.join(fields)}) VALUES ({', '.join('?' * len(fields))})",
                tuple(fields.values()))
            self.conn.commit()
            return cur.lastrowid

    def update_check(self, check_id, **fields):
        fields = {k: v for k, v in fields.items() if k in CHECK_COLUMNS}
        if not fields:
            return 0
        sets = ", ".join(f"{k} = ?" for k in fields)
        return self._exec(f"UPDATE checks SET {sets} WHERE id = ?", (*fields.values(), check_id))

    def delete_check(self, check_id):
        with self.lock:
            self.conn.execute("DELETE FROM check_results WHERE check_id = ?", (check_id,))
            cur = self.conn.execute("DELETE FROM checks WHERE id = ?", (check_id,))
            self.conn.commit()
            return cur.rowcount

    def add_check_result(self, check_id, ts, ok, latency_ms):
        self._exec("INSERT INTO check_results (check_id, ts, ok, latency_ms) VALUES (?, ?, ?, ?)",
                   (check_id, ts, int(ok), latency_ms))

    def check_results(self, check_id, since):
        return self._query("SELECT ts, ok, latency_ms FROM check_results WHERE check_id = ? AND ts >= ? "
                           "ORDER BY ts", (check_id, since))

    def prune_check_results(self, older_than_ts):
        return self._exec("DELETE FROM check_results WHERE ts < ?", (older_than_ts,))

    # Internet outages
    def open_outage(self, start, cause, detail=None):
        with self.lock:
            cur = self.conn.execute("INSERT INTO outages (start, cause, detail) VALUES (?, ?, ?)",
                                    (start, cause, detail))
            self.conn.commit()
            return cur.lastrowid

    def close_outage(self, outage_id, end):
        self._exec("UPDATE outages SET end = ? WHERE id = ?", (end, outage_id))

    def current_outage(self):
        rows = self._query("SELECT * FROM outages WHERE end IS NULL ORDER BY start DESC LIMIT 1")
        return rows[0] if rows else None

    def outages(self, limit=100, since=None):
        if since is not None:
            return self._query("SELECT * FROM outages WHERE COALESCE(end, 9e18) >= ? ORDER BY start DESC LIMIT ?",
                               (since, limit))
        return self._query("SELECT * FROM outages ORDER BY start DESC LIMIT ?", (limit,))
