"""SQLite persistence (events, pending approvals, kills, flags, classifier verdicts, conversation canaries, the
plans of the opt-in planner, for the seamless proxy the facts learned from the app's tools and the calls held while
they are looked up, for private_data the encrypted vault of values that outlive a request, the console's runtime
settings, and the ⑥ attack memory's `attacks`, which may also live in a database of its own: LAOCOON_MEMORY_DB).

Everything that must be shared between gunicorn workers lives here, never in memory.
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, turn_id TEXT, user_id INTEGER, username TEXT, role TEXT,
  stage TEXT NOT NULL, tool TEXT, args TEXT, action TEXT, rule TEXT, severity TEXT, reason TEXT,
  provenance TEXT, prev_hash TEXT NOT NULL, hash TEXT NOT NULL, conversation TEXT);
CREATE TABLE IF NOT EXISTS pending (
  id TEXT PRIMARY KEY, turn_id TEXT, user_id INTEGER NOT NULL, tool TEXT NOT NULL, args TEXT NOT NULL,
  token TEXT NOT NULL, preview TEXT, reason TEXT, provenance TEXT, created_at REAL NOT NULL,
  expires_at REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending');
CREATE TABLE IF NOT EXISTS kills (
  scope TEXT NOT NULL, key TEXT NOT NULL, reason TEXT, created_at REAL, expires_at REAL,
  PRIMARY KEY (scope, key));
CREATE TABLE IF NOT EXISTS flags (
  id INTEGER PRIMARY KEY, kind TEXT, ref TEXT, author_id INTEGER, author TEXT, score REAL, findings TEXT,
  excerpt TEXT, status TEXT DEFAULT 'open', created_at TEXT);
CREATE TABLE IF NOT EXISTS verdicts (
  key TEXT PRIMARY KEY, point TEXT, model TEXT, label TEXT, score REAL, scores TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS canaries (
  conversation_key TEXT PRIMARY KEY, user_id INTEGER, created_at REAL);
CREATE TABLE IF NOT EXISTS pacts (
  key TEXT PRIMARY KEY, user_id INTEGER, conversation TEXT, status TEXT, tools TEXT, model TEXT, error TEXT,
  usage TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS facts (
  user_id INTEGER NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL, data TEXT NOT NULL, at REAL NOT NULL,
  PRIMARY KEY (user_id, kind, key));
CREATE TABLE IF NOT EXISTS holds (
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, conversation TEXT, kind TEXT NOT NULL, round INTEGER NOT NULL,
  lookups TEXT NOT NULL, done TEXT NOT NULL, payload TEXT, created_at REAL NOT NULL, expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS pd_vault (
  conversation_key TEXT NOT NULL, cls TEXT NOT NULL, id TEXT NOT NULL, bucket TEXT, enc_value TEXT NOT NULL,
  origin TEXT, subject TEXT, user_id INTEGER, created_at REAL NOT NULL, expires_at REAL NOT NULL,
  PRIMARY KEY (conversation_key, cls, id));
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at REAL NOT NULL, updated_by TEXT);
CREATE TABLE IF NOT EXISTS attacks (
  id INTEGER PRIMARY KEY, fp TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, label TEXT, text TEXT NOT NULL,
  origin TEXT, evidence TEXT, ref TEXT, user_id INTEGER, conversation TEXT, approval_id TEXT, anchor TEXT,
  seen INTEGER NOT NULL DEFAULT 1, hits INTEGER NOT NULL DEFAULT 0, last_hit REAL, created_at REAL NOT NULL,
  updated_at REAL NOT NULL, decided_by TEXT);
CREATE INDEX IF NOT EXISTS events_user ON events(user_id, ts);
CREATE INDEX IF NOT EXISTS attacks_status ON attacks(status, updated_at);
CREATE INDEX IF NOT EXISTS attacks_fp ON attacks(fp);
CREATE INDEX IF NOT EXISTS attacks_approval ON attacks(approval_id);
"""


def _add_column(conn, table, column, decl="TEXT"):
    """ALTER TABLE ... ADD COLUMN unless the column exists. Another worker (another process, or another Store on the
    same file) can add it between the check and the ALTER: "duplicate column name" then means it is there."""
    if column in {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}:
        return
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
    except sqlite3.OperationalError as e:
        if "duplicate column" not in str(e).lower():
            raise


class Store:
    def __init__(self, path: str):
        self.path = path
        self._init_lock = threading.Lock()
        self._initialised_inode = None

    def _ensure_schema(self, conn):
        # Re-run the (idempotent) schema whenever the file is new, e.g. after the eval harness deletes it. The inode
        # alone does not tell: ext4 gives a deleted file's inode number to the next file at once, so an empty
        # database (schema_version 0: no table was ever created in it) also counts as new.
        try:
            inode = os.stat(self.path).st_ino
        except OSError:
            inode = None
        empty = conn.execute("PRAGMA schema_version").fetchone()[0] == 0
        if empty or inode is None or inode != self._initialised_inode:
            with self._init_lock:
                conn.executescript(SCHEMA)
                _add_column(conn, "events", "conversation")   # a v0.1 database: the column is new in v0.2
                _add_column(conn, "pending", "args_enc")      # private_data: real args, AES-GCM
                _add_column(conn, "attacks", "anchor")        # ⑥ a memory from before anchors
                self._initialised_inode = os.stat(self.path).st_ino

    def connect(self) -> sqlite3.Connection:
        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=15000")
        self._wal(conn)
        self._ensure_schema(conn)
        return conn

    @staticmethod
    def _wal(conn, attempts=50):
        """WAL is a property of the file: set it once. Switching needs an exclusive lock and SQLite does not wait for it
        (busy_timeout does not apply), so two workers opening a brand-new file at once could fail with "database is
        locked". Retry briefly instead."""
        for i in range(attempts):
            try:
                if conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal":
                    return
                conn.execute("PRAGMA journal_mode=WAL")
                return
            except sqlite3.OperationalError:
                if i == attempts - 1:
                    raise
                time.sleep(0.02 * (i + 1))

    @contextmanager
    def tx(self, immediate=False):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def query(self, sql, args=(), one=False):
        conn = self.connect()
        try:
            rows = [dict(r) for r in conn.execute(sql, args).fetchall()]
        finally:
            conn.close()
        return (rows[0] if rows else None) if one else rows

    def execute(self, sql, args=()):
        with self.tx() as conn:
            cur = conn.execute(sql, args)
            return cur.lastrowid, cur.rowcount
