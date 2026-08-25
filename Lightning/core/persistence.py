"""
=============================================================================
                  LIGHTNING - PERSISTENT STORAGE ENGINE (SQLite)
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
Stores threat logs, quarantine records, statistics, and configuration across
reboots using a local SQLite database. Zero external dependencies.
"""

import os
import sys
import time
import json
import sqlite3
import threading
import datetime
from typing import List, Dict, Optional, Tuple

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lightning_data.db")


class PersistenceEngine:
    """
    Thread-safe SQLite persistence layer for LIGHTNING.
    Stores: threat_events, quarantine_bans, stats_snapshots, config.
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._local = threading.local()
        self._init_lock = threading.Lock()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Returns a thread-local database connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, timeout=10)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def _init_db(self):
        """Creates the database schema if it doesn't exist."""
        with self._init_lock:
            conn = self._get_conn()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS threat_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                    ip TEXT NOT NULL,
                    method TEXT,
                    path TEXT,
                    category TEXT NOT NULL,
                    description TEXT,
                    severity TEXT DEFAULT 'MEDIUM',
                    payload_snippet TEXT,
                    action TEXT DEFAULT 'BLOCKED',
                    session_id TEXT
                );

                CREATE TABLE IF NOT EXISTS quarantine_bans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL UNIQUE,
                    reason TEXT,
                    banned_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                    expires_at TEXT,
                    is_permanent INTEGER DEFAULT 0,
                    ban_count INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS stats_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                    total_requests INTEGER DEFAULT 0,
                    total_blocked INTEGER DEFAULT 0,
                    total_warnings INTEGER DEFAULT 0,
                    categories_json TEXT DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS threat_intel_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL UNIQUE,
                    source TEXT NOT NULL,
                    threat_type TEXT,
                    confidence INTEGER DEFAULT 50,
                    added_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                    expires_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_threat_ip ON threat_events(ip);
                CREATE INDEX IF NOT EXISTS idx_threat_category ON threat_events(category);
                CREATE INDEX IF NOT EXISTS idx_threat_time ON threat_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_quarantine_ip ON quarantine_bans(ip);
                CREATE INDEX IF NOT EXISTS idx_intel_ip ON threat_intel_ips(ip);
            """)
            conn.commit()

    # ── Threat Event Recording ──────────────────────────────────────────────

    def record_threat(self, ip: str, method: str, path: str, category: str,
                      description: str = "", severity: str = "MEDIUM",
                      snippet: str = "", action: str = "BLOCKED") -> int:
        """Records a single threat event and returns the row ID."""
        conn = self._get_conn()
        cursor = conn.execute(
            """INSERT INTO threat_events (ip, method, path, category, description, severity, payload_snippet, action)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (ip, method, path, category, description, severity, snippet[:500], action)
        )
        conn.commit()
        return cursor.lastrowid

    def get_recent_threats(self, limit: int = 50) -> List[Dict]:
        """Returns the most recent threat events."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM threat_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_threat_count(self) -> int:
        """Returns total number of recorded threats."""
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) as cnt FROM threat_events").fetchone()
        return row["cnt"] if row else 0

    def get_threats_by_category(self) -> Dict[str, int]:
        """Returns threat counts grouped by category."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT category, COUNT(*) as cnt FROM threat_events GROUP BY category ORDER BY cnt DESC"
        ).fetchall()
        return {r["category"]: r["cnt"] for r in rows}

    def get_threats_by_ip(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Returns the top attacking IPs by event count."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT ip, COUNT(*) as cnt FROM threat_events GROUP BY ip ORDER BY cnt DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [(r["ip"], r["cnt"]) for r in rows]

    def get_threats_today(self) -> int:
        """Returns threat count for today."""
        today = datetime.date.today().isoformat()
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM threat_events WHERE timestamp >= ?", (today,)
        ).fetchone()
        return row["cnt"] if row else 0

    # ── Quarantine Persistence ──────────────────────────────────────────────

    def persist_ban(self, ip: str, reason: str, duration_seconds: int = 300, permanent: bool = False):
        """Records or updates a quarantine ban record."""
        conn = self._get_conn()
        expires = None
        if not permanent and duration_seconds > 0:
            expires = (datetime.datetime.now() + datetime.timedelta(seconds=duration_seconds)).isoformat()

        conn.execute(
            """INSERT INTO quarantine_bans (ip, reason, expires_at, is_permanent, ban_count)
               VALUES (?, ?, ?, ?, 1)
               ON CONFLICT(ip) DO UPDATE SET
                   reason = excluded.reason,
                   expires_at = excluded.expires_at,
                   is_permanent = excluded.is_permanent,
                   ban_count = ban_count + 1""",
            (ip, reason, expires, 1 if permanent else 0)
        )
        conn.commit()

    def remove_ban(self, ip: str):
        """Removes a quarantine ban record."""
        conn = self._get_conn()
        conn.execute("DELETE FROM quarantine_bans WHERE ip = ?", (ip,))
        conn.commit()

    def get_active_bans(self) -> List[Dict]:
        """Returns all currently active (non-expired) bans."""
        conn = self._get_conn()
        now = datetime.datetime.now().isoformat()
        rows = conn.execute(
            """SELECT * FROM quarantine_bans
               WHERE is_permanent = 1 OR expires_at IS NULL OR expires_at > ?
               ORDER BY banned_at DESC""",
            (now,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_repeat_offender_count(self, ip: str) -> int:
        """Returns how many times an IP has been banned historically."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT ban_count FROM quarantine_bans WHERE ip = ?", (ip,)
        ).fetchone()
        return row["ban_count"] if row else 0

    # ── Threat Intel Feed Storage ──────────────────────────────────────────

    def store_threat_intel_ip(self, ip: str, source: str, threat_type: str = "malicious",
                              confidence: int = 80, ttl_hours: int = 24):
        """Stores a known-malicious IP from a threat intelligence feed."""
        conn = self._get_conn()
        expires = (datetime.datetime.now() + datetime.timedelta(hours=ttl_hours)).isoformat()
        conn.execute(
            """INSERT INTO threat_intel_ips (ip, source, threat_type, confidence, expires_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(ip) DO UPDATE SET
                   source = excluded.source,
                   confidence = excluded.confidence,
                   expires_at = excluded.expires_at""",
            (ip, source, threat_type, confidence, expires)
        )
        conn.commit()

    def is_known_threat_ip(self, ip: str) -> Optional[Dict]:
        """Checks if an IP is in the threat intelligence database."""
        conn = self._get_conn()
        now = datetime.datetime.now().isoformat()
        row = conn.execute(
            "SELECT * FROM threat_intel_ips WHERE ip = ? AND (expires_at IS NULL OR expires_at > ?)",
            (ip, now)
        ).fetchone()
        return dict(row) if row else None

    def get_threat_intel_count(self) -> int:
        """Returns the number of IPs in the threat intel database."""
        conn = self._get_conn()
        now = datetime.datetime.now().isoformat()
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM threat_intel_ips WHERE expires_at IS NULL OR expires_at > ?",
            (now,)
        ).fetchone()
        return row["cnt"] if row else 0

    # ── Stats Snapshots ────────────────────────────────────────────────────

    def save_stats_snapshot(self, total: int, blocked: int, warnings: int, categories: Dict[str, int]):
        """Saves a periodic stats snapshot for historical charting."""
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO stats_snapshots (total_requests, total_blocked, total_warnings, categories_json)
               VALUES (?, ?, ?, ?)""",
            (total, blocked, warnings, json.dumps(categories))
        )
        conn.commit()

    def get_stats_history(self, limit: int = 100) -> List[Dict]:
        """Returns recent stats snapshots."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM stats_snapshots ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Utility ────────────────────────────────────────────────────────────

    def get_database_size_kb(self) -> float:
        """Returns the database file size in KB."""
        try:
            return os.path.getsize(self.db_path) / 1024.0
        except Exception:
            return 0.0

    def vacuum(self):
        """Reclaims unused space in the database file."""
        conn = self._get_conn()
        conn.execute("VACUUM")

    def close(self):
        """Closes the thread-local database connection."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
