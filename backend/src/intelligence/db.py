"""
SQLite database manager for TunaMail Stage 5 local intelligence persistence.

Schema:
  ioc_records    - Historical IOC observations
  campaigns      - Detected phishing campaigns
  feedback       - Analyst feedback (automated verdict preserved separately)
  cases          - SOC investigation cases
  case_notes     - Notes attached to investigation cases
  audit_log      - Immutable analyst action log (no credentials stored)
  indicators     - Temporal first/last seen tracker
"""

import sqlite3
import os
import logging
from contextlib import contextmanager

logger = logging.getLogger(__name__)

_DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data")
_DB_PATH = os.path.join(_DB_DIR, "intelligence.db")

_CREATE_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS ioc_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        normalized TEXT NOT NULL,
        source TEXT,
        message_id TEXT,
        confidence REAL DEFAULT 0.5,
        first_seen TEXT,
        last_seen TEXT,
        occurrences INTEGER DEFAULT 1
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ioc_normalized ON ioc_records(normalized)",
    "CREATE INDEX IF NOT EXISTS idx_ioc_message ON ioc_records(message_id)",
    """
    CREATE TABLE IF NOT EXISTS campaigns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        campaign_id TEXT UNIQUE NOT NULL,
        confidence INTEGER DEFAULT 0,
        shared_indicators TEXT DEFAULT '[]',
        related_messages TEXT DEFAULT '[]',
        attack_pattern TEXT,
        created_at TEXT,
        updated_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id TEXT NOT NULL,
        automated_verdict TEXT,
        analyst_verdict TEXT NOT NULL,
        comment TEXT,
        submitted_at TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_feedback_message ON feedback(message_id)",
    """
    CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT UNIQUE NOT NULL,
        title TEXT,
        status TEXT DEFAULT 'OPEN',
        messages TEXT DEFAULT '[]',
        iocs TEXT DEFAULT '[]',
        domains TEXT DEFAULT '[]',
        created_at TEXT,
        updated_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS case_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL,
        note TEXT,
        created_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        actor TEXT DEFAULT 'analyst',
        details TEXT DEFAULT '{}',
        timestamp TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator TEXT UNIQUE NOT NULL,
        indicator_type TEXT,
        first_seen TEXT,
        last_seen TEXT,
        occurrences INTEGER DEFAULT 1,
        tags TEXT DEFAULT '[]'
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_indicator ON indicators(indicator)",
]


def _get_db_path():
    return os.environ.get("TUNAMAIL_DB_PATH", _DB_PATH)


def init_db():
    """Initialize the SQLite database and create tables if they don't exist."""
    db_path = _get_db_path()
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        for stmt in _CREATE_STATEMENTS:
            conn.execute(stmt)
        conn.commit()
        conn.close()
        logger.info(f"Intelligence DB initialized at {db_path}")
    except Exception as e:
        logger.error(f"Failed to initialize intelligence DB: {e}")


@contextmanager
def get_db():
    """Context manager that yields a thread-safe SQLite connection."""
    db_path = _get_db_path()
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def row_to_dict(row):
    """Convert a sqlite3.Row to a plain dict."""
    if row is None:
        return None
    return dict(row)


def rows_to_list(rows):
    """Convert a list of sqlite3.Row objects to plain dicts."""
    return [dict(r) for r in rows]
