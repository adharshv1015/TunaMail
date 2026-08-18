"""
Immutable Audit Log for TunaMail Stage 5.

Records important analyst actions for accountability.
NEVER logs OAuth tokens, session cookies, passwords, or private credentials.

Logged actions:
    email_viewed,
    case_created,
    case_closed,
    ioc_marked_trusted,
    ioc_marked_suspicious,
    case_note_added
"""

import json
import logging
from datetime import datetime, timezone

from src.intelligence.db import get_db, rows_to_list

logger = logging.getLogger(__name__)

# Fields that must never appear in audit log details
_FORBIDDEN_FIELDS = {
    "access_token",
    "refresh_token",
    "token",
    "session_id",
    "cookie",
    "password",
    "secret",
    "credentials",
    "private_key",
    "api_key",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sanitize_details(details: dict) -> dict:
    """Remove any sensitive fields from audit log details."""
    if not details:
        return {}

    return {
        k: v
        for k, v in details.items()
        if k.lower() not in _FORBIDDEN_FIELDS
    }


class AuditLog:
    """
    Append-only audit trail for analyst actions.
    All writes are INSERT-only — no updates or deletes.
    """

    def log(
        self,
        action: str,
        details: dict = None,
        actor: str = "analyst",
    ) -> bool:
        """
        Record an analyst action in the audit log.

        Args:
            action: Action name (e.g., 'email_viewed')
            details: Supporting details (sanitized before storage)
            actor: Who performed the action

        Returns:
            True if logged successfully, False otherwise
        """
        now = _now_iso()
        safe_details = _sanitize_details(details or {})

        try:
            with get_db() as conn:
                conn.execute(
                    """
                    INSERT INTO audit_log
                        (action, actor, details, timestamp)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        action,
                        actor,
                        json.dumps(safe_details),
                        now,
                    ),
                )
            return True

        except Exception as e:
            logger.error(f"AuditLog.log error: {e}")
            return False

    def get_recent(self, limit: int = 100) -> list:
        """Retrieve recent audit log entries."""
        try:
            with get_db() as conn:
                rows = conn.execute(
                    """
                    SELECT *
                    FROM audit_log
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()

                results = rows_to_list(rows)

                for r in results:
                    try:
                        r["details"] = json.loads(
                            r.get("details", "{}")
                        )
                    except Exception:
                        r["details"] = {}

                return results

        except Exception as e:
            logger.error(f"AuditLog.get_recent error: {e}")
            return []

    def get_for_message(self, message_id: str) -> list:
        """Get audit entries related to a specific message."""
        try:
            with get_db() as conn:
                rows = conn.execute(
                    """
                    SELECT *
                    FROM audit_log
                    WHERE details LIKE ?
                    ORDER BY timestamp DESC
                    """,
                    (f'%"{message_id}"%',),
                ).fetchall()

                results = rows_to_list(rows)

                for r in results:
                    try:
                        r["details"] = json.loads(
                            r.get("details", "{}")
                        )
                    except Exception:
                        r["details"] = {}

                return results

        except Exception as e:
            logger.error(f"AuditLog.get_for_message error: {e}")
            return []