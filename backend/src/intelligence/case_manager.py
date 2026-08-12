"""
Investigation Case Manager for TunaMail Stage 5.

Allows analysts to group related emails into investigation cases.
Cases are persisted to SQLite.

Case statuses:
    OPEN, INVESTIGATING, CONFIRMED, FALSE_POSITIVE, CLOSED
"""

import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

from src.intelligence.db import get_db, rows_to_list
from src.intelligence.audit_log import AuditLog

logger = logging.getLogger(__name__)

VALID_STATUSES = {"OPEN", "INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "CLOSED"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CaseManager:
    """
    CRUD operations for SOC investigation cases.
    """

    def create_case(
        self,
        title: str,
        messages: list = None,
        iocs: list = None,
        domains: list = None,
        actor: str = "analyst"
    ) -> dict:
        """Create a new investigation case."""
        now = _now_iso()
        case_id = f"CASE-{str(uuid.uuid4())[:8].upper()}"

        try:
            with get_db() as conn:
                conn.execute(
                    """INSERT INTO cases
                       (case_id, title, status, messages, iocs, domains, created_at, updated_at)
                       VALUES (?, ?, 'OPEN', ?, ?, ?, ?, ?)""",
                    (
                        case_id,
                        title,
                        json.dumps(messages or []),
                        json.dumps(iocs or []),
                        json.dumps(domains or []),
                        now,
                        now
                    )
                )
        except Exception as e:
            logger.error(f"CaseManager.create_case error: {e}")
            return {"success": False, "message": "Failed to create case."}

        AuditLog().log(
            "case_created",
            {"case_id": case_id, "title": title},
            actor=actor
        )

        return {
            "success": True,
            "case_id": case_id,
            "title": title,
            "status": "OPEN",
            "created_at": now
        }

    def get_case(self, case_id: str) -> Optional[dict]:
        """Get a case by ID."""
        try:
            with get_db() as conn:
                row = conn.execute(
                    "SELECT * FROM cases WHERE case_id = ?", (case_id,)
                ).fetchone()
                if not row:
                    return None
                case = dict(row)
                for field in ("messages", "iocs", "domains"):
                    try:
                        case[field] = json.loads(case.get(field, "[]") or "[]")
                    except Exception:
                        case[field] = []
                # Attach notes
                notes = conn.execute(
                    "SELECT * FROM case_notes WHERE case_id = ? ORDER BY created_at ASC",
                    (case_id,)
                ).fetchall()
                case["notes"] = rows_to_list(notes)
                return case
        except Exception as e:
            logger.error(f"CaseManager.get_case error: {e}")
            return None

    def list_cases(self, limit: int = 50) -> list:
        """List all cases, most recently updated first."""
        try:
            with get_db() as conn:
                rows = conn.execute(
                    "SELECT * FROM cases ORDER BY updated_at DESC LIMIT ?", (limit,)
                ).fetchall()
                results = rows_to_list(rows)
                for r in results:
                    for field in ("messages", "iocs", "domains"):
                        try:
                            r[field] = json.loads(r.get(field, "[]") or "[]")
                        except Exception:
                            r[field] = []
                return results
        except Exception as e:
            logger.error(f"CaseManager.list_cases error: {e}")
            return []

    def update_status(self, case_id: str, status: str, actor: str = "analyst") -> dict:
        """Update case status."""
        if status not in VALID_STATUSES:
            return {"success": False, "message": f"Invalid status. Must be one of: {', '.join(VALID_STATUSES)}"}
        now = _now_iso()
        try:
            with get_db() as conn:
                conn.execute(
                    "UPDATE cases SET status = ?, updated_at = ? WHERE case_id = ?",
                    (status, now, case_id)
                )
        except Exception as e:
            logger.error(f"CaseManager.update_status error: {e}")
            return {"success": False, "message": "Failed to update case status."}

        action = "case_closed" if status == "CLOSED" else "case_status_updated"
        AuditLog().log(action, {"case_id": case_id, "status": status}, actor=actor)

        return {"success": True, "case_id": case_id, "status": status}

    def add_message(self, case_id: str, message_id: str) -> dict:
        """Add a message ID to a case."""
        case = self.get_case(case_id)
        if not case:
            return {"success": False, "message": "Case not found."}
        messages = case.get("messages", [])
        if message_id not in messages:
            messages.append(message_id)
        now = _now_iso()
        try:
            with get_db() as conn:
                conn.execute(
                    "UPDATE cases SET messages = ?, updated_at = ? WHERE case_id = ?",
                    (json.dumps(messages), now, case_id)
                )
        except Exception as e:
            logger.error(f"CaseManager.add_message error: {e}")
            return {"success": False, "message": "Failed to add message to case."}
        return {"success": True, "case_id": case_id, "message_count": len(messages)}

    def add_note(self, case_id: str, note: str, actor: str = "analyst") -> dict:
        """Add a note to a case."""
        now = _now_iso()
        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO case_notes (case_id, note, created_at) VALUES (?, ?, ?)",
                    (case_id, note, now)
                )
        except Exception as e:
            logger.error(f"CaseManager.add_note error: {e}")
            return {"success": False, "message": "Failed to add note."}

        AuditLog().log("case_note_added", {"case_id": case_id, "note_length": len(note)}, actor=actor)
        return {"success": True, "case_id": case_id, "created_at": now}
