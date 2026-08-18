"""
Analyst Feedback System for TunaMail Stage 5.

Allows analysts to submit verdicts on analyzed emails.
The automated verdict is NEVER overwritten — both are preserved separately.
Analyst feedback triggers lightweight knowledge base adjustments.

Analyst verdict options:
    TRUE_POSITIVE   - correctly flagged as malicious
    FALSE_POSITIVE  - incorrectly flagged as malicious (was actually safe)
    TRUE_NEGATIVE   - correctly identified as safe
    FALSE_NEGATIVE  - missed a malicious email
    UNKNOWN         - analyst cannot determine
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from src.intelligence.db import get_db, rows_to_list
from src.intelligence.audit_log import AuditLog
from src.intelligence.knowledge_base import get_knowledge_base

logger = logging.getLogger(__name__)

VALID_VERDICTS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "TRUE_NEGATIVE", "FALSE_NEGATIVE", "UNKNOWN"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class FeedbackSystem:
    """
    Handles analyst feedback storage and lightweight learning.
    """

    def submit(
        self,
        message_id: str,
        analyst_verdict: str,
        automated_verdict: str = None,
        comment: str = "",
        entities: dict = None,
        actor: str = "analyst"
    ) -> dict:
        """
        Submit analyst feedback for a message.

        Args:
            message_id: The Gmail message ID
            analyst_verdict: One of VALID_VERDICTS
            automated_verdict: The system's original verdict (preserved unchanged)
            comment: Optional analyst comment
            entities: Entity data for lightweight learning (not required)
            actor: Who submitted (default: 'analyst')

        Returns:
            {success: bool, feedback_id: int, message: str}
        """
        if analyst_verdict not in VALID_VERDICTS:
            return {
                "success": False,
                "message": f"Invalid verdict. Must be one of: {', '.join(VALID_VERDICTS)}"
            }

        now = _now_iso()
        feedback_id = None

        try:
            with get_db() as conn:
                cursor = conn.execute(
                    """INSERT INTO feedback
                       (message_id, automated_verdict, analyst_verdict, comment, submitted_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (message_id, automated_verdict, analyst_verdict, comment or "", now)
                )
                feedback_id = cursor.lastrowid
        except Exception as e:
            logger.error(f"FeedbackSystem.submit DB error: {e}")
            return {"success": False, "message": "Database error storing feedback."}

        # Log the analyst action (no credentials stored)
        audit = AuditLog()
        audit.log(
            action="feedback_submitted",
            details={
                "message_id": message_id,
                "analyst_verdict": analyst_verdict,
                "automated_verdict": automated_verdict,
                "has_comment": bool(comment)
            },
            actor=actor
        )

        # Lightweight learning based on verdict
        if entities:
            self._apply_learning(analyst_verdict, entities)

        return {
            "success": True,
            "feedback_id": feedback_id,
            "message": f"Feedback recorded. Automated verdict remains: {automated_verdict}"
        }

    def _apply_learning(self, analyst_verdict: str, entities: dict):
        """
        Apply lightweight trust adjustments to the knowledge base based on feedback.
        A single decision never permanently whitelists/blacklists anything.
        Delta is small to prevent single analyst errors from having large effects.
        """
        kb = get_knowledge_base()
        sender = entities.get("sender", "")
        sender_domain = entities.get("sender_domain", "")
        url_domains = entities.get("url_domains", [])

        delta = 0.0
        if analyst_verdict == "FALSE_POSITIVE":
            # System said malicious, analyst says safe → slight positive adjustment
            delta = +0.1
        elif analyst_verdict == "TRUE_POSITIVE":
            # System was right it's malicious → reinforce negative for domain
            delta = -0.1
        elif analyst_verdict == "FALSE_NEGATIVE":
            # Missed malicious email → negative adjustment
            delta = -0.15
        elif analyst_verdict == "TRUE_NEGATIVE":
            # Correctly safe → slight positive reinforcement
            delta = +0.05

        if delta != 0.0:
            if sender:
                kb.adjust_sender_trust(sender, delta)
            if sender_domain:
                kb.adjust_domain_trust(sender_domain, delta)

    def get_feedback_for_message(self, message_id: str) -> list:
        """Retrieve all feedback entries for a message."""
        try:
            with get_db() as conn:
                rows = conn.execute(
                    "SELECT * FROM feedback WHERE message_id = ? ORDER BY submitted_at DESC",
                    (message_id,)
                ).fetchall()
                return rows_to_list(rows)
        except Exception as e:
            logger.error(f"FeedbackSystem.get_feedback error: {e}")
            return []

    def get_all_feedback(self, limit: int = 100) -> list:
        """Retrieve recent feedback entries."""
        try:
            with get_db() as conn:
                rows = conn.execute(
                    "SELECT * FROM feedback ORDER BY submitted_at DESC LIMIT ?", (limit,)
                ).fetchall()
                return rows_to_list(rows)
        except Exception as e:
            logger.error(f"FeedbackSystem.get_all_feedback error: {e}")
            return []
