"""
Campaign Detector for TunaMail Stage 5.

Elevates correlated messages to a campaign when a meaningful threshold is reached.

Rules:
  - Minimum 2 related messages sharing at least 1 meaningful IOC (domain, URL, hash, or IP)
  - Generic keyword sharing alone NEVER creates a campaign
  - Infrastructure evolution (sender changes but same URL/domain) = EVOLVING_INFRASTRUCTURE
  - All campaigns persisted to SQLite
"""

import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any

from src.intelligence.db import get_db, rows_to_list

logger = logging.getLogger(__name__)

# Minimum number of related messages to declare a campaign
_CAMPAIGN_MIN_RELATED = 2
# Minimum confidence threshold for campaign declaration
_CAMPAIGN_MIN_CONFIDENCE = 60


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CampaignDetector:
    """
    Detects phishing campaigns from correlation results.
    """

    def detect(
        self,
        message_id: str,
        correlation_result: dict,
        entities: dict,
        existing_analysis: dict = None
    ) -> dict:
        """
        Evaluate whether the correlated messages constitute a campaign.

        Returns:
            {
                campaign_detected: bool,
                campaign_id: str | None,
                confidence: int,
                shared_indicators: [...],
                related_messages: int,
                attack_pattern: str | None,
                campaign_type: str,
                infrastructure_evolution: bool
            }
        """
        if existing_analysis is None:
            existing_analysis = {}

        related = correlation_result.get("related_messages", [])
        shared = correlation_result.get("shared_indicators", [])
        infra_overlap = correlation_result.get("infrastructure_overlap", False)

        if len(related) < _CAMPAIGN_MIN_RELATED:
            return self._no_campaign()

        # Only meaningful IOC types drive campaigns
        meaningful_shared = [s for s in shared if s.get("type") in (
            "DOMAIN", "URL", "IP_ADDRESS", "HASH_MD5", "HASH_SHA1", "HASH_SHA256"
        )]

        if not meaningful_shared:
            return self._no_campaign()

        # Compute confidence based on how many messages share IOCs and how many IOCs are shared
        confidence = self._compute_confidence(related, meaningful_shared, infra_overlap)

        if confidence < _CAMPAIGN_MIN_CONFIDENCE:
            return self._no_campaign()

        # Detect infrastructure evolution
        infra_evolution = self._detect_evolution(message_id, entities, related)

        # Try to find or create campaign record
        campaign_id = self._get_or_create_campaign(
            message_id=message_id,
            related=related,
            shared=meaningful_shared,
            confidence=confidence
        )

        return {
            "campaign_detected": True,
            "campaign_id": campaign_id,
            "confidence": confidence,
            "shared_indicators": [s["value"] for s in meaningful_shared],
            "related_messages": len(related),
            "campaign_type": "EVOLVING_INFRASTRUCTURE" if infra_evolution else "STATIC_CAMPAIGN",
            "infrastructure_evolution": infra_evolution
        }

    def _compute_confidence(self, related: list, shared: list, infra_overlap: bool) -> int:
        """
        Compute campaign confidence (0–100).
        - More related messages = higher confidence
        - More shared indicators = higher confidence
        - Shared URL or hash = highest signal
        - Infrastructure overlap = bonus
        """
        base = 0
        n_related = len(related)
        n_shared = len(shared)

        # Related message count factor
        if n_related >= 5:
            base += 40
        elif n_related >= 3:
            base += 30
        else:
            base += 20

        # Shared indicator quality factor
        for s in shared:
            if s.get("type") == "URL":
                base += 20
            elif s.get("type") in ("HASH_SHA256", "HASH_SHA1", "HASH_MD5"):
                base += 25
            elif s.get("type") == "IP_ADDRESS":
                base += 15
            elif s.get("type") == "DOMAIN":
                base += 10

        if infra_overlap:
            base += 10

        return min(base, 100)

    def _detect_evolution(self, current_msg_id: str, entities: dict, related: list) -> bool:
        """
        Detect if the sender is changing but the infrastructure (domain/URL) stays the same.
        This indicates an evolving campaign.
        """
        current_sender = entities.get("sender_domain", "")
        if not current_sender or not related:
            return False

        try:
            with get_db() as conn:
                # Get sender domains of related messages
                related_ids = [r["message_id"] for r in related]
                if not related_ids:
                    return False
                placeholders = ",".join("?" * len(related_ids))
                rows = conn.execute(
                    f"""SELECT DISTINCT value FROM ioc_records
                        WHERE message_id IN ({placeholders}) AND type = 'DOMAIN'""",
                    related_ids
                ).fetchall()

                # If there are shared domains but the current sender differs from related senders
                # (checked by looking at different EMAIL_ADDRESS senders)
                sender_rows = conn.execute(
                    f"""SELECT DISTINCT value FROM ioc_records
                        WHERE message_id IN ({placeholders}) AND type = 'EMAIL_ADDRESS'
                        AND source LIKE 'header%'""",
                    related_ids
                ).fetchall()

                related_senders = {r["value"] for r in sender_rows}
                if related_senders and entities.get("sender") not in related_senders:
                    # Different sender but shared domain = infrastructure evolution
                    if rows:
                        return True
        except Exception as e:
            logger.error(f"CampaignDetector._detect_evolution error: {e}")
        return False

    def _get_or_create_campaign(
        self,
        message_id: str,
        related: list,
        shared: list,
        confidence: int
    ) -> str:
        """Find an existing campaign for these related messages or create a new one."""
        now = _now_iso()
        related_ids = [r["message_id"] for r in related] + [message_id]
        shared_values = [s["value"] for s in shared]

        try:
            with get_db() as conn:
                # Check if any of the related messages are already in a campaign
                for rid in related_ids:
                    rows = conn.execute(
                        """SELECT campaign_id, related_messages FROM campaigns
                           WHERE related_messages LIKE ?""",
                        (f'%"{rid}"%',)
                    ).fetchall()
                    for row in rows:
                        # Update existing campaign
                        existing_msgs = json.loads(row["related_messages"] or "[]")
                        for rid2 in related_ids:
                            if rid2 not in existing_msgs:
                                existing_msgs.append(rid2)
                        conn.execute(
                            """UPDATE campaigns
                               SET related_messages = ?, shared_indicators = ?, confidence = ?, updated_at = ?
                               WHERE campaign_id = ?""",
                            (
                                json.dumps(existing_msgs),
                                json.dumps(shared_values),
                                confidence,
                                now,
                                row["campaign_id"]
                            )
                        )
                        return row["campaign_id"]

                # Create new campaign
                campaign_id = f"campaign-{str(uuid.uuid4())[:8]}"
                conn.execute(
                    """INSERT INTO campaigns
                       (campaign_id, confidence, shared_indicators, related_messages, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        campaign_id,
                        confidence,
                        json.dumps(shared_values),
                        json.dumps(related_ids),
                        now,
                        now
                    )
                )
                return campaign_id
        except Exception as e:
            logger.error(f"CampaignDetector._get_or_create_campaign error: {e}")
            return f"campaign-{str(uuid.uuid4())[:8]}"

    def _no_campaign(self) -> dict:
        return {
            "campaign_detected": False,
            "campaign_id": None,
            "confidence": 0,
            "shared_indicators": [],
            "related_messages": 0,
            "campaign_type": "NONE",
            "infrastructure_evolution": False
        }
