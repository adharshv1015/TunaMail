"""
IOC Correlation Engine for TunaMail Stage 5.

Compares current email IOCs against stored historical records to find
related emails and shared infrastructure.

Rules:
  - Requires MEANINGFUL IOC matches (domain, URL, IP, hash) — not generic words
  - Generic text matches alone do NOT constitute correlation
  - Returns related messages with shared indicators labeled
"""

import json
import logging
from typing import List, Dict, Any

from src.intelligence.db import get_db, rows_to_list

logger = logging.getLogger(__name__)

# Only these IOC types can drive correlation — not generic text or phone numbers
_CORRELATION_TYPES = {"DOMAIN", "URL", "IP_ADDRESS", "HASH_MD5", "HASH_SHA1", "HASH_SHA256", "EMAIL_ADDRESS"}


def _normalize_list(iocs: list, ioc_type: str) -> set:
    return {
        ioc["normalized"]
        for ioc in iocs
        if ioc.get("type") == ioc_type and ioc.get("normalized")
    }


class CorrelationEngine:
    """
    Compares the current email's meaningful IOCs against stored historical IOC records.
    """

    def correlate(
        self,
        message_id: str,
        iocs: List[Dict],
        entities: Dict,
        existing_analysis: Dict = None
    ) -> Dict[str, Any]:
        """
        Find related messages and shared indicators.

        Returns:
            {
                related_messages: [{message_id, shared_indicators, relationship_type}],
                shared_indicators: [{type, value, shared_count}],
                infrastructure_overlap: bool,
                relationship_summary: str
            }
        """
        if existing_analysis is None:
            existing_analysis = {}

        # First, store all current IOCs
        self._store_iocs(message_id, iocs)

        # Extract meaningful IOC values for correlation
        current_meaningful = {
            ioc["normalized"]
            for ioc in iocs
            if ioc.get("type") in _CORRELATION_TYPES and ioc.get("normalized")
        }

        if not current_meaningful:
            return self._empty_result()

        # Find related messages from stored IOC records
        related: Dict[str, Dict] = {}  # message_id -> match info

        try:
            with get_db() as conn:
                for norm_val in current_meaningful:
                    rows = conn.execute(
                        """SELECT message_id, type, value, normalized, confidence
                           FROM ioc_records
                           WHERE normalized = ? AND message_id != ?
                           LIMIT 50""",
                        (norm_val, message_id)
                    ).fetchall()
                    for row in rows:
                        mid = row["message_id"]
                        if mid and mid != message_id:
                            if mid not in related:
                                related[mid] = {"message_id": mid, "shared_indicators": [], "relationship_type": "SAME_IOC"}
                            indicator_entry = {
                                "type": row["type"],
                                "value": row["normalized"],
                                "confidence": row["confidence"]
                            }
                            if indicator_entry not in related[mid]["shared_indicators"]:
                                related[mid]["shared_indicators"].append(indicator_entry)
        except Exception as e:
            logger.error(f"CorrelationEngine.correlate DB error: {e}")
            return self._empty_result()

        # Determine relationship types
        for mid, info in related.items():
            types = {s["type"] for s in info["shared_indicators"]}
            if "HASH_SHA256" in types or "HASH_SHA1" in types or "HASH_MD5" in types:
                info["relationship_type"] = "SAME_ATTACHMENT_HASH"
            elif "URL" in types:
                info["relationship_type"] = "SAME_URL"
            elif "DOMAIN" in types or "IP_ADDRESS" in types:
                info["relationship_type"] = "SAME_INFRASTRUCTURE"
            else:
                info["relationship_type"] = "SAME_SENDER"

        # Build shared_indicators summary
        shared_summary: Dict[str, Dict] = {}
        for mid, info in related.items():
            for ind in info["shared_indicators"]:
                key = f"{ind['type']}:{ind['value']}"
                if key not in shared_summary:
                    shared_summary[key] = {
                        "type": ind["type"],
                        "value": ind["value"],
                        "shared_count": 0
                    }
                shared_summary[key]["shared_count"] += 1

        related_list = list(related.values())
        shared_list = list(shared_summary.values())

        # Infrastructure overlap = same domain or IP across different senders
        sender_domains = {
            ioc["normalized"]
            for ioc in iocs
            if ioc.get("type") == "DOMAIN"
        }
        infra_overlap = any(
            any(s["type"] in ("DOMAIN", "IP_ADDRESS") for s in info["shared_indicators"])
            for info in related.values()
        )

        summary = self._build_summary(related_list, shared_list)

        return {
            "related_messages": related_list,
            "shared_indicators": shared_list,
            "infrastructure_overlap": infra_overlap,
            "relationship_summary": summary
        }

    def _store_iocs(self, message_id: str, iocs: List[Dict]):
        """Persist current email's IOCs to the database."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        try:
            with get_db() as conn:
                for ioc in iocs:
                    if ioc.get("type") not in _CORRELATION_TYPES:
                        continue
                    norm = ioc.get("normalized", "")
                    if not norm:
                        continue
                    existing = conn.execute(
                        "SELECT id, occurrences FROM ioc_records WHERE normalized = ? AND message_id = ?",
                        (norm, message_id)
                    ).fetchone()
                    if not existing:
                        conn.execute(
                            """INSERT INTO ioc_records
                               (type, value, normalized, source, message_id, confidence, first_seen, last_seen, occurrences)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                            (
                                ioc.get("type", "UNKNOWN"),
                                ioc.get("value", norm),
                                norm,
                                ioc.get("source", ""),
                                message_id,
                                ioc.get("confidence", 0.5),
                                now,
                                now
                            )
                        )
        except Exception as e:
            logger.error(f"CorrelationEngine._store_iocs error: {e}")

    def _empty_result(self) -> Dict:
        return {
            "related_messages": [],
            "shared_indicators": [],
            "infrastructure_overlap": False,
            "relationship_summary": "No correlations found."
        }

    def _build_summary(self, related: list, shared: list) -> str:
        if not related:
            return "No related messages found."
        n = len(related)
        top = shared[:3]
        indicators_str = ", ".join(s["value"] for s in top) if top else ""
        if indicators_str:
            return f"{n} related message(s) share indicators: {indicators_str}"
        return f"{n} related message(s) detected with shared infrastructure."
