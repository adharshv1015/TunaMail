"""
Temporal IOC tracker for TunaMail Stage 5.

Tracks first_seen, last_seen, and occurrence counts for each indicator.
FIRST_SEEN status = UNKNOWN / LOW HISTORICAL CONFIDENCE — NOT malicious by default.
"""

import json
import logging
from datetime import datetime, timezone

from src.intelligence.db import get_db, rows_to_list

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class TemporalTracker:
    """
    Records when indicators are first and last observed.
    Used to detect new vs. recurring vs. campaign indicators.
    """

    def record(self, indicator: str, indicator_type: str = None) -> dict:
        """
        Record an observation of an indicator. Returns the updated record.
        """
        now = _now_iso()
        try:
            with get_db() as conn:
                row = conn.execute(
                    "SELECT * FROM indicators WHERE indicator = ?", (indicator,)
                ).fetchone()
                if row is None:
                    conn.execute(
                        """INSERT INTO indicators (indicator, indicator_type, first_seen, last_seen, occurrences, tags)
                           VALUES (?, ?, ?, ?, 1, '[]')""",
                        (indicator, indicator_type, now, now)
                    )
                    return {
                        "indicator": indicator,
                        "indicator_type": indicator_type,
                        "first_seen": now,
                        "last_seen": now,
                        "occurrences": 1,
                        "status": "FIRST_SEEN"
                    }
                else:
                    new_count = row["occurrences"] + 1
                    conn.execute(
                        "UPDATE indicators SET last_seen = ?, occurrences = ? WHERE indicator = ?",
                        (now, new_count, indicator)
                    )
                    return {
                        "indicator": indicator,
                        "indicator_type": indicator_type or row["indicator_type"],
                        "first_seen": row["first_seen"],
                        "last_seen": now,
                        "occurrences": new_count,
                        "status": "RECURRING" if new_count >= 2 else "FIRST_SEEN"
                    }
        except Exception as e:
            logger.error(f"TemporalTracker.record error: {e}")
            return {"indicator": indicator, "status": "UNKNOWN", "occurrences": 0}

    def get(self, indicator: str) -> dict | None:
        """Look up temporal data for a single indicator."""
        try:
            with get_db() as conn:
                row = conn.execute(
                    "SELECT * FROM indicators WHERE indicator = ?", (indicator,)
                ).fetchone()
                if row:
                    d = dict(row)
                    d["status"] = "RECURRING" if d["occurrences"] >= 2 else "FIRST_SEEN"
                    return d
        except Exception as e:
            logger.error(f"TemporalTracker.get error: {e}")
        return None

    def batch_record(self, iocs: list) -> dict:
        """
        Record multiple IOCs at once. Returns a dict mapping normalized → temporal record.
        """
        results = {}
        for ioc in iocs:
            norm = ioc.get("normalized", ioc.get("value", ""))
            if norm:
                record = self.record(norm, ioc.get("type"))
                results[norm] = record
        return results

    def get_first_seen_flags(self, iocs: list) -> dict:
        """
        Returns a dict of normalized IOC values → first_seen flag.
        FIRST_SEEN means UNKNOWN / LOW HISTORICAL CONFIDENCE — not malicious.
        """
        flags = {}
        for ioc in iocs:
            norm = ioc.get("normalized", ioc.get("value", ""))
            record = self.get(norm)
            if record and record.get("status") == "FIRST_SEEN":
                flags[norm] = {
                    "type": ioc.get("type"),
                    "status": "FIRST_SEEN",
                    "note": "UNKNOWN / LOW HISTORICAL CONFIDENCE — not classified as malicious"
                }
        return flags
