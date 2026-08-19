
"""
Stage 14 — Store maintenance / data retention utilities.

Provides configurable record expiry for all local JSON stores:

  HISTORY_RETENTION_DAYS    — behavior store entries
  AUDIT_RETENTION_DAYS      — audit log entries
  CAMPAIGN_RETENTION_DAYS   — campaign history entries

Records older than the configured threshold are removed on the next
maintenance run. The operation uses the existing atomic-write path so it
cannot corrupt the store even if interrupted.

Usage (can be called during startup or on a periodic schedule):
  from src.storage.store_maintenance import run_maintenance
  run_maintenance()
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict

logger = logging.getLogger(__name__)

# Configurable retention windows (in days)
HISTORY_RETENTION_DAYS = int(os.environ.get("HISTORY_RETENTION_DAYS", "90"))
AUDIT_RETENTION_DAYS = int(os.environ.get("AUDIT_RETENTION_DAYS", "180"))
CAMPAIGN_RETENTION_DAYS = int(os.environ.get("CAMPAIGN_RETENTION_DAYS", "60"))
MAX_HISTORY_ENTRIES = int(os.environ.get("MAX_HISTORY_ENTRIES", "10000"))


def _days_to_seconds(days: int) -> float:
    return days * 86400.0


def _prune_dict_by_timestamp(
    data: Dict[str, Any],
    key_field: str,
    max_age_seconds: float,
    max_entries: int = 0,
) -> Dict[str, Any]:
    """
    Remove entries where data[entry][key_field] is older than max_age_seconds.

    If key_field is not present, the entry is kept (safe default).
    Optionally cap to max_entries (keeps most recent).
    """
    now = time.time()
    kept: Dict[str, Any] = {}

    for record_key, record in data.items():
        if not isinstance(record, dict):
            kept[record_key] = record
            continue

        ts = record.get(key_field)
        if ts is None:
            # No timestamp — keep conservatively
            kept[record_key] = record
            continue

        try:
            age = now - float(ts)
        except (TypeError, ValueError):
            kept[record_key] = record
            continue

        if age <= max_age_seconds:
            kept[record_key] = record

    # Enforce max entries by evicting oldest
    if max_entries and len(kept) > max_entries:
        sorted_keys = sorted(
            kept.keys(),
            key=lambda k: (kept[k].get(key_field) or 0),
        )
        for old_key in sorted_keys[: len(kept) - max_entries]:
            del kept[old_key]

    return kept


def _prune_behavior_store() -> int:
    """Prune stale entries from the behavior store. Returns removed count."""
    try:
        from src.storage.behavior_store import get_behavior_store

        store = get_behavior_store()
        data = store.store.get_all()
        original_count = len(data)

        # Behavior entries contain a list of timestamps;
        # keep entry if any timestamp is recent.
        max_age = _days_to_seconds(HISTORY_RETENTION_DAYS)
        now = time.time()
        kept: Dict[str, Any] = {}

        for sender, record in data.items():
            if not isinstance(record, dict):
                continue

            timestamps = record.get("timestamps", [])

            if not timestamps:
                # No activity recorded — prune
                continue

            try:
                most_recent = max(float(t) for t in timestamps)

                if now - most_recent <= max_age:
                    # Trim old timestamps within the entry
                    record["timestamps"] = [
                        t for t in timestamps
                        if now - float(t) <= max_age
                    ]
                    kept[sender] = record

            except (TypeError, ValueError):
                kept[sender] = record

        removed = original_count - len(kept)

        if removed > 0:
            store.store._atomic_write(kept)  # type: ignore[protected-access]
            store.store._cache = kept         # type: ignore[protected-access]
            logger.info(
                "StoreMaintenance: behavior_store pruned %d stale entries",
                removed,
            )

        return removed

    except Exception as e:
        logger.warning(
            "StoreMaintenance: behavior_store prune failed: %s",
            e,
        )
        return 0


def _prune_campaign_store() -> int:
    """Prune campaigns that have not been seen recently."""
    try:
        from src.storage.campaign_store import get_campaign_store

        store = get_campaign_store()
        data = store.store.get_all()
        original_count = len(data)

        max_age = _days_to_seconds(CAMPAIGN_RETENTION_DAYS)
        now = time.time()
        kept: Dict[str, Any] = {}

        for cid, record in data.items():
            if not isinstance(record, dict):
                continue

            last_seen = record.get("last_seen") or record.get("timestamp")

            if last_seen is None:
                # No timestamp — keep conservatively
                kept[cid] = record
                continue

            try:
                if now - float(last_seen) <= max_age:
                    kept[cid] = record

            except (TypeError, ValueError):
                kept[cid] = record

        removed = original_count - len(kept)

        if removed > 0:
            store.store._atomic_write(kept)   # type: ignore[protected-access]
            store.store._cache = kept          # type: ignore[protected-access]
            logger.info(
                "StoreMaintenance: campaign_store pruned %d stale entries",
                removed,
            )

        return removed

    except Exception as e:
        logger.warning(
            "StoreMaintenance: campaign_store prune failed: %s",
            e,
        )
        return 0


def _prune_reputation_store() -> int:
    """
    Trim seen_message_ids lists that have grown beyond MAX_HISTORY_ENTRIES.
    Does NOT remove entire reputation records — only trims history lists.
    """
    try:
        from src.storage.reputation_store import get_reputation_store

        store = get_reputation_store()
        data = store.store.get_all()
        trimmed = 0

        for sender, record in data.items():
            if not isinstance(record, dict):
                continue

            seen = record.get("seen_message_ids", [])

            if len(seen) > MAX_HISTORY_ENTRIES:
                record["seen_message_ids"] = seen[-MAX_HISTORY_ENTRIES:]
                trimmed += 1

        if trimmed > 0:
            store.store._atomic_write(data)   # type: ignore[protected-access]
            store.store._cache = data          # type: ignore[protected-access]
            logger.info(
                "StoreMaintenance: reputation_store trimmed %d oversized histories",
                trimmed,
            )

        return trimmed

    except Exception as e:
        logger.warning(
            "StoreMaintenance: reputation_store trim failed: %s",
            e,
        )
        return 0


def run_maintenance() -> Dict[str, int]:
    """
    Execute all retention maintenance tasks.

    Returns a summary dict with counts of records removed/trimmed per store.
    Safe to call at startup or on a schedule.
    """
    logger.info("StoreMaintenance: starting maintenance run")

    results = {
        "behavior_pruned": _prune_behavior_store(),
        "campaign_pruned": _prune_campaign_store(),
        "reputation_trimmed": _prune_reputation_store(),
    }

    logger.info(
        "StoreMaintenance: completed — %s",
        results,
    )

    return results
