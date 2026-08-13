"""
Stage 14 — Per-message analysis result cache.

Prevents duplicate full-pipeline execution when the frontend requests
the same message_id repeatedly (page refresh, rapid selection, StrictMode).

Cache key = message_id + content fingerprint (SHA-256 of stable message fields).
If the message content hasn't changed, the cached result is returned immediately.
If it has changed (e.g., labels updated), the cache is invalidated.

Decision immutability: the cached result is never modified — it is returned as-is.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

ANALYSIS_CACHE_TTL_SECONDS = int(os.environ.get("ANALYSIS_CACHE_TTL_SECONDS", "3600"))
MAX_ANALYSIS_CACHE_ENTRIES = int(os.environ.get("MAX_ANALYSIS_CACHE_ENTRIES", "500"))

# Increment this whenever the intelligence pipeline changes significantly.
# Cache entries from a previous version will be automatically invalidated.
ANALYSIS_VERSION = "15.1"


def _content_fingerprint(parsed_email: dict) -> str:
    """
    Build a stable, safe fingerprint of the parsed email.

    Uses only stable structural fields — NOT raw body content so it's safe
    to store in memory without risk of retaining large email bodies.
    """
    msg_id = parsed_email.get("id", "")
    sender = parsed_email.get("from", "")
    subject = parsed_email.get("subject", "")
    body = parsed_email.get("body", "")
    attachments = [
        a.get("filename", "") + str(a.get("size", 0))
        for a in (parsed_email.get("attachments") or [])
        if isinstance(a, dict)
    ]

    body_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]

    key_data = {
        "id": msg_id,
        "from": sender,
        "subject": subject,
        "body_hash": body_hash,
        "attachments": sorted(attachments),
    }
    return hashlib.sha256(
        json.dumps(key_data, sort_keys=True).encode()
    ).hexdigest()


class AnalysisCache:
    """
    Thread-safe singleton cache for full email analysis results.

    Uses per-key locking (single-flight pattern) so that two concurrent
    requests for the same message only trigger one analysis run.
    """

    _instance: Optional["AnalysisCache"] = None
    _class_lock = threading.Lock()

    def __new__(cls) -> "AnalysisCache":
        with cls._class_lock:
            if cls._instance is None:
                inst = super().__new__(cls)
                inst._init()
                cls._instance = inst
        return cls._instance

    def _init(self) -> None:
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._locks: Dict[str, threading.Lock] = {}
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def get_lock(self, message_id: str) -> threading.Lock:
        """Return a per-message lock for single-flight protection."""
        with self._lock:
            if message_id not in self._locks:
                self._locks[message_id] = threading.Lock()
            return self._locks[message_id]

    def get(self, message_id: str, fingerprint: str) -> Optional[Any]:
        with self._lock:
            entry = self._cache.get(message_id)
            if entry is None:
                self._misses += 1
                return None

            # Check TTL
            if time.time() - entry["timestamp"] > ANALYSIS_CACHE_TTL_SECONDS:
                del self._cache[message_id]
                if message_id in self._locks:
                    del self._locks[message_id]
                self._misses += 1
                return None

            # Check fingerprint + analysis version — if either changed, invalidate
            if entry["fingerprint"] != fingerprint or entry.get("analysis_version") != ANALYSIS_VERSION:
                del self._cache[message_id]
                self._misses += 1
                logger.debug("AnalysisCache: fingerprint/version mismatch for %s — invalidated", message_id)
                return None

            entry["last_accessed"] = time.time()
            self._hits += 1
            logger.debug("AnalysisCache: HIT for message %s", message_id)
            return entry["data"]

    def set(self, message_id: str, fingerprint: str, data: Any) -> None:
        with self._lock:
            if len(self._cache) >= MAX_ANALYSIS_CACHE_ENTRIES:
                self._evict_lru()

            self._cache[message_id] = {
                "data": data,
                "fingerprint": fingerprint,
                "analysis_version": ANALYSIS_VERSION,
                "timestamp": time.time(),
                "last_accessed": time.time(),
            }
            logger.debug("AnalysisCache: stored result for message %s", message_id)

    def invalidate(self, message_id: str) -> None:
        with self._lock:
            if message_id in self._cache:
                del self._cache[message_id]
            if message_id in self._locks:
                del self._locks[message_id]

    def get_by_message_id(self, message_id: str) -> Optional[Any]:
        """Lightweight lookup for inbox listing — checks only TTL and analysis_version.
        Does not validate the fingerprint (since we don't have parsed content here).
        Returns the cached data if valid, or None if absent/stale/wrong version.
        """
        with self._lock:
            entry = self._cache.get(message_id)
            if entry is None:
                return None
            # Check TTL
            if time.time() - entry["timestamp"] > ANALYSIS_CACHE_TTL_SECONDS:
                del self._cache[message_id]
                if message_id in self._locks:
                    del self._locks[message_id]
                return None
            # Check analysis version
            if entry.get("analysis_version") != ANALYSIS_VERSION:
                del self._cache[message_id]
                return None
            return entry["data"]

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._locks.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0

    def statistics(self) -> Dict[str, Any]:
        with self._lock:
            total = self._hits + self._misses
            return {
                "entries": len(self._cache),
                "max_entries": MAX_ANALYSIS_CACHE_ENTRIES,
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "hit_ratio": round(self._hits / total, 4) if total > 0 else 0.0,
                "ttl_seconds": ANALYSIS_CACHE_TTL_SECONDS,
            }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _evict_lru(self) -> None:
        num_to_evict = max(1, int(MAX_ANALYSIS_CACHE_ENTRIES * 0.1))
        sorted_keys = sorted(
            self._cache.keys(),
            key=lambda k: self._cache[k]["last_accessed"],
        )
        for key in sorted_keys[:num_to_evict]:
            del self._cache[key]
            if key in self._locks:
                del self._locks[key]
            self._evictions += 1


# Module-level singleton
analysis_cache = AnalysisCache()


def get_analysis_fingerprint(parsed_email: dict) -> str:
    """Public helper for generating the content fingerprint."""
    return _content_fingerprint(parsed_email)
