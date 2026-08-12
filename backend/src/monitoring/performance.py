"""
Stage 14 — Enhanced PerformanceTracker.

Tracks per-stage timing with monotonic timers, records timeout events,
and provides a full summary including slowest stage and aggregate stats.

No email content, credentials, or cookies are logged.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Dict, List, Optional


class PerformanceTracker:
    """
    Lightweight per-request performance tracker.

    Usage:
        tracker = PerformanceTracker()
        with tracker.measure("URLAnalyzer"):
            ...do work...
        tracker.record_timeout("CampaignDetector", reason="budget exceeded")
        tracker.complete()
        summary = tracker.get_summary()
    """

    def __init__(self, budget_seconds: float = 0.0) -> None:
        self.stages: List[Dict[str, Any]] = []
        self.timeouts: List[Dict[str, str]] = []
        self.start_time = time.monotonic()
        self.total_duration_ms: float = 0.0
        self.status = "IN_PROGRESS"
        self._budget_seconds = budget_seconds

    # ------------------------------------------------------------------
    # Context manager — measures one named stage
    # ------------------------------------------------------------------

    @contextmanager
    def measure(self, stage_name: str):
        stage_start = time.monotonic()
        try:
            yield
        finally:
            duration_ms = (time.monotonic() - stage_start) * 1000
            self.stages.append(
                {
                    "stage": stage_name,
                    "duration_ms": round(duration_ms, 2),
                }
            )

    # ------------------------------------------------------------------
    # Timeout recording
    # ------------------------------------------------------------------

    def record_timeout(self, analyzer: str, reason: str = "Analysis budget exceeded") -> None:
        """Record that an analyzer was skipped due to time budget."""
        self.timeouts.append(
            {
                "status": "TIMEOUT",
                "analyzer": analyzer,
                "reason": reason,
            }
        )

    # ------------------------------------------------------------------
    # Budget helpers
    # ------------------------------------------------------------------

    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.start_time

    def budget_remaining_seconds(self) -> float:
        if self._budget_seconds <= 0:
            return float("inf")
        return max(0.0, self._budget_seconds - self.elapsed_seconds())

    def is_over_budget(self) -> bool:
        if self._budget_seconds <= 0:
            return False
        return self.elapsed_seconds() >= self._budget_seconds

    # ------------------------------------------------------------------
    # Completion + summary
    # ------------------------------------------------------------------

    def complete(self) -> None:
        self.total_duration_ms = round(
            (time.monotonic() - self.start_time) * 1000, 2
        )
        self.status = "COMPLETED"

    def _slowest_stage(self) -> Optional[Dict[str, Any]]:
        if not self.stages:
            return None
        return max(self.stages, key=lambda s: s["duration_ms"])

    def get_summary(self) -> Dict[str, Any]:
        if self.status != "COMPLETED":
            self.complete()

        slowest = self._slowest_stage()
        total_stage_ms = sum(s["duration_ms"] for s in self.stages)

        return {
            "status": self.status,
            "total_duration_ms": self.total_duration_ms,
            "stages": self.stages,
            "timeouts": self.timeouts,
            "slowest_stage": slowest,
            "stage_total_ms": round(total_stage_ms, 2),
            "overhead_ms": round(
                max(0.0, self.total_duration_ms - total_stage_ms), 2
            ),
            "timeout_count": len(self.timeouts),
        }
