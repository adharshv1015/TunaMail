"""
Stage 14 — JSON-safe serialization utilities.

Ensure all API payloads are safe to pass through json.dumps() regardless
of what Python types end up in the analysis result.

Handles: datetime, date, set, frozenset, bytes, bytearray, Path, Enum,
         and any object with a __dict__.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from enum import Enum
from typing import Any


def _default_handler(obj: Any) -> Any:  # noqa: ANN401
    """Fallback encoder for non-standard types."""
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, datetime.timedelta):
        return obj.total_seconds()
    if isinstance(obj, (set, frozenset)):
        return sorted(obj, key=str)
    if isinstance(obj, (bytes, bytearray)):
        try:
            return obj.decode("utf-8", errors="replace")
        except Exception:
            return "<bytes>"
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, Enum):
        return obj.value
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    return str(obj)


def json_safe(value: Any) -> Any:
    """
    Recursively sanitise a value so that json.dumps() will never raise.

    Works in-place on dicts/lists for efficiency; returns the sanitised value.
    """
    if isinstance(value, dict):
        return {k: json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_safe(v) for v in value]
    if isinstance(value, tuple):
        return [json_safe(v) for v in value]
    # Probe: try direct serialization; if it fails, apply handler
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return _default_handler(value)


def safe_json_dumps(value: Any, **kwargs) -> str:
    """Serialize *value* to JSON string, never raising due to type errors."""
    return json.dumps(json_safe(value), **kwargs)
