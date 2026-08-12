# ============================================================
# backend/src/ai/evidence_integrity.py
# ============================================================

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List


class EvidenceIntegrityValidator:

    REQUIRED_FIELDS = {
        "type",
        "severity",
        "confidence",
        "source",
        "explanation",
    }

    VALID_SEVERITIES = {
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    def validate(self, evidence: Dict[str, Any]) -> Dict[str, Any]:

        if not isinstance(evidence, dict):
            return {
                "valid": False,
                "reason": "Malformed evidence",
            }

        confidence = evidence.get("confidence", 0)

        try:
            confidence = float(confidence)
        except (ValueError, TypeError):
            confidence = 0

        confidence = max(0.0, min(1.0, confidence))

        severity = str(
            evidence.get("severity", "INFO")
        ).upper()

        if severity not in self.VALID_SEVERITIES:
            severity = "INFO"

        normalized = {
            "type": str(evidence.get("type", "UNKNOWN")),
            "severity": severity,
            "confidence": confidence,
            "source": str(evidence.get("source", "UNKNOWN")),
            "explanation": str(
                evidence.get(
                    "explanation",
                    "",
                )
            ),
        }

        if "entity" in evidence:
            normalized["entity"] = evidence["entity"]

        normalized["fingerprint"] = self.fingerprint(
            normalized
        )

        return {
            "valid": True,
            "evidence": normalized,
        }

    def validate_many(
        self,
        evidence: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        output = []

        for item in evidence or []:

            result = self.validate(item)

            if result["valid"]:
                output.append(result["evidence"])

        return output

    @staticmethod
    def fingerprint(evidence: Dict[str, Any]) -> str:

        payload = {
            "type": evidence.get("type"),
            "source": evidence.get("source"),
            "explanation": str(
                evidence.get(
                    "explanation",
                    "",
                )
            ).strip().lower(),
            "entity": evidence.get("entity"),
        }

        raw = json.dumps(
            payload,
            sort_keys=True,
            default=str,
        )

        return hashlib.sha256(
            raw.encode("utf-8")
        ).hexdigest()
