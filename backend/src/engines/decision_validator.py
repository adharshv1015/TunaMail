# ============================================================
# backend/src/engines/decision_validator.py
# ============================================================

class DecisionValidator:

    VALID_VERDICTS = {
        "SAFE",
        "VERIFIED LEGITIMATE",
        "LIKELY LEGITIMATE",
        "LOW RISK",
        "SUSPICIOUS",
        "HIGH RISK",
        "PHISHING",
        "UNKNOWN",
    }

    VALID_DETAIL_VERDICTS = {
        "CLEAR_POSITIVE_EVIDENCE",
        "LIMITED_CONTEXT",
        "INSUFFICIENT_EVIDENCE",
        "CONFLICTING_EVIDENCE",
        "BRAND_IMPERSONATION",
        "TRUST_HISTORY_CONFLICT",
        "LINK_ONLY",
        "MALICIOUS_EVIDENCE",
        "NEW_SENDER",
        "SUSPICIOUS_HISTORY",
        "POSSIBLE_COMPROMISED_SENDER",
        "DOMAIN_DRIFT",
        "AUTHENTICATION_DRIFT"
    }

    def validate(self, decision):

        if not isinstance(decision, dict):
            return self._unknown()

        risk = self._number(
            decision.get("risk_score"),
            0,
        )

        confidence = self._number(
            decision.get("confidence"),
            0,
        )

        risk = max(0, min(100, risk))
        confidence = max(0, min(100, confidence))

        verdict = str(
            decision.get(
                "verdict",
                "UNKNOWN",
            )
        ).upper()

        if verdict not in self.VALID_VERDICTS:
            verdict = "UNKNOWN"

        detail = str(
            decision.get(
                "detail_verdict",
                "INSUFFICIENT_EVIDENCE",
            )
        ).upper()

        if detail not in self.VALID_DETAIL_VERDICTS:
            detail = "INSUFFICIENT_EVIDENCE"

        # No evidence + low risk must not automatically mean SAFE.
        if risk == 0 and confidence < 50:
            verdict = "UNKNOWN"

            if detail == "CLEAR_POSITIVE_EVIDENCE":
                detail = "INSUFFICIENT_EVIDENCE"

        decision["risk_score"] = risk
        decision["confidence"] = confidence
        decision["verdict"] = verdict
        decision["detail_verdict"] = detail

        return decision

    @staticmethod
    def _number(value, fallback):

        try:
            return float(value)
        except (ValueError, TypeError):
            return fallback

    @staticmethod
    def _unknown():

        return {
            "risk_score": 0,
            "confidence": 0,
            "verdict": "UNKNOWN",
            "detail_verdict": "INSUFFICIENT_EVIDENCE",
            "recommendation": (
                "Insufficient evidence to determine "
                "whether this email is legitimate."
            ),
        }
