# ============================================================
# backend/src/engines/decision_validator.py
# ============================================================

from __future__ import annotations

from typing import Any, Dict


class DecisionValidator:
    """
    Final schema and consistency validator.

    Responsibilities:
    - Normalize risk_score and confidence to 0..100.
    - Validate verdict/detail_verdict values.
    - Prevent impossible/unsafe combinations such as:
        * low-confidence zero-evidence SAFE
        * legitimate verdict with critical malicious evidence
        * PHISHING without supporting malicious evidence
        * VERIFIED LEGITIMATE with unresolved contradictions
        * stale/limited context being presented as verified safe
    - Preserve the evidence already produced by ARE,
      DecisionFusionEngine, and the consistency guard.

    This class does NOT invent evidence and does NOT perform
    a new independent risk-scoring algorithm.
    """

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
        "AUTHENTICATION_DRIFT",
        "URL_BEHAVIOR_DRIFT",
        "POSSIBLE_COMPROMISED_ACCOUNT",
        "STRONG_SECURITY_EVIDENCE",
        "SUSPICIOUS_EVIDENCE",
        "STALE_HISTORICAL_EVIDENCE",
        "AI_LEGITIMACY_CONFLICT",
        "AI_IGNORED_DUE_TO_MALICE",
        "UNAVAILABLE",
        "UNKNOWN",
    }

    CRITICAL_NEGATIVE_TYPES = {
        "CREDENTIAL_HARVESTING",
        "MALICIOUS_URL",
        "KNOWN_MALICIOUS_URL",
        "MALICIOUS_REDIRECT",
        "BRAND_IMPERSONATION",
        "EXECUTABLE_ATTACHMENT",
        "SCRIPT_ATTACHMENT",
        "MALICIOUS_ATTACHMENT",
        "PRIVATE_IP_DESTINATION",
    }

    STRONG_NEGATIVE_TYPES = {
        "DOMAIN_MISMATCH",
        "URL_DOMAIN_MISMATCH",
        "SUSPICIOUS_URL",
        "SUSPICIOUS_REDIRECT",
        "HOMOGRAPH_DOMAIN",
        "PUNYCODE_DOMAIN",
        "HOSTNAME_MISMATCH",
        "TLS_POLICY_VIOLATION",
        "CREDENTIAL_REQUEST",
        "FINANCIAL_REQUEST",
        "AUTHENTICATION_FAILURE",
        "AUTHENTICATION_DRIFT",
        "DOMAIN_DRIFT",
        "URL_BEHAVIOR_DRIFT",
        "CAMPAIGN_ANOMALY",
        "TRUST_HISTORY_CONFLICT",
        "ADVERSARIAL_INDICATOR",
        "NEW_DOMAIN",
    }

    CONTRADICTION_TYPES = {
        "CONFLICTING_EVIDENCE",
        "HISTORICAL_CURRENT_CONFLICT",
        "TRUST_HISTORY_CONFLICT",
        "AI_IGNORED_DUE_TO_MALICE",
        "AI_LEGITIMACY_CONFLICT",
    }

    LEGITIMATE_VERDICTS = {
        "SAFE",
        "VERIFIED LEGITIMATE",
        "LIKELY LEGITIMATE",
    }

    RISK_VERDICTS = {
        "SUSPICIOUS",
        "HIGH RISK",
        "PHISHING",
    }

    def validate(
        self,
        decision: Dict[str, Any] | None,
    ) -> Dict[str, Any]:
        """
        Normalize and validate a final decision.

        The method is intentionally conservative:
        current malicious evidence is never silently converted
        into a legitimate verdict.
        """

        if not isinstance(decision, dict):
            return self._unknown()

        # Work on the same dictionary so callers retain any
        # additional API fields they already have.
        decision = dict(decision)

        # ----------------------------------------------------
        # Normalize numeric values
        # ----------------------------------------------------

        risk = self._number(
            decision.get("risk_score"),
            0,
        )

        confidence = self._number(
            decision.get("confidence"),
            0,
        )

        risk = self._clamp(risk)
        confidence = self._clamp(confidence)

        # ----------------------------------------------------
        # Normalize verdict
        # ----------------------------------------------------

        verdict = str(
            decision.get(
                "verdict",
                "UNKNOWN",
            )
        ).strip().upper()

        if verdict not in self.VALID_VERDICTS:
            verdict = "UNKNOWN"

        # ----------------------------------------------------
        # Normalize detail verdict
        # ----------------------------------------------------

        detail = str(
            decision.get(
                "detail_verdict",
                "INSUFFICIENT_EVIDENCE",
            )
        ).strip().upper()

        if detail not in self.VALID_DETAIL_VERDICTS:
            detail = "INSUFFICIENT_EVIDENCE"

        critical = self._critical_evidence(
            decision
        )

        if critical:
            verdict = "PHISHING"
            risk = max(
                risk,
                80,
            )
            confidence = max(
                confidence,
                70,
            )
            detail = "MALICIOUS_EVIDENCE"

        # ----------------------------------------------------
        # Extract structured evidence
        # ----------------------------------------------------

        structured_evidence = self._extract_structured_evidence(
            decision
        )



        strong = self._strong_evidence(
            structured_evidence
        )

        negative = self._negative_evidence(
            structured_evidence
        )

        contradictions = self._contradictions(
            structured_evidence
        )

        positive = self._positive_evidence(
            structured_evidence
        )

        has_critical = bool(critical)
        has_strong = bool(strong)
        has_negative = bool(negative)
        has_contradiction = bool(contradictions)

        # ----------------------------------------------------
        # Preserve explicit limited-context states
        # ----------------------------------------------------

        if detail in {
            "LIMITED_CONTEXT",
            "LINK_ONLY",
            "INSUFFICIENT_EVIDENCE",
            "UNAVAILABLE",
        }:
            if not has_critical and not has_strong:
                verdict = "UNKNOWN"

                confidence = min(
                    confidence,
                    45,
                )

        # ----------------------------------------------------
        # Current critical malicious evidence always wins.
        # ----------------------------------------------------

        if has_critical:

            verdict = "PHISHING"

            risk = max(
                risk,
                80,
            )

            # Never invent a huge confidence value. Preserve
            # existing calibration while preventing a critical
            # result from being presented as almost uncertain.
            confidence = max(
                confidence,
                70,
            )

            detail = "MALICIOUS_EVIDENCE"

        # ----------------------------------------------------
        # Strong evidence cannot coexist with a legitimate
        # verdict when the evidence is materially negative.
        # ----------------------------------------------------

        elif has_strong:

            if verdict in self.LEGITIMATE_VERDICTS:

                if risk >= 80:
                    verdict = "PHISHING"
                elif risk >= 60:
                    verdict = "HIGH RISK"
                elif risk < 40:
                    verdict = "SAFE"
                else:
                    verdict = "SUSPICIOUS"

                confidence = min(
                    confidence,
                    70,
                )

                if detail in {
                    "CLEAR_POSITIVE_EVIDENCE",
                    "UNKNOWN",
                    "INSUFFICIENT_EVIDENCE",
                }:
                    detail = "STRONG_SECURITY_EVIDENCE"

            elif verdict == "UNKNOWN":

                if risk >= 80:
                    verdict = "PHISHING"
                elif risk >= 60:
                    verdict = "HIGH RISK"
                elif risk < 40:
                    verdict = "SAFE"
                else:
                    verdict = "SUSPICIOUS"

                detail = "STRONG_SECURITY_EVIDENCE"

        # ----------------------------------------------------
        # Contradictory evidence
        # ----------------------------------------------------

        if has_contradiction:

            if verdict in {
                "VERIFIED LEGITIMATE",
                "LIKELY LEGITIMATE",
            }:

                # Do not claim verified legitimacy while
                # unresolved high contradictions remain.
                verdict = "UNKNOWN"

            confidence = min(
                confidence,
                50,
            )

            if detail not in {
                "POSSIBLE_COMPROMISED_SENDER",
                "TRUST_HISTORY_CONFLICT",
            }:
                detail = "CONFLICTING_EVIDENCE"

        # ----------------------------------------------------
        # PHISHING requires supporting current evidence.
        # ----------------------------------------------------

        if (
            verdict == "PHISHING"
            and not has_critical
        ):

            verdict = "SUSPICIOUS"

            risk = min(
                max(
                    risk,
                    40,
                ),
                59,
            )

            confidence = min(
                confidence,
                50,
            )

            detail = "INSUFFICIENT_EVIDENCE"

        # ----------------------------------------------------
        # ZERO EVIDENCE + ZERO RISK + LOW CONFIDENCE
        # must never become SAFE.
        # ----------------------------------------------------

        meaningful_positive = [p for p in positive if str(p.get("severity", "")).upper() != "INFO"]

        if (
            risk == 0
            and confidence < 50
            and not meaningful_positive
        ):

            verdict = "UNKNOWN"

            if detail == "CLEAR_POSITIVE_EVIDENCE":
                detail = "INSUFFICIENT_EVIDENCE"

        # ----------------------------------------------------
        # UNKNOWN with strong current evidence
        # ----------------------------------------------------

        if (
            verdict == "UNKNOWN"
            and has_strong
        ):

            if risk >= 80:
                verdict = "PHISHING"
                risk = max(
                    risk,
                    80,
                )
                detail = "MALICIOUS_EVIDENCE"

            elif risk >= 60:
                verdict = "HIGH RISK"
                detail = "STRONG_SECURITY_EVIDENCE"

            elif risk < 40:
                verdict = "SAFE"
                detail = "SAFE_EVIDENCE"

            else:
                verdict = "SUSPICIOUS"
                detail = "SUSPICIOUS_EVIDENCE"

        # ----------------------------------------------------
        # Historical evidence handling
        #
        # A historical positive record never overrides current
        # critical/strong negative evidence.
        # ----------------------------------------------------

        historical_status = str(
            decision.get(
                "historical_status",
                "",
            )
        ).upper()

        if historical_status == "STALE_HISTORICAL_EVIDENCE":

            if verdict in self.LEGITIMATE_VERDICTS and has_negative:
                verdict = "UNKNOWN"

            if detail not in {
                "MALICIOUS_EVIDENCE",
                "CONFLICTING_EVIDENCE",
            }:
                detail = (
                    "STALE_HISTORICAL_EVIDENCE"
                )

            confidence = min(
                confidence,
                50,
            )

        # ----------------------------------------------------
        # Avoid claiming SAFE/verified legitimate without
        # meaningful positive evidence.
        # ----------------------------------------------------

        if verdict in {
            "SAFE",
            "VERIFIED LEGITIMATE",
            "LIKELY LEGITIMATE",
        }:

            if (
                not positive
                and not has_negative
            ):

                if confidence < 70:
                    verdict = "UNKNOWN"
                    detail = (
                        "INSUFFICIENT_EVIDENCE"
                    )

        # ----------------------------------------------------
        # A VERIFIED LEGITIMATE result should have stronger
        # support than a generic SAFE result.
        # ----------------------------------------------------

        if verdict == "VERIFIED LEGITIMATE":

            independent_sources = {
                str(
                    item.get(
                        "source",
                        "",
                    )
                )
                for item in positive
                if item.get(
                    "source"
                )
            }

            if len(independent_sources) < 2:
                verdict = (
                    "LIKELY LEGITIMATE"
                )

                confidence = min(
                    confidence,
                    85,
                )

        # ----------------------------------------------------
        # Final clamping
        # ----------------------------------------------------

        risk = self._clamp(risk)
        confidence = self._clamp(confidence)

        # ----------------------------------------------------
        # Write normalized values back
        # ----------------------------------------------------

        decision["risk_score"] = risk
        decision["confidence"] = confidence
        decision["verdict"] = verdict
        decision["detail_verdict"] = detail

        # Keep structured evidence if present.
        if structured_evidence:
            decision[
                "structured_evidence"
            ] = structured_evidence

        # ----------------------------------------------------
        # Ensure recommendation exists and matches verdict
        # ----------------------------------------------------

        if not decision.get(
            "recommendation"
        ):

            decision[
                "recommendation"
            ] = self._recommendation(
                verdict
            )

        return decision

    # ========================================================
    # Evidence extraction
    # ========================================================

    def _extract_structured_evidence(
        self,
        decision: Dict[str, Any],
    ) -> list[Dict[str, Any]]:

        raw = (
            decision.get(
                "structured_evidence",
                [],
            )
            or []
        )

        if not isinstance(
            raw,
            list,
        ):
            return []

        normalized = []
        seen = set()

        for item in raw:

            if not isinstance(
                item,
                dict,
            ):
                continue

            item_type = self._normalize_type(
                item.get("type")
            )

            severity = self._normalize_severity(
                item.get("severity")
            )

            direction = self._normalize_direction(
                item.get(
                    "direction",
                    item.get(
                        "supports"
                    ),
                )
            )

            source = str(
                item.get(
                    "source",
                    "UNKNOWN",
                )
            )

            explanation = str(
                item.get(
                    "explanation",
                    "",
                )
            )

            key = (
                item_type,
                severity,
                direction,
                source,
                explanation,
            )

            if key in seen:
                continue

            seen.add(key)

            normalized.append(
                {
                    **item,
                    "type": item_type,
                    "severity": severity,
                    "direction": direction,
                    "source": source,
                    "explanation": explanation,
                }
            )

        return normalized

    # ========================================================
    # Evidence categories
    # ========================================================

    def _critical_evidence(self, decision):
        evidence = (
            decision.get(
                "structured_evidence",
                [],
            )
            or []
        )

        return [
            item
            for item in evidence
            if isinstance(item, dict)
            and item.get("direction") == "NEGATIVE"
            and (
                str(
                    item.get(
                        "severity",
                        "",
                    )
                ).upper() == "CRITICAL"
                or str(
                    item.get(
                        "type",
                        "",
                    )
                ).upper()
                in self.CRITICAL_NEGATIVE_TYPES
            )
        ]

    @staticmethod
    def _strong_evidence(
        evidence,
    ):
        return [
            item
            for item in evidence
            if item.get(
                "direction"
            ) == "NEGATIVE"
            and (
                item.get(
                    "severity"
                )
                in {
                    "HIGH",
                    "CRITICAL",
                }
                or item.get(
                    "type"
                )
                in DecisionValidator.STRONG_NEGATIVE_TYPES
            )
        ]

    @staticmethod
    def _negative_evidence(
        evidence,
    ):
        return [
            item
            for item in evidence
            if item.get(
                "direction"
            ) == "NEGATIVE"
        ]

    @staticmethod
    def _positive_evidence(
        evidence,
    ):
        return [
            item
            for item in evidence
            if item.get(
                "direction"
            ) == "POSITIVE"
        ]

    @staticmethod
    def _contradictions(
        evidence,
    ):
        return [
            item
            for item in evidence
            if (
                item.get(
                    "type"
                )
                in DecisionValidator.CONTRADICTION_TYPES
            )
            or str(
                item.get(
                    "reasoning_state",
                    "",
                )
            ).upper()
            == "CONFLICTING_EVIDENCE"
        ]

    # ========================================================
    # Normalization helpers
    # ========================================================

    @staticmethod
    def _normalize_type(
        value: Any,
    ) -> str:
        return (
            str(value or "UNKNOWN")
            .strip()
            .upper()
            .replace(
                "-",
                "_",
            )
            .replace(
                " ",
                "_",
            )
        )

    @staticmethod
    def _normalize_direction(
        value: Any,
    ) -> str:

        value = str(
            value or "NEUTRAL"
        ).strip().upper()

        if value in {
            "BENIGN",
            "POSITIVE",
        }:
            return "POSITIVE"

        if value in {
            "MALICIOUS",
            "NEGATIVE",
        }:
            return "NEGATIVE"

        return "NEUTRAL"

    @staticmethod
    def _normalize_severity(
        value: Any,
    ) -> str:

        value = str(
            value or "INFO"
        ).strip().upper()

        if value not in {
            "INFO",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }:
            return "INFO"

        return value

    @staticmethod
    def _number(
        value: Any,
        fallback: float,
    ) -> float:

        try:
            return float(value)
        except (
            ValueError,
            TypeError,
        ):
            return fallback

    @staticmethod
    def _clamp(
        value: float,
    ) -> int:

        return int(
            max(
                0,
                min(
                    100,
                    round(value),
                ),
            )
        )

    # ========================================================
    # Recommendations
    # ========================================================

    @staticmethod
    def _recommendation(
        verdict: str,
    ) -> str:

        recommendations = {
            "VERIFIED LEGITIMATE": (
                "Strong evidence indicates this email "
                "is legitimate."
            ),
            "LIKELY LEGITIMATE": (
                "Appears likely legitimate, but verify "
                "unexpected requests."
            ),
            "LOW RISK": (
                "No significant threats detected, "
                "but sender is not fully verified."
            ),
            "SAFE": (
                "No immediate threats were detected "
                "and sufficient positive evidence exists."
            ),
            "UNKNOWN": (
                "Insufficient evidence to verify this sender. "
                "Exercise caution."
            ),
            "SUSPICIOUS": (
                "Exercise caution before clicking links "
                "or downloading files."
            ),
            "HIGH RISK": (
                "Multiple risk factors detected. "
                "Do not click links unless verified."
            ),
            "PHISHING": (
                "Do not interact with this email. "
                "Report or delete it immediately."
            ),
        }

        return recommendations.get(
            verdict,
            "Exercise caution.",
        )

    # ========================================================
    # Unknown result
    # ========================================================

    @classmethod
    def _unknown(
        cls,
    ) -> Dict[str, Any]:

        return {
            "risk_score": 0,
            "confidence": 0,
            "verdict": "UNKNOWN",
            "detail_verdict": (
                "INSUFFICIENT_EVIDENCE"
            ),
            "recommendation": (
                "Insufficient evidence to determine "
                "whether this email is legitimate."
            ),
            "structured_evidence": [],
        }