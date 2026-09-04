import logging

logger = logging.getLogger(__name__)


class DecisionFusionEngine:
    """
    Final evidence-fusion layer.

    Rules:
    - Current deterministic evidence has priority over AI/history.
    - Historical reputation never overrides current malicious evidence.
    - Trusted sender status is supporting evidence, not a bypass.
    - Risk score and confidence remain separate.
    - UNKNOWN is preserved when evidence is insufficient.
    - AI recommendations are treated as evidence, not authority.
    """

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

    POSITIVE_TYPES = {
        "AUTHENTICATION_PASS",
        "DOMAIN_ALIGNMENT",
        "URL_ALIGNMENT",
        "VALID_HISTORICAL_EVIDENCE",
        "TRUSTED_SENDER",
        "TRUSTED_DOMAIN",
        "NORMAL_BEHAVIOR",
    }

    CONTRADICTION_TYPES = {
        "CONFLICTING_EVIDENCE",
        "HISTORICAL_CURRENT_CONFLICT",
        "TRUST_HISTORY_CONFLICT",
        "AI_IGNORED_DUE_TO_MALICE",
        "AI_LEGITIMACY_CONFLICT",
    }

    def __init__(self):
        pass

    # =========================================================
    # NORMALIZATION
    # =========================================================

    @staticmethod
    def _normalize_type(value):
        return (
            str(value or "UNKNOWN")
            .strip()
            .upper()
            .replace("-", "_")
            .replace(" ", "_")
        )

    @staticmethod
    def _normalize_direction(value):
        value = str(value or "NEUTRAL").upper()

        if value in {"BENIGN", "POSITIVE"}:
            return "POSITIVE"

        if value in {"MALICIOUS", "NEGATIVE"}:
            return "NEGATIVE"

        return "NEUTRAL"

    @staticmethod
    def _normalize_severity(value):
        value = str(value or "INFO").upper()

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
    def _safe_int(value, default=0):
        try:
            return int(round(float(value)))
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _clamp_score(value):
        return max(
            0,
            min(
                100,
                DecisionFusionEngine._safe_int(value),
            ),
        )

    @staticmethod
    def _clamp_confidence(value):
        return max(
            0,
            min(
                100,
                DecisionFusionEngine._safe_int(value),
            ),
        )

    # =========================================================
    # STRUCTURED EVIDENCE
    # =========================================================

    def _extract_structured_evidence(
        self,
        are_result,
        evidence_graph=None,
    ):
        evidence = []

        for item in (
            are_result.get(
                "structured_evidence",
                [],
            )
            or []
        ):
            normalized = self._normalize_evidence(item)

            if normalized:
                evidence.append(normalized)

        if isinstance(evidence_graph, dict):
            graph_items = (
                evidence_graph.get(
                    "evidence",
                    [],
                )
                or []
            )

            for item in graph_items:
                normalized = self._normalize_evidence(item)

                if normalized:
                    evidence.append(normalized)

        # Remove duplicates while preserving order.
        unique = []
        fingerprints = set()

        for item in evidence:
            fingerprint = (
                item["type"],
                item["source"],
                item["direction"],
                item["severity"],
                item["explanation"],
            )

            if fingerprint in fingerprints:
                continue

            fingerprints.add(fingerprint)
            unique.append(item)

        return unique

    def _normalize_evidence(self, item):
        if not isinstance(item, dict):
            return None

        return {
            "type": self._normalize_type(
                item.get("type")
            ),
            "severity": self._normalize_severity(
                item.get("severity")
            ),
            "direction": self._normalize_direction(
                item.get("direction")
                or item.get("supports")
            ),
            "source": str(
                item.get(
                    "source",
                    "UNKNOWN",
                )
            ),
            "explanation": str(
                item.get(
                    "explanation",
                    "",
                )
            ),
            "confidence": max(
                0.0,
                min(
                    1.0,
                    self._safe_float(
                        item.get(
                            "confidence",
                            0,
                        )
                    ),
                ),
            ),
        }

    @staticmethod
    def _safe_float(value, default=0.0):
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    # =========================================================
    # EVIDENCE GROUPS
    # =========================================================

    def _critical_negative(self, evidence):
        return [
            item
            for item in evidence
            if item["direction"] == "NEGATIVE"
            and (
                item["severity"] == "CRITICAL"
                or item["type"]
                in self.CRITICAL_NEGATIVE_TYPES
            )
        ]

    def _strong_negative(self, evidence):
        return [
            item
            for item in evidence
            if item["direction"] == "NEGATIVE"
            and (
                item["severity"]
                in {"HIGH", "CRITICAL"}
                or item["type"]
                in self.STRONG_NEGATIVE_TYPES
            )
        ]

    def _all_negative(self, evidence):
        return [
            item
            for item in evidence
            if item["direction"] == "NEGATIVE"
        ]

    def _positive(self, evidence):
        return [
            item
            for item in evidence
            if item["direction"] == "POSITIVE"
        ]

    def _contradictions(self, evidence):
        return [
            item
            for item in evidence
            if item["type"]
            in self.CONTRADICTION_TYPES
        ]

    # =========================================================
    # TEXT FALLBACK
    # =========================================================

    def _fallback_negative_from_reasoning(
        self,
        reasoning,
    ):
        """
        Compatibility fallback for legacy evidence arrays.
        Structured evidence remains authoritative.
        """
        results = []

        if not isinstance(reasoning, dict):
            return results

        categories = (
            "technical",
            "behavioral",
            "network",
        )

        critical_patterns = {
            "credential harvesting": (
                "CREDENTIAL_HARVESTING"
            ),
            "brand impersonation": (
                "BRAND_IMPERSONATION"
            ),
            "known malicious url": (
                "KNOWN_MALICIOUS_URL"
            ),
            "executable attachment": (
                "EXECUTABLE_ATTACHMENT"
            ),
            "script attachment": (
                "SCRIPT_ATTACHMENT"
            ),
            "malicious redirect": (
                "MALICIOUS_REDIRECT"
            ),
        }

        strong_patterns = {
            "hostname mismatch": (
                "HOSTNAME_MISMATCH"
            ),
            "punycode": (
                "PUNYCODE_DOMAIN"
            ),
            "domain mismatch": (
                "DOMAIN_MISMATCH"
            ),
            "credential request": (
                "CREDENTIAL_REQUEST"
            ),
            "suspicious url": (
                "SUSPICIOUS_URL"
            ),
            "financial request": (
                "FINANCIAL_REQUEST"
            ),
        }

        medium_patterns = {
            "tls policy violation": (
                "TLS_POLICY_VIOLATION"
            ),
        }

        for category in categories:
            for raw in (
                reasoning.get(
                    category,
                    [],
                )
                or []
            ):
                text = str(raw)
                lowered = text.lower()

                matched_type = None
                severity = "MEDIUM"

                for pattern, evidence_type in (
                    critical_patterns.items()
                ):
                    if pattern in lowered:
                        matched_type = evidence_type
                        severity = "CRITICAL"
                        break

                if not matched_type:
                    for pattern, evidence_type in (
                        strong_patterns.items()
                    ):
                        if pattern in lowered:
                            matched_type = evidence_type
                            severity = "HIGH"
                            break

                if not matched_type:
                    for pattern, evidence_type in (
                        medium_patterns.items()
                    ):
                        if pattern in lowered:
                            matched_type = evidence_type
                            severity = "MEDIUM"
                            break

                if matched_type:
                    results.append({
                        "type": matched_type,
                        "severity": severity,
                        "direction": "NEGATIVE",
                        "source": f"legacy:{category}",
                        "explanation": text,
                        "confidence": 0.70,
                    })

        return results

    # =========================================================
    # RECOMMENDATION
    # =========================================================

    def get_recommendation(self, verdict):
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
                "but sender legitimacy is not fully verified."
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
                "Do not interact until verified."
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

    # =========================================================
    # FINAL EVALUATION
    # =========================================================

    def evaluate(
        self,
        are_result,
        conflict_result=None,
        evidence_graph=None,
    ):
        are_result = are_result or {}

        risk_score = self._clamp_score(
            are_result.get(
                "risk_score",
                0,
            )
        )

        confidence = self._clamp_confidence(
            are_result.get(
                "confidence",
                50,
            )
        )

        detail_verdict = str(
            are_result.get(
                "detail_verdict",
                "",
            )
        ).upper()

        are_verdict = str(
            are_result.get(
                "verdict",
                "UNKNOWN",
            )
        ).upper()

        reasoning = (
            are_result.get(
                "evidence",
                {},
            )
            or are_result.get(
                "reasoning",
                {},
            )
            or {}
        )

        is_trusted_sender = bool(
            are_result.get(
                "is_trusted_sender",
                False,
            )
        )

        structured_evidence = (
            self._extract_structured_evidence(
                are_result,
                evidence_graph,
            )
        )

        # Backward-compatible fallback when structured
        # evidence is unavailable.
        legacy_negative = (
            self._fallback_negative_from_reasoning(
                reasoning
            )
        )

        existing_types = {
            item["type"]
            for item in structured_evidence
        }

        for item in legacy_negative:
            if item["type"] not in existing_types:
                structured_evidence.append(item)

        critical_negative = (
            self._critical_negative(
                structured_evidence
            )
        )

        strong_negative = (
            self._strong_negative(
                structured_evidence
            )
        )

        all_negative = (
            self._all_negative(
                structured_evidence
            )
        )

        positive = self._positive(
            structured_evidence
        )

        contradictions = self._contradictions(
            structured_evidence
        )

        # Detect unavailable analyzers.
        unavailable = any(
            "unavailable" in str(item).lower()
            for category in (
                "technical",
                "behavioral",
                "network",
            )
            for item in (
                reasoning.get(
                    category,
                    [],
                )
                or []
            )
        )

        if (
            unavailable
            and detail_verdict
            not in {
                "LIMITED_CONTEXT",
                "INSUFFICIENT_EVIDENCE",
                "LINK_ONLY",
            }
        ):
            detail_verdict = "UNAVAILABLE"

        # -----------------------------------------------------
        # Determine evidence strength
        # -----------------------------------------------------

        has_critical = bool(
            critical_negative
        )

        has_strong = bool(
            strong_negative
        )

        has_any_negative = bool(
            all_negative
        )

        has_contradiction = bool(
            contradictions
        ) or detail_verdict == (
            "CONFLICTING_EVIDENCE"
        )

        # -----------------------------------------------------
        # Analyze page-intelligence-derived evidence
        # -----------------------------------------------------

        page_credential_harvest = any(
            item["type"]
            in {
                "CREDENTIAL_HARVESTING",
                "CREDENTIAL_FORM",
            }
            and item["direction"]
            == "NEGATIVE"
            for item in structured_evidence
        )

        # -----------------------------------------------------
        # Determine final verdict
        # -----------------------------------------------------

        verdict = "UNKNOWN"

        # -----------------------------------------------------
        # Preserve degraded / limited-context state from ARE
        # -----------------------------------------------------

        if (
            are_verdict == "UNKNOWN"
            and detail_verdict in {"LIMITED_CONTEXT", "INSUFFICIENT_EVIDENCE"}
        ):
            verdict = "UNKNOWN"
            detail_verdict = "LIMITED_CONTEXT"
            confidence = min(confidence, 40)

        # -----------------------------------------------------
        # Priority 1:
        # CURRENT CRITICAL DETERMINISTIC EVIDENCE
        # -----------------------------------------------------

        elif has_critical:
            verdict = "PHISHING"
            risk_score = max(
                risk_score,
                80,
            )

        # -----------------------------------------------------
        # Priority 2:
        # STRONG CURRENT SECURITY EVIDENCE
        # -----------------------------------------------------

        elif has_strong:

            if risk_score >= 80:
                verdict = "PHISHING"

            elif risk_score >= 60:
                verdict = "HIGH RISK"

            elif risk_score >= 40:
                verdict = "SUSPICIOUS"

            elif risk_score < 40:
                verdict = "SAFE"


        # -----------------------------------------------------
        # Priority 3:
        # Context / contradiction states
        # -----------------------------------------------------

        elif detail_verdict in {
            "LIMITED_CONTEXT",
            "INSUFFICIENT_EVIDENCE",
            "LINK_ONLY",
            "UNAVAILABLE",
        }:
            verdict = "UNKNOWN"
            confidence = min(
                confidence,
                40,
            )
            
            has_all_attachments_deep_scanned = any(
                item.get("type") == "ALL_ATTACHMENTS_DEEP_SCAN_COMPLETED" 
                for item in structured_evidence
            )
            
            if (
                risk_score == 0 
                and not has_any_negative 
                and has_all_attachments_deep_scanned
            ):
                verdict = "SAFE"

        elif has_contradiction:

            verdict = "UNKNOWN"
            confidence = min(
                confidence,
                50,
            )

            if risk_score >= 40:
                verdict = "SUSPICIOUS"
            else:
                verdict = "SAFE"

        # -----------------------------------------------------
        # Priority 4:
        # Numeric score as supporting evidence
        # -----------------------------------------------------

        elif risk_score >= 80:
            verdict = "PHISHING"

        elif risk_score >= 60:
            verdict = "HIGH RISK"

        elif risk_score >= 40:
            verdict = "SUSPICIOUS"

        elif risk_score < 40:

            if (
                len(positive) >= 3
                and confidence >= 90
                and not has_any_negative
                and not has_contradiction
            ):
                verdict = "VERIFIED LEGITIMATE"

            elif (
                len(positive) >= 2
                and confidence >= 70
                and not has_any_negative
                and not has_contradiction
            ):
                verdict = "LIKELY LEGITIMATE"

            else:
                verdict = "SAFE"
        # -----------------------------------------------------
        # Priority 5:
        # Low-risk legitimacy
        # -----------------------------------------------------

        elif (
            not has_any_negative
            and not has_contradiction
        ):

            positive_types = {
                item["type"]
                for item in positive
            }

            if (
                len(positive_types) >= 3
                and confidence >= 90
            ):
                verdict = "VERIFIED LEGITIMATE"

            elif (
                len(positive_types) >= 2
                and confidence >= 70
            ):
                verdict = "LIKELY LEGITIMATE"

            elif confidence >= 70:
                verdict = "LOW RISK"

            elif confidence >= 50:
                verdict = "LOW RISK"

            else:
                verdict = "UNKNOWN"

        else:
            verdict = "UNKNOWN"

        # -----------------------------------------------------
        # Detail verdict adjustments
        # -----------------------------------------------------

        if detail_verdict == "TRUST_HISTORY_CONFLICT":
            if verdict in {
                "PHISHING",
                "HIGH RISK",
            }:
                detail_verdict = (
                    "POSSIBLE_COMPROMISED_SENDER"
                )

            elif has_any_negative:
                detail_verdict = (
                    "TRUST_HISTORY_CONFLICT"
                )
                confidence = min(
                    confidence,
                    55,
                )

        elif detail_verdict == "SUSPICIOUS_HISTORY":

            if has_any_negative:
                verdict = max(
                    ["UNKNOWN", "SUSPICIOUS"],
                    key=lambda item: 1
                    if item == verdict
                    else 0,
                )

        elif detail_verdict in {
            "DOMAIN_DRIFT",
            "AUTHENTICATION_DRIFT",
        }:

            if has_any_negative:
                if verdict in {
                    "VERIFIED LEGITIMATE",
                    "LIKELY LEGITIMATE",
                    "LOW RISK",
                    "SAFE",
                    "UNKNOWN",
                }:
                    verdict = "SUSPICIOUS"

        # -----------------------------------------------------
        # AI sanity information
        # -----------------------------------------------------

        ai = (
            are_result.get(
                "ai",
                {},
            )
            or {}
        )

        recommended = str(
            ai.get(
                "recommended_classification",
                "",
            )
        ).upper()

        # AI says SAFE/LEGITIMATE but current critical
        # malicious evidence exists.
        if (
            recommended
            in {
                "SAFE",
                "LEGITIMATE",
                "LIKELY_LEGITIMATE",
                "VERIFIED_LEGITIMATE",
            }
            and has_critical
        ):
            verdict = "PHISHING"
            risk_score = max(
                risk_score,
                80,
            )
            detail_verdict = (
                "MALICIOUS_EVIDENCE"
            )

        # AI says PHISHING but there is no meaningful
        # current malicious evidence.
        elif (
            recommended == "PHISHING"
            and not has_any_negative
            and risk_score < 30
        ):
            verdict = "UNKNOWN"
            confidence = min(
                confidence,
                45,
            )
            detail_verdict = (
                "INSUFFICIENT_EVIDENCE"
            )

        # AI says SUSPICIOUS while there is strong
        # independent positive evidence and no negative evidence.
        elif (
            recommended == "SUSPICIOUS"
            and len(positive) >= 2
            and not has_any_negative
            and not has_contradiction
        ):
            verdict = "LIKELY LEGITIMATE"
            confidence = min(
                confidence,
                70,
            )
            detail_verdict = (
                "AI_LEGITIMACY_CONFLICT"
            )

        # -----------------------------------------------------
        # Trusted sender protection
        # -----------------------------------------------------

        # Trusted sender cannot override current malicious
        # evidence.
        if (
            is_trusted_sender
            and has_any_negative
        ):

            if has_critical:
                verdict = "PHISHING"
                risk_score = max(
                    risk_score,
                    80,
                )
                detail_verdict = (
                    "POSSIBLE_COMPROMISED_SENDER"
                )

            elif (
                risk_score >= 40
                and verdict
                in {
                    "SAFE",
                    "LOW RISK",
                    "LIKELY LEGITIMATE",
                    "VERIFIED LEGITIMATE",
                    "UNKNOWN",
                }
            ):
                verdict = "SUSPICIOUS"

                if (
                    detail_verdict
                    in {
                        "",
                        "UNKNOWN",
                        None,
                    }
                ):
                    detail_verdict = (
                        "TRUST_HISTORY_CONFLICT"
                    )

        # -----------------------------------------------------
        # Ensure malicious evidence cannot end in safe state
        # -----------------------------------------------------

        if (
            has_critical
            and verdict
            in {
                "SAFE",
                "LOW RISK",
                "LIKELY LEGITIMATE",
                "VERIFIED LEGITIMATE",
                "UNKNOWN",
            }
        ):
            verdict = "PHISHING"
            risk_score = max(
                risk_score,
                80,
            )
            detail_verdict = (
                "MALICIOUS_EVIDENCE"
            )

        # -----------------------------------------------------
        # Ensure weak PHISHING has evidence
        # -----------------------------------------------------

        if (
            verdict == "PHISHING"
            and not has_any_negative
        ):
            verdict = "UNKNOWN"
            confidence = min(
                confidence,
                50,
            )
            detail_verdict = (
                "INSUFFICIENT_EVIDENCE"
            )

        # -----------------------------------------------------
        # Unknown + strong current malicious evidence
        # -----------------------------------------------------

        if (
            verdict == "UNKNOWN"
            and has_strong
            and detail_verdict not in {
                "LIMITED_CONTEXT",
                "INSUFFICIENT_EVIDENCE",
            }
        ):
            if risk_score >= 80:
                verdict = "PHISHING"
                detail_verdict = (
                    "MALICIOUS_EVIDENCE"
                )
            else:
                verdict = "SUSPICIOUS"
                detail_verdict = (
                    "SUSPICIOUS_EVIDENCE"
                )

        # -----------------------------------------------------
        # Confidence calibration
        # -----------------------------------------------------

        if has_critical:
            confidence = max(
                confidence,
                75,
            )

        elif (
            has_strong
            and len(all_negative) >= 2
        ):
            confidence = max(
                confidence,
                65,
            )

        if has_contradiction:
            confidence = min(
                confidence,
                50,
            )

        if detail_verdict in {
            "LIMITED_CONTEXT",
            "LINK_ONLY",
        } and not has_critical:
            confidence = min(
                confidence,
                40,
            )

        if detail_verdict == (
            "INSUFFICIENT_EVIDENCE"
        ):
            confidence = min(
                confidence,
                45,
            )

        # -----------------------------------------------------
        # Final normalization
        # -----------------------------------------------------

        risk_score = self._clamp_score(
            risk_score
        )

        confidence = self._clamp_confidence(
            confidence
        )

        recommendation = (
            self.get_recommendation(
                verdict
            )
        )

        adaptive_factors = []

        adaptive = (
            are_result.get(
                "adaptive_info",
                {},
            )
            or {}
        )

        adaptive_factors.extend(
            adaptive.get(
                "behavioral_anomalies",
                [],
            )
            or []
        )

        explanation = (
            self._build_explanation(
                verdict=verdict,
                detail_verdict=detail_verdict,
                risk_score=risk_score,
                confidence=confidence,
                structured_evidence=structured_evidence,
                adaptive_factors=adaptive_factors,
            )
        )

        return {
            "risk_score": risk_score,
            "confidence": confidence,
            "verdict": verdict,
            "detail_verdict": detail_verdict,
            "recommendation": recommendation,
            "reasoning": reasoning,
            "explanation": explanation,
            "evidence_quality": (
                self.get_evidence_quality(
                    confidence
                )
            ),
            "is_trusted_sender": (
                is_trusted_sender
            ),
            "structured_evidence": (
                structured_evidence
            ),
        }

    # =========================================================
    # EXPLANATION
    # =========================================================

    def _build_explanation(
        self,
        verdict,
        detail_verdict,
        risk_score,
        confidence,
        structured_evidence,
        adaptive_factors=None,
    ):
        severity_map = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
        }

        positive = [
            item
            for item in structured_evidence
            if item["direction"]
            == "POSITIVE"
        ]

        negative = [
            item
            for item in structured_evidence
            if item["direction"]
            == "NEGATIVE"
        ]

        neutral = [
            item
            for item in structured_evidence
            if item["direction"]
            == "NEUTRAL"
        ]

        positive = sorted(
            positive,
            key=lambda item: severity_map.get(
                item["severity"],
                0,
            ),
            reverse=True,
        )

        negative = sorted(
            negative,
            key=lambda item: severity_map.get(
                item["severity"],
                0,
            ),
            reverse=True,
        )

        if verdict in {
            "PHISHING",
            "HIGH RISK",
            "SUSPICIOUS",
        }:

            if negative:
                primary_reason = (
                    negative[0].get(
                        "explanation"
                    )
                    or "Current security evidence indicates risk."
                )
            else:
                primary_reason = (
                    "Risk classification lacks explicit "
                    "supporting evidence."
                )

        elif verdict in {
            "VERIFIED LEGITIMATE",
            "LIKELY LEGITIMATE",
        }:

            if positive:
                types = []

                for item in positive:
                    item_type = (
                        item.get(
                            "type",
                            "",
                        )
                        .replace(
                            "_",
                            " ",
                        )
                        .lower()
                    )

                    if item_type and item_type not in types:
                        types.append(
                            item_type
                        )

                primary_reason = (
                    "Legitimate classification is supported "
                    "by: "
                    + ", ".join(
                        types[:5]
                    )
                    + "."
                )

            else:
                primary_reason = (
                    "No explicit positive evidence was available."
                )

        elif verdict in {
            "SAFE",
            "LOW RISK",
        }:

            if positive:
                primary_reason = (
                    "No significant current threats were "
                    "detected and supporting legitimacy "
                    "evidence is present."
                )
            else:
                primary_reason = (
                    "No significant current threats were "
                    "detected, but evidence is limited."
                )

        else:
            primary_reason = (
                "Insufficient evidence to establish sender intent."
            )

        limitations = []

        if detail_verdict in {
            "LIMITED_CONTEXT",
            "LINK_ONLY",
        }:
            limitations.append(
                "The message contains limited context."
            )

        if detail_verdict in {
            "CONFLICTING_EVIDENCE",
            "TRUST_HISTORY_CONFLICT",
            "POSSIBLE_COMPROMISED_SENDER",
            "AI_LEGITIMACY_CONFLICT",
        }:
            limitations.append(
                "Different evidence sources disagree."
            )

        if neutral:
            limitations.append(
                f"{len(neutral)} neutral/conflicting "
                "evidence items were considered."
            )

        return {
            "summary": (
                f"{verdict.title()} detected."
            ),
            "primary_reason": primary_reason,
            "supporting_evidence": (
                negative
                if verdict
                in {
                    "PHISHING",
                    "HIGH RISK",
                    "SUSPICIOUS",
                }
                else positive
            ),
            "contradicting_evidence": (
                positive
                if verdict
                in {
                    "PHISHING",
                    "HIGH RISK",
                    "SUSPICIOUS",
                }
                else negative
            ),
            "positive_evidence": positive,
            "negative_evidence": negative,
            "adaptive_factors": (
                adaptive_factors or []
            ),
            "confidence_factors": [
                f"{len(positive)} positive signals",
                f"{len(negative)} negative signals",
                f"Confidence: {confidence}%",
            ],
            "limitations": limitations,
        }

    # =========================================================
    # EVIDENCE QUALITY
    # =========================================================

    def get_evidence_quality(
        self,
        confidence,
    ):
        if confidence >= 80:
            return "HIGH"

        if confidence >= 50:
            return "MEDIUM"

        return "LIMITED"

    # =========================================================
    # RECOMMENDATION
    # =========================================================

    def get_recommendation(
        self,
        verdict,
    ):
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