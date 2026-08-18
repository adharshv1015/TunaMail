import logging

logger = logging.getLogger(__name__)


class DecisionConsistencyValidator:

    CRITICAL_TYPES = {
        "CREDENTIAL_HARVESTING",
        "BRAND_IMPERSONATION",
        "MALICIOUS_URL",
        "MALICIOUS_REDIRECT",
        "MALICIOUS_ATTACHMENT",
        "EXECUTABLE_ATTACHMENT",
    }

    STRONG_TYPES = {
        "CREDENTIAL_REQUEST",
        "SUSPICIOUS_URL",
        "HOMOGRAPH_DOMAIN",
        "PUNYCODE_DOMAIN",
        "SUSPICIOUS_REDIRECT",
        "DOMAIN_MISMATCH",
        "HOSTNAME_MISMATCH",
        "TLS_POLICY_VIOLATION",
    }

    def validate(self, final_decision, evidence_graph=None):

        decision = dict(final_decision or {})

        verdict = str(
            decision.get("verdict", "UNKNOWN")
        ).upper()

        evidence = self._extract_evidence(
            decision,
            evidence_graph or {},
        )

        critical = [
            item for item in evidence
            if item["type"] in self.CRITICAL_TYPES
            and item["direction"] == "NEGATIVE"
        ]

        strong = [
            item for item in evidence
            if item["type"] in self.STRONG_TYPES
            and item["direction"] == "NEGATIVE"
        ]

        contradictions = [
            item for item in evidence
            if item.get("type") == "CONFLICTING_EVIDENCE"
            or item.get("reasoning_state") == "CONFLICTING_EVIDENCE"
        ]

        has_critical = bool(critical)
        has_strong = bool(strong)

        # --------------------------------------------------
        # 1. SAFE / LEGITIMATE + critical malicious evidence
        # --------------------------------------------------

        if verdict in {
            "SAFE",
            "VERIFIED LEGITIMATE",
            "LIKELY LEGITIMATE",
        } and has_critical:

            decision["verdict"] = "PHISHING"
            decision["risk_score"] = max(
                int(decision.get("risk_score", 0)),
                80,
            )
            decision["detail_verdict"] = "MALICIOUS_EVIDENCE"

            self._prepend_explanation(
                decision,
                "Decision Consistency Validator: "
                "critical current malicious evidence overrides "
                "the previous legitimate verdict."
            )

            return decision

        # --------------------------------------------------
        # 2. VERIFIED LEGITIMATE + unresolved contradiction
        # --------------------------------------------------

        if (
            verdict == "VERIFIED LEGITIMATE"
            and contradictions
        ):

            decision["verdict"] = "UNKNOWN"
            decision["detail_verdict"] = (
                "CONFLICTING_EVIDENCE"
            )

            decision["confidence"] = min(
                int(decision.get("confidence", 0)),
                50,
            )

            self._prepend_explanation(
                decision,
                "Decision Consistency Validator: "
                "unresolved contradictions prevent a "
                "verified-legitimate conclusion."
            )

            return decision

        # --------------------------------------------------
        # 3. UNKNOWN + strong malicious evidence
        # --------------------------------------------------

        if verdict == "UNKNOWN":

            if has_critical:

                decision["verdict"] = "PHISHING"
                decision["risk_score"] = max(
                    int(decision.get("risk_score", 0)),
                    80,
                )
                decision["detail_verdict"] = (
                    "MALICIOUS_EVIDENCE"
                )

                return decision

            if has_strong:

                decision["verdict"] = "SUSPICIOUS"
                decision["risk_score"] = max(
                    int(decision.get("risk_score", 0)),
                    40,
                )
                decision["detail_verdict"] = (
                    "SUSPICIOUS_EVIDENCE"
                )

                return decision

        # --------------------------------------------------
        # 4. PHISHING with no malicious evidence
        # --------------------------------------------------

        if (
            verdict == "PHISHING"
            and not has_critical
            and not has_strong
        ):

            decision["verdict"] = "SUSPICIOUS"
            decision["detail_verdict"] = (
                "INSUFFICIENT_EVIDENCE"
            )

            decision["confidence"] = min(
                int(decision.get("confidence", 0)),
                50,
            )

            self._prepend_explanation(
                decision,
                "Decision Consistency Validator: "
                "the phishing verdict lacks supporting "
                "current malicious evidence."
            )

            return decision

        return decision

    def _extract_evidence(
        self,
        decision,
        evidence_graph,
    ):

        results = []

        reasoning = decision.get(
            "reasoning",
            {},
        )

        for category in (
            "technical",
            "behavioral",
            "network",
            "positive",
            "negative",
        ):

            items = reasoning.get(
                category,
                [],
            )

            if not isinstance(items, list):
                continue

            for item in items:

                if isinstance(item, dict):

                    results.append({
                        "type": str(
                            item.get(
                                "type",
                                "UNKNOWN",
                            )
                        ).upper(),
                        "severity": str(
                            item.get(
                                "severity",
                                "INFO",
                            )
                        ).upper(),
                        "direction": str(
                            item.get(
                                "direction",
                                "NEUTRAL",
                            )
                        ).upper(),
                        "reasoning_state": item.get(
                            "reasoning_state"
                        ),
                    })

        graph_items = (
            evidence_graph.get(
                "evidence",
                []
            )
            if isinstance(
                evidence_graph,
                dict,
            )
            else []
        )

        for item in graph_items:

            if isinstance(item, dict):

                results.append({
                    "type": str(
                        item.get(
                            "type",
                            "UNKNOWN",
                        )
                    ).upper(),
                    "severity": str(
                        item.get(
                            "severity",
                            "INFO",
                        )
                    ).upper(),
                    "direction": str(
                        item.get(
                            "direction",
                            "NEUTRAL",
                        )
                    ).upper(),
                    "reasoning_state": item.get(
                        "reasoning_state"
                    ),
                })

        return results

    @staticmethod
    def _prepend_explanation(
        decision,
        message,
    ):

        existing = decision.get(
            "explanation",
            "",
        )

        decision["explanation"] = (
            message
            + "\n\n"
            + str(existing)
        )