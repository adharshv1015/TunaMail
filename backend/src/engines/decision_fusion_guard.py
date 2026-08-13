# ============================================================
# backend/src/engines/decision_fusion_guard.py
# ============================================================

def enforce_deterministic_priority(
    decision,
    analysis,
):

    decision = dict(decision or {})

    critical = []
    contradictions = []

    def walk(value):

        if isinstance(value, dict):

            severity = str(
                value.get(
                    "severity",
                    "",
                )
            ).upper()

            if severity == "CRITICAL":
                critical.append(value)

            if value.get(
                "reasoning_state"
            ) == "CONFLICTING_EVIDENCE":
                contradictions.append(value)

            for child in value.values():
                walk(child)

        elif isinstance(value, list):

            for child in value:
                walk(child)

    walk(analysis)

    is_trusted_sender = decision.get("is_trusted_sender", False)

    if critical:
        # For trusted senders (LinkedIn, Google, etc.) only apply the CRITICAL
        # override when the base risk score is already ≥ 60. This prevents a
        # single CRITICAL-tagged field (e.g. a tracking-link TLS warning) from
        # incorrectly overriding a clean trusted-org verdict to PHISHING.
        critical_applies = (not is_trusted_sender) or int(decision.get("risk_score", 0)) >= 60

        if critical_applies:
            decision["risk_score"] = max(
                int(
                    decision.get(
                        "risk_score",
                        0,
                    )
                ),
                80,
            )

            decision["confidence"] = max(
                int(
                    decision.get(
                        "confidence",
                        0,
                    )
                ),
                70,
            )

            decision["verdict"] = (
                "PHISHING"
            )

            decision["detail_verdict"] = (
                "MALICIOUS_EVIDENCE"
            )

        return decision

    if contradictions:

        decision["verdict"] = "UNKNOWN"
        decision["detail_verdict"] = (
            "CONFLICTING_EVIDENCE"
        )

        decision["confidence"] = min(
            int(
                decision.get(
                    "confidence",
                    0,
                )
            ),
            50,
        )

    return decision


# ============================================================
# REQUIRED FINAL DECISION RULES
# ============================================================

def enforce_unknown_when_insufficient(
    decision,
    analysis,
):

    decision = dict(decision or {})

    confidence = int(
        decision.get(
            "confidence",
            0,
        )
    )

    context = (
        analysis.get("ai", {})
        .get("context", {})
    )

    reasoning = (
        analysis.get("ai", {})
        .get("reasoning_state")
    )

    if (
        context.get("state")
        in {
            "LIMITED_CONTEXT",
            "INSUFFICIENT_EVIDENCE",
        }
        or reasoning
        in {
            "LIMITED_CONTEXT",
            "INSUFFICIENT_EVIDENCE",
        }
    ):

        if confidence < 60:

            decision["verdict"] = "UNKNOWN"

    return decision
