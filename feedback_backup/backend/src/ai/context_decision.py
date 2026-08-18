# ============================================================
# backend/src/ai/context_decision.py
# ============================================================

from .context_rules import analyze_context
from .positive_evidence import calculate_positive_evidence


def apply_context_rules(
    parsed_email,
    analysis,
    decision,
):

    context = analyze_context(
        parsed_email
    )

    positive = calculate_positive_evidence(
        analysis
    )

    decision = dict(decision or {})

    decision["context"] = context
    decision["positive_evidence"] = positive

    risk = int(
        decision.get(
            "risk_score",
            0,
        )
    )

    confidence = int(
        decision.get(
            "confidence",
            0,
        )
    )

    if context["state"] == "INSUFFICIENT_EVIDENCE":

        decision["verdict"] = "UNKNOWN"
        decision["detail_verdict"] = (
            "INSUFFICIENT_EVIDENCE"
        )

        confidence = min(
            confidence,
            35,
        )

    elif context["state"] == "LIMITED_CONTEXT":

        if positive["score"] < 45:

            decision["verdict"] = "UNKNOWN"
            decision["detail_verdict"] = (
                "LIMITED_CONTEXT"
            )

            confidence = min(
                confidence,
                45,
            )

    decision["confidence"] = confidence

    return decision
