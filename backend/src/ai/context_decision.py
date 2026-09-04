# ============================================================
# backend/src/ai/context_decision.py
# ============================================================

from .context_rules import analyze_context


def calculate_positive_evidence(analysis):

    authentication = (
        analysis.get("authentication")
        or {}
    )

    trust = (
        analysis.get("trust")
        or {}
    )

    url_data = (
        analysis.get("url")
        or {}
    )

    score = 0
    reasons = []

    if authentication.get("spf") == "pass":
        score += 15
        reasons.append("SPF passed")

    if authentication.get("dkim") == "pass":
        score += 15
        reasons.append("DKIM passed")

    if authentication.get("dmarc") == "pass":
        score += 15
        reasons.append("DMARC passed")

    if trust.get("is_trusted_sender") is True:
        score += 15
        reasons.append("Sender has established trust")

    url_analysis = url_data.get("analysis") or []

    if isinstance(url_analysis, list):
        for item in url_analysis:
            if not isinstance(item, dict):
                continue

            domain_reputation = item.get("domain_reputation")

            if domain_reputation == "trusted":
                score += 15
                reasons.append(
                    "URL domain has established reputation"
                )
                break

    if isinstance(url_analysis, list):
        for item in url_analysis:
            if not isinstance(item, dict):
                continue

            redirects = item.get("redirects") or {}

            if (
                isinstance(redirects, dict)
                and redirects.get("detected") is False
                and redirects.get("chain") == []
            ):
                score += 5
                reasons.append(
                    "No redirect chain detected"
                )
                break

    return {
        "score": min(score, 100),
        "reasons": reasons,
    }


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

        if not positive["score"] >= 45:

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
