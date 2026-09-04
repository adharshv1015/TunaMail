# ============================================================
# backend/src/ai/positive_evidence.py
# ============================================================

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
