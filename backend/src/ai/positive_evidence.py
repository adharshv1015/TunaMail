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

    urls = (
        analysis.get("urls")
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

    if trust.get("trusted") is True:
        score += 15
        reasons.append("Sender has established trust")

    if urls.get("domain_reputation") == "trusted":
        score += 15
        reasons.append("URL domain has established reputation")

    if urls.get("redirects") == []:
        score += 5
        reasons.append("No redirect chain detected")

    return {
        "score": min(score, 100),
        "reasons": reasons,
    }
