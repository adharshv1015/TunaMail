from __future__ import annotations

from typing import Any, Dict, List


# ============================================================
# Evidence definitions
# ============================================================

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

SAFE_VERDICTS = {
    "SAFE",
    "LIKELY LEGITIMATE",
    "VERIFIED LEGITIMATE",
    "LOW RISK",
}

RISK_VERDICTS = {
    "SUSPICIOUS",
    "HIGH RISK",
    "PHISHING",
}


# ============================================================
# Generic helpers
# ============================================================

def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(round(float(value)))
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _clamp_score(value: Any) -> int:
    return max(0, min(100, _safe_int(value)))


def _clamp_confidence(value: Any) -> int:
    return max(0, min(100, _safe_int(value)))


def _normalize_type(value: Any) -> str:
    return (
        str(value or "UNKNOWN")
        .strip()
        .upper()
        .replace("-", "_")
        .replace(" ", "_")
    )


def _normalize_direction(value: Any) -> str:
    value = str(value or "NEUTRAL").strip().upper()

    if value in {"BENIGN", "POSITIVE"}:
        return "POSITIVE"

    if value in {"MALICIOUS", "NEGATIVE"}:
        return "NEGATIVE"

    return "NEUTRAL"


def _normalize_severity(value: Any) -> str:
    value = str(value or "INFO").strip().upper()

    if value not in {
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }:
        return "INFO"

    return value


# ============================================================
# Evidence extraction
# ============================================================

def _normalize_evidence(item: Any) -> Dict[str, Any] | None:
    if not isinstance(item, dict):
        return None

    return {
        "type": _normalize_type(item.get("type")),
        "severity": _normalize_severity(item.get("severity")),
        "direction": _normalize_direction(
            item.get("direction", item.get("supports"))
        ),
        "source": str(item.get("source", "UNKNOWN")),
        "explanation": str(item.get("explanation", "")),
        "confidence": max(
            0.0,
            min(
                1.0,
                _safe_float(item.get("confidence", 0.0)),
            ),
        ),
        "reasoning_state": str(
            item.get("reasoning_state", "")
        ).upper(),
    }


def _collect_structured_evidence(
    decision: Dict[str, Any],
    analysis: Dict[str, Any],
) -> List[Dict[str, Any]]:

    evidence: List[Dict[str, Any]] = []

    for item in (
        decision.get("structured_evidence", [])
        or []
    ):
        normalized = _normalize_evidence(item)

        if normalized:
            evidence.append(normalized)

    for item in (
        analysis.get("structured_evidence", [])
        or []
    ):
        normalized = _normalize_evidence(item)

        if normalized:
            evidence.append(normalized)

    graph = analysis.get("evidence_graph", {})

    if isinstance(graph, dict):
        for item in (
            graph.get("evidence", [])
            or []
        ):
            normalized = _normalize_evidence(item)

            if normalized:
                evidence.append(normalized)

    unique: List[Dict[str, Any]] = []
    seen = set()

    for item in evidence:
        key = (
            item["type"],
            item["severity"],
            item["direction"],
            item["source"],
            item["explanation"],
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(item)

    return unique


# ============================================================
# Legacy text fallback
# ============================================================

def _collect_legacy_evidence(
    decision: Dict[str, Any],
    analysis: Dict[str, Any],
) -> List[Dict[str, Any]]:

    reasoning = (
        decision.get("reasoning")
        or analysis.get("evidence")
        or {}
    )

    if not isinstance(reasoning, dict):
        return []

    mapping = {
        "credential harvesting": (
            "CREDENTIAL_HARVESTING",
            "CRITICAL",
        ),
        "brand impersonation": (
            "BRAND_IMPERSONATION",
            "CRITICAL",
        ),
        "known malicious url": (
            "KNOWN_MALICIOUS_URL",
            "CRITICAL",
        ),
        "malicious redirect": (
            "MALICIOUS_REDIRECT",
            "CRITICAL",
        ),
        "executable attachment": (
            "EXECUTABLE_ATTACHMENT",
            "CRITICAL",
        ),
        "script attachment": (
            "SCRIPT_ATTACHMENT",
            "CRITICAL",
        ),
        "malicious attachment": (
            "MALICIOUS_ATTACHMENT",
            "CRITICAL",
        ),
        "hostname mismatch": (
            "HOSTNAME_MISMATCH",
            "HIGH",
        ),
        "tls policy violation": (
            "TLS_POLICY_VIOLATION",
            "HIGH",
        ),
        "punycode domain detected": (
            "PUNYCODE_DOMAIN",
            "HIGH",
        ),
        "homoglyph": (
            "HOMOGRAPH_DOMAIN",
            "HIGH",
        ),
        "domain mismatch": (
            "DOMAIN_MISMATCH",
            "HIGH",
        ),
        "suspicious url": (
            "SUSPICIOUS_URL",
            "HIGH",
        ),
        "credential request": (
            "CREDENTIAL_REQUEST",
            "HIGH",
        ),
        "financial request": (
            "FINANCIAL_REQUEST",
            "HIGH",
        ),
        "newly registered domain": (
            "NEW_DOMAIN",
            "MEDIUM",
        ),
    }

    output: List[Dict[str, Any]] = []

    for category in (
        "technical",
        "behavioral",
        "network",
        "negative",
    ):
        for raw in (
            reasoning.get(category, [])
            or []
        ):
            text = str(raw)
            lowered = text.lower()

            matched_type = None
            severity = "MEDIUM"

            for pattern, (
                evidence_type,
                evidence_severity,
            ) in mapping.items():

                if pattern in lowered:
                    matched_type = evidence_type
                    severity = evidence_severity
                    break

            if not matched_type:
                continue

            output.append(
                {
                    "type": matched_type,
                    "severity": severity,
                    "direction": "NEGATIVE",
                    "source": f"legacy:{category}",
                    "explanation": text,
                    "confidence": 0.70,
                    "reasoning_state": "",
                }
            )

    return output


# ============================================================
# Evidence selection
# ============================================================

def _get_critical_evidence(
    evidence: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    return [
        item
        for item in evidence
        if item["direction"] == "NEGATIVE"
        and (
            item["severity"] == "CRITICAL"
            or item["type"] in CRITICAL_NEGATIVE_TYPES
        )
    ]


def _get_strong_evidence(
    evidence: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    return [
        item
        for item in evidence
        if item["direction"] == "NEGATIVE"
        and (
            item["severity"] in {
                "HIGH",
                "CRITICAL",
            }
            or item["type"] in STRONG_NEGATIVE_TYPES
        )
    ]


def _get_negative_evidence(
    evidence: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    return [
        item
        for item in evidence
        if item["direction"] == "NEGATIVE"
    ]


def _get_contradictions(
    evidence: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    return [
        item
        for item in evidence
        if (
            item["type"] in CONTRADICTION_TYPES
            or item["reasoning_state"]
            == "CONFLICTING_EVIDENCE"
        )
    ]


# ============================================================
# Authentication helper
# ============================================================

def _authentication_state(
    analysis: Dict[str, Any],
) -> str:

    authentication = (
        analysis.get("authentication", {})
        or {}
    )

    status = str(
        authentication.get(
            "analysis_status",
            "AVAILABLE",
        )
    ).upper()

    if status == "UNAVAILABLE":
        return "UNAVAILABLE"

    spf = str(
        authentication.get("spf", "")
    ).lower()

    dkim = str(
        authentication.get("dkim", "")
    ).lower()

    dmarc = str(
        authentication.get("dmarc", "")
    ).lower()

    if (
        spf == "pass"
        and dkim == "pass"
        and dmarc == "pass"
    ):
        return "PASSED"

    if (
        spf == "fail"
        or dkim == "fail"
        or dmarc == "fail"
    ):
        return "FAILED"

    return "PARTIAL"


# ============================================================
# Trusted sender safety check
# ============================================================

def _trusted_sender_is_overrideable(
    decision: Dict[str, Any],
    analysis: Dict[str, Any],
) -> bool:

    if not decision.get(
        "is_trusted_sender",
        False,
    ):
        return False

    return (
        _authentication_state(analysis)
        == "PASSED"
    )


# ============================================================
# Final normalization
# ============================================================

def _finalize(
    decision: Dict[str, Any],
) -> Dict[str, Any]:

    decision["risk_score"] = _clamp_score(
        decision.get("risk_score", 0)
    )

    decision["confidence"] = _clamp_confidence(
        decision.get("confidence", 0)
    )

    verdict = str(
        decision.get("verdict", "UNKNOWN")
    ).upper()

    allowed_verdicts = {
        "SAFE",
        "LOW RISK",
        "LIKELY LEGITIMATE",
        "VERIFIED LEGITIMATE",
        "UNKNOWN",
        "SUSPICIOUS",
        "HIGH RISK",
        "PHISHING",
    }

    if verdict not in allowed_verdicts:
        verdict = "UNKNOWN"

    decision["verdict"] = verdict

    if not decision.get("detail_verdict"):
        decision["detail_verdict"] = "UNKNOWN"

    return decision


# ============================================================
# Main deterministic guard
# ============================================================

def enforce_deterministic_priority(
    decision: Dict[str, Any] | None,
    analysis: Dict[str, Any] | None,
) -> Dict[str, Any]:

    decision = dict(decision or {})
    analysis = dict(analysis or {})

    risk_score = _clamp_score(
        decision.get("risk_score", 0)
    )

    confidence = _clamp_confidence(
        decision.get("confidence", 0)
    )

    verdict = str(
        decision.get("verdict", "UNKNOWN")
    ).upper()

    detail_verdict = str(
        decision.get("detail_verdict", "")
    ).upper()

    decision["risk_score"] = risk_score
    decision["confidence"] = confidence
    decision["verdict"] = verdict
    decision["detail_verdict"] = detail_verdict

    structured_evidence = _collect_structured_evidence(
        decision,
        analysis,
    )

    existing_types = {
        item["type"]
        for item in structured_evidence
    }

    for item in _collect_legacy_evidence(
        decision,
        analysis,
    ):
        if item["type"] not in existing_types:
            structured_evidence.append(item)

    decision["structured_evidence"] = structured_evidence

    critical = _get_critical_evidence(
        structured_evidence
    )

    strong = _get_strong_evidence(
        structured_evidence
    )

    negative = _get_negative_evidence(
        structured_evidence
    )

    contradictions = _get_contradictions(
        structured_evidence
    )

    has_critical = bool(critical)
    has_strong = bool(strong)
    has_negative = bool(negative)
    has_contradiction = bool(contradictions)

    is_trusted_sender = bool(
        decision.get(
            "is_trusted_sender",
            False,
        )
    )

    history_conflict = any(
        item["type"] == "TRUST_HISTORY_CONFLICT"
        for item in structured_evidence
    )

    stale_history = any(
        item["type"] == "STALE_HISTORICAL_EVIDENCE"
        for item in structured_evidence
    )

    # --------------------------------------------------------
    # RULE 1
    # Critical malicious evidence ALWAYS wins.
    # --------------------------------------------------------

    if has_critical:

        decision["verdict"] = "PHISHING"

        decision["risk_score"] = max(
            risk_score,
            80,
        )

        decision["confidence"] = max(
            confidence,
            70,
        )

        decision["detail_verdict"] = (
            "MALICIOUS_EVIDENCE"
        )

        if is_trusted_sender:
            decision["detail_verdict"] = (
                "POSSIBLE_COMPROMISED_SENDER"
            )

        return _finalize(decision)

    # --------------------------------------------------------
    # RULE 2
    # Trusted sender + strong current evidence.
    # --------------------------------------------------------

    if (
        is_trusted_sender
        and has_strong
    ):

        if risk_score >= 80:
            decision["verdict"] = "PHISHING"
            decision["risk_score"] = max(
                risk_score,
                80,
            )

        elif risk_score >= 60:
            decision["verdict"] = "HIGH RISK"

        elif risk_score < 40:
            decision["verdict"] = "SAFE"

        else:
            decision["verdict"] = "SUSPICIOUS"

        decision["detail_verdict"] = (
            "POSSIBLE_COMPROMISED_SENDER"
        )

        decision["confidence"] = min(
            confidence,
            70,
        )

        return _finalize(decision)

    # --------------------------------------------------------
    # RULE 3
    # Strong current evidence.
    # --------------------------------------------------------

    if has_strong:

        if risk_score >= 80:
            decision["verdict"] = "PHISHING"

        elif risk_score >= 60:
            decision["verdict"] = "HIGH RISK"

        elif risk_score < 40:
            decision["verdict"] = "SAFE"

        else:
            decision["verdict"] = "SUSPICIOUS"

        decision["detail_verdict"] = (
            "STRONG_SECURITY_EVIDENCE"
        )

        return _finalize(decision)

    # --------------------------------------------------------
    # RULE 4
    # Safe verdict + contradiction.
    # --------------------------------------------------------

    if (
        verdict in SAFE_VERDICTS
        and has_contradiction
    ):

        decision["verdict"] = "UNKNOWN"

        decision["detail_verdict"] = (
            "CONFLICTING_EVIDENCE"
        )

        decision["confidence"] = min(
            confidence,
            50,
        )

        return _finalize(decision)

    # --------------------------------------------------------
    # RULE 5
    # UNKNOWN + evidence.
    # --------------------------------------------------------

    if verdict == "UNKNOWN":

        if has_critical:

            decision["verdict"] = "PHISHING"

            decision["risk_score"] = max(
                risk_score,
                80,
            )

            decision["detail_verdict"] = (
                "MALICIOUS_EVIDENCE"
            )

        elif has_strong:

            if risk_score >= 80:
                decision["verdict"] = "PHISHING"

            elif risk_score >= 60:
                decision["verdict"] = "HIGH RISK"

            elif risk_score < 40:
                decision["verdict"] = "SAFE"

            else:
                decision["verdict"] = "SUSPICIOUS"

            decision["detail_verdict"] = (
                "STRONG_SECURITY_EVIDENCE"
            )

        return _finalize(decision)

    # --------------------------------------------------------
    # RULE 6
    # PHISHING requires current negative evidence.
    # --------------------------------------------------------

    if (
        verdict == "PHISHING"
        and not has_negative
    ):

        decision["verdict"] = "SUSPICIOUS"

        decision["risk_score"] = max(
            min(risk_score, 59),
            40,
        )

        decision["confidence"] = min(
            confidence,
            50,
        )

        decision["detail_verdict"] = (
            "INSUFFICIENT_EVIDENCE"
        )

        return _finalize(decision)

    # --------------------------------------------------------
    # RULE 7
    # Stale historical evidence has no authority.
    # --------------------------------------------------------

    if stale_history:

        if (
            decision.get("verdict")
            in SAFE_VERDICTS
            and has_negative
        ):

            decision["verdict"] = "UNKNOWN"

            decision["confidence"] = min(
                confidence,
                50,
            )

            decision["detail_verdict"] = (
                "STALE_HISTORICAL_EVIDENCE"
            )

    # --------------------------------------------------------
    # RULE 8
    # Historical trust conflict.
    # --------------------------------------------------------

    if history_conflict:

        if (
            decision.get("verdict")
            in RISK_VERDICTS
        ):

            decision["detail_verdict"] = (
                "POSSIBLE_COMPROMISED_SENDER"
            )

        elif has_negative:
            if risk_score < 40:
                decision["verdict"] = "SAFE"
            else:
                decision["verdict"] = "SUSPICIOUS"
                decision["detail_verdict"] = "TRUST_HISTORY_CONFLICT"
            
            decision["confidence"] = min(
                confidence,
                55,
            )

    return _finalize(decision)


# ============================================================
# Insufficient evidence guard
# ============================================================

def enforce_unknown_when_insufficient(
    decision: Dict[str, Any] | None,
    analysis: Dict[str, Any] | None,
) -> Dict[str, Any]:

    decision = dict(decision or {})
    analysis = dict(analysis or {})

    structured = _collect_structured_evidence(
        decision,
        analysis,
    )

    has_positive_evidence = any(
        item.get("direction") == "POSITIVE"
        for item in structured
    )

    has_negative_evidence = bool(
        _get_negative_evidence(structured)
    )

    has_critical_evidence = bool(
        _get_critical_evidence(structured)
    )

    if (
        not has_positive_evidence
        and not has_negative_evidence
        and not has_critical_evidence
    ):

        decision["verdict"] = "UNKNOWN"
        decision["confidence"] = 0

    decision["risk_score"] = _clamp_score(
        decision.get("risk_score", 0)
    )

    decision["confidence"] = _clamp_confidence(
        decision.get("confidence", 0)
    )

    return _finalize(decision)