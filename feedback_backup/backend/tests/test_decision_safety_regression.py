# ============================================================
# backend/tests/test_decision_safety_regression.py
# ============================================================

from src.engines.decision_validator import DecisionValidator


def test_credential_harvesting_cannot_finish_safe():
    validator = DecisionValidator()

    decision = {
        "risk_score": 20,
        "confidence": 90,
        "verdict": "SAFE",
        "detail_verdict": "CLEAR_POSITIVE_EVIDENCE",
        "structured_evidence": [
            {
                "type": "CREDENTIAL_HARVESTING",
                "severity": "CRITICAL",
                "direction": "NEGATIVE",
                "source": "PagePhishingAnalyzer",
                "explanation": "Password harvesting form detected.",
                "confidence": 0.97,
            }
        ],
    }

    result = validator.validate(decision)

    assert result["verdict"] == "PHISHING"
    assert result["risk_score"] >= 80


def test_trusted_sender_does_not_override_current_malicious_evidence():
    validator = DecisionValidator()

    decision = {
        "risk_score": 25,
        "confidence": 95,
        "verdict": "VERIFIED LEGITIMATE",
        "detail_verdict": "CLEAR_POSITIVE_EVIDENCE",
        "is_trusted_sender": True,
        "structured_evidence": [
            {
                "type": "TRUSTED_SENDER",
                "severity": "LOW",
                "direction": "POSITIVE",
                "source": "TrustEngine",
                "explanation": "Known sender.",
                "confidence": 0.95,
            },
            {
                "type": "CREDENTIAL_HARVESTING",
                "severity": "CRITICAL",
                "direction": "NEGATIVE",
                "source": "PagePhishingAnalyzer",
                "explanation": "Credential form detected.",
                "confidence": 0.98,
            },
        ],
    }

    result = validator.validate(decision)

    assert result["verdict"] == "PHISHING"
    assert result["risk_score"] >= 80


def test_link_only_without_malicious_evidence_is_unknown():
    validator = DecisionValidator()

    decision = {
        "risk_score": 0,
        "confidence": 25,
        "verdict": "SAFE",
        "detail_verdict": "LIMITED_CONTEXT",
        "structured_evidence": [
            {
                "type": "LIMITED_CONTEXT",
                "severity": "MEDIUM",
                "direction": "NEUTRAL",
                "source": "URLAnalyzer",
                "explanation": "Email contains only a link.",
                "confidence": 0.90,
            }
        ],
    }

    result = validator.validate(decision)

    assert result["verdict"] == "UNKNOWN"


def test_malicious_url_cannot_finish_safe():
    validator = DecisionValidator()

    decision = {
        "risk_score": 15,
        "confidence": 85,
        "verdict": "LIKELY LEGITIMATE",
        "detail_verdict": "CLEAR_POSITIVE_EVIDENCE",
        "structured_evidence": [
            {
                "type": "KNOWN_MALICIOUS_URL",
                "severity": "CRITICAL",
                "direction": "NEGATIVE",
                "source": "URLAnalyzer",
                "explanation": "Known malicious URL detected.",
                "confidence": 0.99,
            }
        ],
    }

    result = validator.validate(decision)

    assert result["verdict"] == "PHISHING"
    assert result["risk_score"] >= 80


def test_brand_impersonation_cannot_finish_safe():
    validator = DecisionValidator()

    decision = {
        "risk_score": 10,
        "confidence": 90,
        "verdict": "SAFE",
        "detail_verdict": "CLEAR_POSITIVE_EVIDENCE",
        "structured_evidence": [
            {
                "type": "BRAND_IMPERSONATION",
                "severity": "CRITICAL",
                "direction": "NEGATIVE",
                "source": "BrandIntelligence",
                "explanation": "Brand impersonation detected.",
                "confidence": 0.95,
            }
        ],
    }

    result = validator.validate(decision)

    assert result["verdict"] == "PHISHING"
    assert result["risk_score"] >= 80


def test_executable_attachment_cannot_finish_safe():
    validator = DecisionValidator()

    decision = {
        "risk_score": 5,
        "confidence": 80,
        "verdict": "LIKELY LEGITIMATE",
        "detail_verdict": "CLEAR_POSITIVE_EVIDENCE",
        "structured_evidence": [
            {
                "type": "EXECUTABLE_ATTACHMENT",
                "severity": "CRITICAL",
                "direction": "NEGATIVE",
                "source": "AttachmentAnalyzer",
                "explanation": "Executable attachment detected.",
                "confidence": 0.98,
            }
        ],
    }

    result = validator.validate(decision)

    assert result["verdict"] == "PHISHING"
    assert result["risk_score"] >= 80


def test_plain_http_alone_does_not_become_phishing():
    validator = DecisionValidator()

    decision = {
        "risk_score": 5,
        "confidence": 70,
        "verdict": "UNKNOWN",
        "detail_verdict": "LIMITED_CONTEXT",
        "structured_evidence": [
            {
                "type": "HTTP_POLICY_WARNING",
                "severity": "LOW",
                "direction": "NEGATIVE",
                "source": "URLAnalyzer",
                "explanation": "URL uses plain HTTP.",
                "confidence": 0.90,
            }
        ],
    }

    result = validator.validate(decision)

    assert result["verdict"] != "PHISHING"


def test_valid_tls_alone_does_not_make_email_safe():
    validator = DecisionValidator()

    decision = {
        "risk_score": 0,
        "confidence": 40,
        "verdict": "SAFE",
        "detail_verdict": "CLEAR_POSITIVE_EVIDENCE",
        "structured_evidence": [
            {
                "type": "VALID_TLS",
                "severity": "INFO",
                "direction": "POSITIVE",
                "source": "TLSInspector",
                "explanation": "TLS certificate validation succeeded.",
                "confidence": 0.96,
            }
        ],
    }

    result = validator.validate(decision)

    assert result["verdict"] == "UNKNOWN"