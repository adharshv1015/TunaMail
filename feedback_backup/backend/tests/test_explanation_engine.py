"""
Stage 13 — ExplanationEngine Tests
====================================
Tests for all 20 scenarios specified in Stage 13, plus the critical regression test
that proves the ExplanationEngine CANNOT modify the underlying security decision.
"""

import sys
import os
import copy
import pytest

# Ensure the backend src directory is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "intelligence"))

from src.ai.explanation_engine import ExplanationEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decision(verdict="UNKNOWN", risk=0, confidence=40, detail="INSUFFICIENT_EVIDENCE"):
    return {
        "verdict": verdict,
        "risk_score": risk,
        "confidence": confidence,
        "detail_verdict": detail,
        "recommendation": "Test recommendation.",
    }


def _auth(spf="pass", dkim="pass", dmarc="pass"):
    return {"spf": spf, "dkim": dkim, "dmarc": dmarc, "analysis_status": "AVAILABLE"}


def _url_item(domain="example.com", detections=0):
    return {
        "url": f"https://{domain}/path",
        "domain": domain,
        "threat_intelligence": {"detections": detections},
        "redirect_chain": {"final_risk": "LOW"},
    }


def _whois(domain="example.com", age_days=500):
    return {"domain": domain, "age_days": age_days, "age_category": "established"}


def _analysis(
    auth=None,
    urls=None,
    whois=None,
    content=None,
    attachment=None,
    trust=None,
    ai=None,
    conflict=None,
):
    return {
        "authentication": auth or _auth(),
        "url": {"analysis": urls or [], "risk_score": 0},
        "whois": whois or [],
        "content": content or {"analysis_status": "AVAILABLE"},
        "attachment": attachment or {"risk_score": 0, "evidence": [], "analysis_status": "AVAILABLE"},
        "trust": trust or {},
        "ai": ai or {},
        "conflict": conflict or {},
        "reasoning": {},
    }


engine = ExplanationEngine()


# ---------------------------------------------------------------------------
# CRITICAL REGRESSION TEST — Must pass for every scenario
# ---------------------------------------------------------------------------

def _assert_decision_unchanged(original_decision, after_explanation):
    assert original_decision["risk_score"] == after_explanation["risk_score"], \
        f"risk_score was mutated: {original_decision['risk_score']} → {after_explanation['risk_score']}"
    assert original_decision["verdict"] == after_explanation["verdict"], \
        f"verdict was mutated: {original_decision['verdict']} → {after_explanation['verdict']}"
    assert original_decision["confidence"] == after_explanation["confidence"], \
        f"confidence was mutated: {original_decision['confidence']} → {after_explanation['confidence']}"


def run_and_assert_immutable(analysis, decision, parsed_email=None):
    """Run the engine and assert that decision was not modified."""
    original = copy.deepcopy(decision)
    result = engine.generate(parsed_email or {}, analysis, decision)
    _assert_decision_unchanged(original, decision)
    assert isinstance(result, dict), "Result must be a dict"
    assert "primary_reason" in result
    assert "final_reason" in result
    assert "groups" in result
    assert "agreement" in result
    return result


# ---------------------------------------------------------------------------
# SCENARIO 1: Legitimate account verification (Google with full auth)
# ---------------------------------------------------------------------------

def test_01_legitimate_account_verification():
    """SPF+DKIM+DMARC pass, google.com sender, verification language → VERIFIED LEGITIMATE"""
    decision = _decision("VERIFIED LEGITIMATE", 10, 92, "CLEAR_POSITIVE_EVIDENCE")
    analysis = _analysis(
        auth=_auth(),
        urls=[_url_item("accounts.google.com", 0)],
        whois=[_whois("google.com", 10000)],
        content={"verification_request": True, "analysis_status": "AVAILABLE"},
    )
    result = run_and_assert_immutable(analysis, decision)
    groups = result["groups"]
    positive_types = {e["type"] for e in groups["POSITIVE_EVIDENCE"]}
    assert "AUTHENTICATION_PASS" in positive_types
    assert result["agreement"]["negative_sources"] == 0 or \
           "BRAND_IMPERSONATION" not in {e["type"] for e in groups["NEGATIVE_EVIDENCE"]}
    assert "verification" in result["final_reason"].lower() or \
           "authentication" in result["final_reason"].lower()


# ---------------------------------------------------------------------------
# SCENARIO 2: Fake account verification (bad domain, credential request)
# ---------------------------------------------------------------------------

def test_02_fake_account_verification():
    """Auth fails, suspicious URL, credential request → PHISHING"""
    decision = _decision("PHISHING", 85, 90, "MALICIOUS_EVIDENCE")
    analysis = _analysis(
        auth=_auth("fail", "fail", "fail"),
        urls=[_url_item("g00gle-security.net", detections=3)],
        whois=[_whois("g00gle-security.net", 5)],
        content={"credential_request": True, "verification_request": True, "analysis_status": "AVAILABLE"},
    )
    result = run_and_assert_immutable(analysis, decision)
    groups = result["groups"]
    neg_types = {e["type"] for e in groups["NEGATIVE_EVIDENCE"]}
    assert "CREDENTIAL_HARVESTING" in neg_types
    assert "SUSPICIOUS_URL" in neg_types
    assert "NEWLY_REGISTERED_DOMAIN" in neg_types


# ---------------------------------------------------------------------------
# SCENARIO 3: Legitimate password reset
# ---------------------------------------------------------------------------

def test_03_legitimate_password_reset():
    """Full auth pass, canonical URL → LIKELY LEGITIMATE"""
    decision = _decision("LIKELY LEGITIMATE", 5, 80, "CLEAR_POSITIVE_EVIDENCE")
    analysis = _analysis(
        auth=_auth(),
        urls=[_url_item("accounts.microsoft.com", 0)],
        whois=[_whois("microsoft.com", 9000)],
        content={"verification_request": True, "analysis_status": "AVAILABLE"},
        trust={"trusted": True},
    )
    result = run_and_assert_immutable(analysis, decision)
    pos_types = {e["type"] for e in result["groups"]["POSITIVE_EVIDENCE"]}
    assert "AUTHENTICATION_PASS" in pos_types
    assert "TRUSTED_SENDER" in pos_types


# ---------------------------------------------------------------------------
# SCENARIO 4: Fake password reset
# ---------------------------------------------------------------------------

def test_04_fake_password_reset():
    """No auth, unrelated domain, credential harvesting → PHISHING"""
    decision = _decision("PHISHING", 90, 92, "MALICIOUS_EVIDENCE")
    analysis = _analysis(
        auth=_auth("fail", "fail", "none"),
        urls=[_url_item("microsoft-security-alert.ru", detections=5)],
        whois=[_whois("microsoft-security-alert.ru", 2)],
        content={"credential_request": True, "urgency": True, "analysis_status": "AVAILABLE"},
        ai={"brand_intelligence": [{"brand": "Microsoft", "impersonation_risk": True}]},
    )
    result = run_and_assert_immutable(analysis, decision)
    neg_types = {e["type"] for e in result["groups"]["NEGATIVE_EVIDENCE"]}
    assert "BRAND_IMPERSONATION" in neg_types
    assert "CREDENTIAL_HARVESTING" in neg_types
    assert "brand impersonation" in result["primary_reason"].lower()


# ---------------------------------------------------------------------------
# SCENARIO 5: Link-only legitimate
# ---------------------------------------------------------------------------

def test_05_link_only_legitimate():
    """Only a URL, no body, trusted domain → UNKNOWN (limited context)"""
    decision = _decision("UNKNOWN", 0, 25, "LIMITED_CONTEXT")
    analysis = _analysis(
        auth=_auth(),
        urls=[_url_item("github.com", 0)],
        ai={"context_quality": {"link_only": True, "limited_context": False}},
    )
    result = run_and_assert_immutable(analysis, decision)
    ctx_types = {e["type"] for e in result["groups"]["CONTEXT_LIMITATIONS"]}
    assert "LINK_ONLY" in ctx_types
    # Must not say SAFE or VERIFIED
    assert "safe" not in result["final_reason"].lower() or "not" in result["final_reason"].lower()


# ---------------------------------------------------------------------------
# SCENARIO 6: Link-only unknown
# ---------------------------------------------------------------------------

def test_06_link_only_unknown():
    """Only a suspicious URL, no context → UNKNOWN"""
    decision = _decision("UNKNOWN", 30, 20, "LINK_ONLY")
    analysis = _analysis(
        auth=_auth("none", "none", "none"),
        urls=[_url_item("random-domain-xyz.biz", detections=0)],
        ai={"context_quality": {"link_only": True, "limited_context": True}},
    )
    result = run_and_assert_immutable(analysis, decision)
    ctx_types = {e["type"] for e in result["groups"]["CONTEXT_LIMITATIONS"]}
    assert "LINK_ONLY" in ctx_types
    assert result["final_reason"], "final_reason must not be empty"


# ---------------------------------------------------------------------------
# SCENARIO 7: Brand impersonation
# ---------------------------------------------------------------------------

def test_07_brand_impersonation():
    """Brand reference to PayPal with unrelated domain → PHISHING"""
    decision = _decision("PHISHING", 88, 91, "BRAND_IMPERSONATION")
    analysis = _analysis(
        auth=_auth("fail", "fail", "fail"),
        urls=[_url_item("paypa1-secure.com", detections=2)],
        ai={"brand_intelligence": [{"brand": "PayPal", "impersonation_risk": True}]},
    )
    result = run_and_assert_immutable(analysis, decision)
    neg_types = {e["type"] for e in result["groups"]["NEGATIVE_EVIDENCE"]}
    brand_types = {e["type"] for e in result["groups"]["BRAND_FINDINGS"]}
    assert "BRAND_IMPERSONATION" in neg_types
    assert "BRAND_IMPERSONATION" in brand_types
    assert "brand impersonation" in result["primary_reason"].lower()


# ---------------------------------------------------------------------------
# SCENARIO 8: Homoglyph domain
# ---------------------------------------------------------------------------

def test_08_homoglyph_domain():
    """Domain with lookalike Unicode characters → PHISHING"""
    decision = _decision("PHISHING", 82, 88, "MALICIOUS_EVIDENCE")
    analysis = _analysis(
        auth=_auth("fail", "fail", "none"),
        urls=[_url_item("аpple.com", detections=0)],  # Cyrillic 'а'
        ai={"homoglyph": [{"domain": "аpple.com", "similar_to": "apple.com"}]},
    )
    result = run_and_assert_immutable(analysis, decision)
    neg_types = {e["type"] for e in result["groups"]["NEGATIVE_EVIDENCE"]}
    assert "HOMOGLYPH_DOMAIN" in neg_types
    assert "homoglyph" in result["primary_reason"].lower() or "visual" in result["primary_reason"].lower()


# ---------------------------------------------------------------------------
# SCENARIO 9: SPF pass + malicious URL
# ---------------------------------------------------------------------------

def test_09_spf_pass_malicious_url():
    """Authentication passes but URL is malicious → contradictions detected"""
    decision = _decision("HIGH RISK", 65, 75, "MALICIOUS_EVIDENCE")
    analysis = _analysis(
        auth=_auth("pass", "pass", "pass"),
        urls=[_url_item("steal-credentials-here.tk", detections=4)],
        conflict={"conflict_state": "CONFLICTING_EVIDENCE"},
    )
    result = run_and_assert_immutable(analysis, decision)
    contradictions = result["groups"]["CONTRADICTIONS"]
    assert len(contradictions) > 0
    # Authentication pass should be in positive evidence
    pos_types = {e["type"] for e in result["groups"]["POSITIVE_EVIDENCE"]}
    assert "AUTHENTICATION_PASS" in pos_types
    # URL should be in negative evidence
    neg_types = {e["type"] for e in result["groups"]["NEGATIVE_EVIDENCE"]}
    assert "SUSPICIOUS_URL" in neg_types


# ---------------------------------------------------------------------------
# SCENARIO 10: Trusted sender + malicious URL
# ---------------------------------------------------------------------------

def test_10_trusted_sender_malicious_url():
    """Trusted sender history but current message has malicious URL → SUSPICIOUS"""
    decision = _decision("SUSPICIOUS", 45, 60, "POSSIBLE_COMPROMISED_SENDER")
    analysis = _analysis(
        auth=_auth(),
        urls=[_url_item("evil-redirect.biz", detections=2)],
        trust={"trusted": True},
        conflict={"conflict_state": "CONFLICTING_EVIDENCE"},
    )
    result = run_and_assert_immutable(analysis, decision)
    pos_types = {e["type"] for e in result["groups"]["POSITIVE_EVIDENCE"]}
    neg_types = {e["type"] for e in result["groups"]["NEGATIVE_EVIDENCE"]}
    assert "TRUSTED_SENDER" in pos_types
    assert "SUSPICIOUS_URL" in neg_types
    # Must have some contradiction explanation
    contras = result["groups"]["CONTRADICTIONS"]
    assert len(contras) > 0


# ---------------------------------------------------------------------------
# SCENARIO 11: Strong legitimate evidence
# ---------------------------------------------------------------------------

def test_11_strong_legitimate_evidence():
    """All auth pass, established domain, trusted sender → VERIFIED LEGITIMATE"""
    decision = _decision("VERIFIED LEGITIMATE", 5, 95, "CLEAR_POSITIVE_EVIDENCE")
    analysis = _analysis(
        auth=_auth(),
        urls=[_url_item("amazon.com", 0)],
        whois=[_whois("amazon.com", 8000)],
        trust={"trusted": True},
        content={"analysis_status": "AVAILABLE"},
    )
    result = run_and_assert_immutable(analysis, decision)
    pos_types = {e["type"] for e in result["groups"]["POSITIVE_EVIDENCE"]}
    assert "AUTHENTICATION_PASS" in pos_types
    assert "TRUSTED_SENDER" in pos_types
    assert "ESTABLISHED_DOMAIN" in pos_types
    assert result["agreement"]["negative_sources"] == 0


# ---------------------------------------------------------------------------
# SCENARIO 12: Insufficient evidence
# ---------------------------------------------------------------------------

def test_12_insufficient_evidence():
    """Empty analysis, no signals → UNKNOWN"""
    decision = _decision("UNKNOWN", 0, 30, "INSUFFICIENT_EVIDENCE")
    analysis = _analysis(
        auth={"analysis_status": "UNAVAILABLE"},
        content={"analysis_status": "UNAVAILABLE"},
        attachment={"risk_score": 0, "evidence": [], "analysis_status": "UNAVAILABLE"},
    )
    result = run_and_assert_immutable(analysis, decision)
    ctx_types = {e["type"] for e in result["groups"]["CONTEXT_LIMITATIONS"]}
    assert "INSUFFICIENT_EVIDENCE" in ctx_types
    assert result["final_reason"]


# ---------------------------------------------------------------------------
# SCENARIO 13: Conflicting evidence
# ---------------------------------------------------------------------------

def test_13_conflicting_evidence():
    """Auth pass + suspicious URL + conflict engine triggered"""
    decision = _decision("UNKNOWN", 30, 45, "CONFLICTING_EVIDENCE")
    analysis = _analysis(
        auth=_auth("pass", "pass", "pass"),
        urls=[_url_item("suspicious-redirect.ml", detections=1)],
        conflict={"conflict_state": "CONFLICTING_EVIDENCE"},
    )
    result = run_and_assert_immutable(analysis, decision)
    assert len(result["groups"]["CONTRADICTIONS"]) > 0
    assert result["agreement"]["contradictory_sources"] >= 1


# ---------------------------------------------------------------------------
# SCENARIO 14: Analyzer unavailable
# ---------------------------------------------------------------------------

def test_14_analyzer_unavailable():
    """Auth analyzer returns UNAVAILABLE → graceful handling"""
    decision = _decision("UNKNOWN", 0, 30, "INSUFFICIENT_EVIDENCE")
    analysis = _analysis(
        auth={"analysis_status": "UNAVAILABLE"},
        content={"analysis_status": "UNAVAILABLE"},
    )
    result = run_and_assert_immutable(analysis, decision)
    ctx_types = {e["type"] for e in result["groups"]["CONTEXT_LIMITATIONS"]}
    assert "AUTHENTICATION_UNAVAILABLE" in ctx_types


# ---------------------------------------------------------------------------
# SCENARIO 15: Compromised trusted sender
# ---------------------------------------------------------------------------

def test_15_compromised_trusted_sender():
    """Trusted sender history + current malicious URL → SUSPICIOUS"""
    decision = _decision("SUSPICIOUS", 42, 65, "TRUST_HISTORY_CONFLICT")
    analysis = _analysis(
        auth=_auth("pass", "fail", "none"),
        urls=[_url_item("malware-payload.cc", detections=3)],
        trust={"trusted": True},
        conflict={"conflict_state": "CONFLICTING_EVIDENCE"},
    )
    result = run_and_assert_immutable(analysis, decision)
    pos_types = {e["type"] for e in result["groups"]["POSITIVE_EVIDENCE"]}
    neg_types = {e["type"] for e in result["groups"]["NEGATIVE_EVIDENCE"]}
    assert "TRUSTED_SENDER" in pos_types
    assert "SUSPICIOUS_URL" in neg_types
    contras = result["groups"]["CONTRADICTIONS"]
    contra_types = {e["type"] for e in contras}
    assert "TRUST_HISTORY_CONFLICT" in contra_types


# ---------------------------------------------------------------------------
# SCENARIO 16: Campaign phishing
# ---------------------------------------------------------------------------

def test_16_campaign_phishing():
    """Campaign infrastructure match → phishing"""
    decision = _decision("PHISHING", 80, 88, "MALICIOUS_EVIDENCE")
    analysis = _analysis(
        auth=_auth("fail", "fail", "none"),
        urls=[_url_item("phish-campaign-123.net", detections=2)],
        ai={
            "campaign": [
                {"campaign_id": "CAMP-2025-001", "matched_messages": 12}
            ]
        },
    )
    result = run_and_assert_immutable(analysis, decision)
    beh_types = {e["type"] for e in result["groups"]["BEHAVIORAL_FINDINGS"]}
    assert "CAMPAIGN_MATCH" in beh_types
    assert "campaign" in result["primary_reason"].lower()


# ---------------------------------------------------------------------------
# SCENARIO 17: Multiple malicious indicators
# ---------------------------------------------------------------------------

def test_17_multiple_malicious_indicators():
    """Brand impersonation + credential harvesting + homoglyph + suspicious URL"""
    decision = _decision("PHISHING", 95, 95, "MALICIOUS_EVIDENCE")
    analysis = _analysis(
        auth=_auth("fail", "fail", "fail"),
        urls=[_url_item("paypa1.verify-now.com", detections=5)],
        whois=[_whois("verify-now.com", 3)],
        content={"credential_request": True, "urgency": True, "analysis_status": "AVAILABLE"},
        ai={
            "brand_intelligence": [{"brand": "PayPal", "impersonation_risk": True}],
            "homoglyph": [{"domain": "paypa1.verify-now.com", "similar_to": "paypal.com"}],
        },
    )
    result = run_and_assert_immutable(analysis, decision)
    neg_types = {e["type"] for e in result["groups"]["NEGATIVE_EVIDENCE"]}
    assert "BRAND_IMPERSONATION" in neg_types
    assert "CREDENTIAL_HARVESTING" in neg_types
    assert "HOMOGLYPH_DOMAIN" in neg_types
    assert result["agreement"]["negative_sources"] > 2


# ---------------------------------------------------------------------------
# SCENARIO 18: Multiple legitimate indicators
# ---------------------------------------------------------------------------

def test_18_multiple_legitimate_indicators():
    """All auth pass + trusted sender + established domain + no malicious URLs"""
    decision = _decision("VERIFIED LEGITIMATE", 3, 96, "CLEAR_POSITIVE_EVIDENCE")
    analysis = _analysis(
        auth=_auth("pass", "pass", "pass"),
        urls=[_url_item("google.com", 0), _url_item("googleapis.com", 0)],
        whois=[_whois("google.com", 9000), _whois("googleapis.com", 9000)],
        trust={"trusted": True},
    )
    result = run_and_assert_immutable(analysis, decision)
    pos_types = {e["type"] for e in result["groups"]["POSITIVE_EVIDENCE"]}
    assert "AUTHENTICATION_PASS" in pos_types
    assert "TRUSTED_SENDER" in pos_types
    assert result["agreement"]["negative_sources"] == 0


# ---------------------------------------------------------------------------
# SCENARIO 19: Empty email
# ---------------------------------------------------------------------------

def test_19_empty_email():
    """Empty email with no auth, content, URLs → UNKNOWN"""
    decision = _decision("UNKNOWN", 0, 20, "INSUFFICIENT_EVIDENCE")
    analysis = _analysis(
        auth={"analysis_status": "UNAVAILABLE"},
        urls=[],
        content={"analysis_status": "UNAVAILABLE"},
        attachment={"risk_score": 0, "evidence": [], "analysis_status": "UNAVAILABLE"},
    )
    result = run_and_assert_immutable(analysis, decision, parsed_email={})
    # Should not crash, should return a valid structure
    assert isinstance(result, dict)
    assert "groups" in result
    assert "primary_reason" in result
    assert "final_reason" in result


# ---------------------------------------------------------------------------
# SCENARIO 20: Malformed email / corrupted analysis
# ---------------------------------------------------------------------------

def test_20_malformed_email():
    """Corrupted/None analysis fields — engine must not crash"""
    decision = _decision("UNKNOWN", 0, 30, "INSUFFICIENT_EVIDENCE")
    analysis = {
        "authentication": None,
        "url": {"analysis": None},
        "whois": None,
        "content": None,
        "attachment": None,
        "trust": None,
        "ai": None,
        "conflict": None,
        "reasoning": None,
    }
    result = run_and_assert_immutable(analysis, decision, parsed_email=None)
    assert isinstance(result, dict)
    assert "groups" in result


# ---------------------------------------------------------------------------
# ADDITIONAL: Verify explanation output never contains sensitive fields
# ---------------------------------------------------------------------------

def test_no_oauth_tokens_in_explanation():
    """Explanation output must not expose OAuth tokens, session IDs, or credentials"""
    decision = _decision("PHISHING", 80, 88)
    analysis = _analysis(
        auth=_auth("fail", "fail", "fail"),
        ai={"brand_intelligence": [{"brand": "Google", "impersonation_risk": True}]},
    )
    result = engine.generate(
        {"oauth_token": "FAKE_SECRET_TOKEN", "session_id": "SESSION_XYZ"},
        analysis,
        decision,
    )
    result_str = str(result)
    assert "FAKE_SECRET_TOKEN" not in result_str
    assert "SESSION_XYZ" not in result_str


# ---------------------------------------------------------------------------
# ADDITIONAL: Test confidence explanation coverage
# ---------------------------------------------------------------------------

def test_high_confidence_explanation():
    decision = _decision("PHISHING", 90, 90)
    analysis = _analysis(
        auth=_auth("fail", "fail", "fail"),
        urls=[_url_item("phish.tk", 3)],
        ai={"brand_intelligence": [{"brand": "Apple", "impersonation_risk": True}]},
    )
    result = engine.generate({}, analysis, decision)
    assert result["confidence_explanation"]
    assert "90" in result["confidence_explanation"]


def test_low_confidence_explanation():
    decision = _decision("UNKNOWN", 0, 25, "INSUFFICIENT_EVIDENCE")
    analysis = _analysis(
        auth={"analysis_status": "UNAVAILABLE"},
    )
    result = engine.generate({}, analysis, decision)
    assert result["confidence_explanation"]
    assert "25" in result["confidence_explanation"]


# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
