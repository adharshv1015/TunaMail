import pytest

from src.engines.are import AnalyticalReasoningEngine
from src.engines.decision_fusion_engine import DecisionFusionEngine
from src.engines.evidence_conflict_engine import EvidenceConflictEngine
from src.engines.explanation_engine import ExplanationEngine
from src.ai.orchestrator import analyze_email_with_ai
from src.ai.inference import get_ai_engine

def set_model_prediction(predicted_class="LEGITIMATE", prob=0.95):
    engine = get_ai_engine()
    engine.model.predict = lambda t, f, v: (predicted_class, {predicted_class: prob, "UNKNOWN": 0.05})

def mock_parsed_email(body="Test body", sender="test@example.com", headers=None):
    if headers is None:
        headers = {"From": sender, "Return-Path": sender}
    return {
        "body": body,
        "from": sender,
        "headers": headers,
        "attachments": []
    }

def mock_existing_analysis(auth_pass=True, urls=None, content_risk=0):
    if urls is None:
        urls = []
    
    return {
        "authentication": {
            "spf": "pass" if auth_pass else "fail",
            "dkim": "pass" if auth_pass else "fail",
            "dmarc": "pass" if auth_pass else "fail"
        },
        "url": {
            "urls": [u.get("url", "") for u in urls],
            "analysis": urls,
            "limited_context": False
        },
        "content": {
            "risk_score": content_risk,
            "evidence": [] if content_risk == 0 else ["Suspicious wording detected"],
            "urgency": False,
            "credential_request": False,
            "financial_request": False,
            "threat_language": False,
            "impersonation": False
        },
        "whois": [],
        "attachment": {"risk_score": 0, "evidence": []},
        "trust": {"trust_score": 100 if auth_pass else 0, "evidence": []}
    }

def create_url_analysis(domain, brand_rel="UNKNOWN", align="aligned", is_private=False):
    return {
        "url": f"https://{domain}/path",
        "domain": domain,
        "brand_relationship": brand_rel,
        "brand_impersonation": brand_rel in ["IMPERSONATION", "LOOKALIKE"],
        "email_alignment": align,
        "alignment": align,
        "tls": {"certificate_valid": True},
        "dns": {"private_ip_detected": is_private}
    }

def run_pipeline(email, analysis):
    are = AnalyticalReasoningEngine()
    decision_engine = DecisionFusionEngine()
    conflict_engine = EvidenceConflictEngine()
    explanation_engine = ExplanationEngine()
    
    ai_analysis = analyze_email_with_ai(email, analysis)
    
    are_result = are.evaluate(
        analysis["authentication"],
        analysis["url"],
        analysis["whois"],
        analysis["content"],
        analysis["attachment"],
        analysis["trust"],
        ai_analysis=ai_analysis
    )
    
    conflict_result = conflict_engine.evaluate(
        email,
        analysis["authentication"],
        analysis["url"],
        analysis["whois"],
        analysis["content"],
        analysis["attachment"],
        analysis["trust"],
        ai_analysis
    )
    
    decision_result = decision_engine.evaluate(are_result, conflict_result)
    
    explanation = explanation_engine.evaluate(
        verdict=decision_result["verdict"],
        confidence=decision_result["confidence"],
        risk_score=decision_result["risk_score"],
        conflict_state=conflict_result["conflict_state"],
        structured_evidence=conflict_result["structured_evidence"]
    )
    
    return decision_result, conflict_result, explanation

def test_1_legitimate_verification():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="Please verify your account here https://paypal.com/verify", sender="security@paypal.com")
    urls = [create_url_analysis("paypal.com", brand_rel="OFFICIAL", align="aligned")]
    analysis = mock_existing_analysis(auth_pass=True, urls=urls)
    
    decision, conflict, exp = run_pipeline(email, analysis)
    assert decision["verdict"] in ["VERIFIED LEGITIMATE", "LIKELY LEGITIMATE"]
    assert conflict["conflict_state"] == "CONSISTENT_LEGITIMATE"

def test_2_keyword_trap():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="URGENT ACCOUNT SECURITY. We wanted to let you know about a security update.", sender="trusted@bank.com")
    analysis = mock_existing_analysis(auth_pass=True, content_risk=0)
    
    decision, conflict, exp = run_pipeline(email, analysis)
    assert decision["verdict"] != "PHISHING"
    assert decision["verdict"] != "HIGH RISK"

def test_3_link_only_unknown():
    set_model_prediction("UNKNOWN")
    email = mock_parsed_email(body="https://unknown-domain.example", sender="random@random.com")
    urls = [create_url_analysis("unknown-domain.example", brand_rel="UNKNOWN", align="unknown")]
    analysis = mock_existing_analysis(auth_pass=False, urls=urls)
    
    decision, conflict, exp = run_pipeline(email, analysis)
    assert decision["verdict"] in ["UNKNOWN", "SUSPICIOUS"]
    assert decision["verdict"] != "SAFE"
    assert conflict["conflict_state"] in ["LIMITED_CONTEXT", "CONFLICTING_EVIDENCE"]

def test_4_brand_impersonation():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="Update paypal https://paypal-security.example.com", sender="fake@example.com")
    urls = [create_url_analysis("paypal-security.example.com", brand_rel="IMPERSONATION", align="misaligned")]
    analysis = mock_existing_analysis(auth_pass=True, urls=urls)
    
    decision, conflict, exp = run_pipeline(email, analysis)
    assert decision["verdict"] in ["SUSPICIOUS", "PHISHING", "HIGH RISK"]
    assert conflict["conflict_state"] == "CONFLICTING_EVIDENCE"

def test_5_authentication_contradiction():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="Login https://paypal-security.example.com", sender="good-auth@example.com")
    urls = [create_url_analysis("paypal-security.example.com", brand_rel="IMPERSONATION", align="misaligned")]
    # SPF/DKIM passes, but URL impersonates brand
    analysis = mock_existing_analysis(auth_pass=True, urls=urls)
    
    decision, conflict, exp = run_pipeline(email, analysis)
    assert conflict["conflict_state"] == "CONFLICTING_EVIDENCE"
    assert decision["confidence"] <= 50

def test_6_empty_email():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="", sender=None)
    analysis = mock_existing_analysis(auth_pass=False)
    
    decision, conflict, exp = run_pipeline(email, analysis)
    assert decision["verdict"] in ["UNKNOWN", "SUSPICIOUS"]
    assert conflict["conflict_state"] == "INSUFFICIENT_EVIDENCE"

def test_7_internal_url_ssrf():
    from src.analyzers.url_analyzer import URLAnalyzer
    analyzer = URLAnalyzer()
    res = analyzer.analyze("http://127.0.0.1/admin")
    assert len(res["analysis"]) > 0
    assert res["analysis"][0]["dns"]["private_ip_detected"] is True

def test_8_cloud_metadata_ssrf():
    from src.analyzers.url_analyzer import URLAnalyzer
    analyzer = URLAnalyzer()
    res = analyzer.analyze("http://169.254.169.254/latest/meta-data/")
    assert len(res["analysis"]) > 0
    assert res["analysis"][0]["dns"]["private_ip_detected"] is True
