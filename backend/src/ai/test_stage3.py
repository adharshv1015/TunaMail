import pytest
from src.ai.orchestrator import analyze_email_with_ai

def mock_parsed_email(body="Test body", sender="test@example.com", headers=None, attachments=None):
    if headers is None:
        headers = {"From": sender, "Return-Path": sender}
    return {
        "body": body,
        "from": sender,
        "headers": headers,
        "attachments": attachments or []
    }

def mock_existing_analysis(auth_pass=True, urls=None, content=None):
    if urls is None:
        urls = []
    if content is None:
        content = {
            "urgency": False,
            "credential_request": False,
            "financial_request": False,
            "threat_language": False,
            "impersonation": False
        }
    
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
        "content": content
    }

def create_url_analysis(domain, brand_rel="UNKNOWN", tls_valid=True, align="aligned"):
    return {
        "url": f"https://{domain}/path",
        "domain": domain,
        "brand_relationship": brand_rel,
        "email_alignment": align,
        "tls": {"certificate_valid": tls_valid},
        "dns": {"private_ip_detected": False}
    }

from src.ai.inference import get_ai_engine

def set_model_prediction(predicted_class="LEGITIMATE", prob=0.95):
    engine = get_ai_engine()
    # Mock the predict function
    engine.model.predict = lambda t, f, v: (predicted_class, {predicted_class: prob, "UNKNOWN": 0.05})

def test_1_legitimate_account_verification():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="Please verify your account here https://paypal.com/verify", sender="security@paypal.com")
    urls = [create_url_analysis("paypal.com", brand_rel="OFFICIAL", align="aligned")]
    analysis = mock_existing_analysis(auth_pass=True, urls=urls)
    result = analyze_email_with_ai(email, analysis)
    assert result["recommended_classification"] == "VERIFIED_LEGITIMATE"
    assert result["reasoning_state"] == "SUFFICIENT_EVIDENCE"

def test_2_legitimate_password_reset():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="Password reset for your account https://github.com/reset", sender="noreply@github.com")
    urls = [create_url_analysis("github.com", brand_rel="OFFICIAL", align="aligned")]
    analysis = mock_existing_analysis(auth_pass=True, urls=urls)
    result = analyze_email_with_ai(email, analysis)
    assert result["recommended_classification"] == "VERIFIED_LEGITIMATE"

def test_3_legitimate_security_alert():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="Security alert: new sign in. https://google.com/alert", sender="alerts@google.com")
    urls = [create_url_analysis("google.com", brand_rel="OFFICIAL", align="aligned")]
    analysis = mock_existing_analysis(auth_pass=True, urls=urls)
    result = analyze_email_with_ai(email, analysis)
    assert result["recommended_classification"] in ["VERIFIED_LEGITIMATE", "LIKELY_LEGITIMATE"]

def test_4_link_only_email():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="https://random-domain.com", sender="test@example.com")
    urls = [create_url_analysis("random-domain.com", brand_rel="UNKNOWN", align="unknown")]
    analysis = mock_existing_analysis(auth_pass=False, urls=urls)
    result = analyze_email_with_ai(email, analysis)
    assert result["reasoning_state"] == "CONFLICTING_EVIDENCE"
    assert result["recommended_classification"] == "SUSPICIOUS"

def test_5_empty_email():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="", sender="test@example.com")
    analysis = mock_existing_analysis(auth_pass=False)
    result = analyze_email_with_ai(email, analysis)
    assert result["reasoning_state"] == "INSUFFICIENT_EVIDENCE"
    assert result["recommended_classification"] == "UNKNOWN"
    assert result["confidence"] == 0.0

def test_6_unknown_domain():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="Check out this new startup https://unknown-startup.io", sender="friend@example.com")
    urls = [create_url_analysis("unknown-startup.io", brand_rel="UNKNOWN", align="misaligned")]
    analysis = mock_existing_analysis(auth_pass=True, urls=urls)
    result = analyze_email_with_ai(email, analysis)
    assert result["reasoning_state"] == "CONFLICTING_EVIDENCE"
    assert result["recommended_classification"] == "SUSPICIOUS"

def test_7_brand_impersonation():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="Update paypal https://paypal-security.com", sender="fake@example.com")
    urls = [create_url_analysis("paypal-security.com", brand_rel="IMPERSONATION", align="misaligned")]
    analysis = mock_existing_analysis(auth_pass=True, urls=urls)
    result = analyze_email_with_ai(email, analysis)
    assert result["reasoning_state"] == "CONFLICTING_EVIDENCE"
    assert result["recommended_classification"] == "PHISHING"

def test_8_lookalike_domain():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="Update https://paypa1.com", sender="fake@example.com")
    urls = [create_url_analysis("paypa1.com", brand_rel="LOOKALIKE", align="misaligned")]
    analysis = mock_existing_analysis(auth_pass=False, urls=urls)
    result = analyze_email_with_ai(email, analysis)
    assert result["recommended_classification"] in ["SUSPICIOUS", "PHISHING"]

def test_9_credential_phishing():
    set_model_prediction("PHISHING")
    email = mock_parsed_email(body="Confirm your login password", sender="bad@evil.com")
    analysis = mock_existing_analysis(auth_pass=False, content={"credential_request": True})
    result = analyze_email_with_ai(email, analysis)
    assert "Email contains a credential request." in result["signals"]

def test_10_financial_phishing():
    set_model_prediction("PHISHING")
    email = mock_parsed_email(body="Send payment invoice immediately", sender="bad@evil.com")
    analysis = mock_existing_analysis(auth_pass=False, content={"financial_request": True})
    result = analyze_email_with_ai(email, analysis)

def test_11_urgent_phishing():
    set_model_prediction("PHISHING")
    email = mock_parsed_email(body="Your account will be suspended urgently", sender="bad@evil.com")
    analysis = mock_existing_analysis(auth_pass=False, content={"urgency": True})
    result = analyze_email_with_ai(email, analysis)
    assert "Email contains urgent language." in result["signals"]

def test_12_spf_pass_malicious_url():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="Look https://evil.com", sender="good@good.com")
    urls = [create_url_analysis("evil.com", brand_rel="UNKNOWN", align="misaligned")]
    analysis = mock_existing_analysis(auth_pass=True, urls=urls)
    result = analyze_email_with_ai(email, analysis)
    assert result["reasoning_state"] == "CONFLICTING_EVIDENCE"

def test_13_spf_fail_official_url():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="https://paypal.com", sender="spoof@paypal.com")
    urls = [create_url_analysis("paypal.com", brand_rel="OFFICIAL", align="aligned")]
    analysis = mock_existing_analysis(auth_pass=False, urls=urls)
    result = analyze_email_with_ai(email, analysis)
    assert result["reasoning_state"] == "CONFLICTING_EVIDENCE"

def test_14_dkim_pass_unrelated_url():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="https://random.com", sender="good@good.com")
    urls = [create_url_analysis("random.com", brand_rel="UNKNOWN", align="misaligned")]
    analysis = mock_existing_analysis(auth_pass=True, urls=urls)
    result = analyze_email_with_ai(email, analysis)
    assert result["reasoning_state"] == "CONFLICTING_EVIDENCE"

def test_15_multiple_urls():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="https://google.com and https://evil.com", sender="good@good.com")
    urls = [
        create_url_analysis("google.com", brand_rel="OFFICIAL", align="aligned"),
        create_url_analysis("evil.com", brand_rel="UNKNOWN", align="misaligned")
    ]
    analysis = mock_existing_analysis(auth_pass=True, urls=urls)
    result = analyze_email_with_ai(email, analysis)
    assert result["reasoning_state"] == "LINK_ONLY"

def test_16_redirect_url():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="https://bit.ly/123", sender="good@good.com")
    urls = [create_url_analysis("bit.ly", brand_rel="UNKNOWN", align="misaligned")]
    analysis = mock_existing_analysis(auth_pass=True, urls=urls)
    result = analyze_email_with_ai(email, analysis)
    assert result["reasoning_state"] == "CONFLICTING_EVIDENCE"

def test_17_https_valid():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="https://paypal.com", sender="paypal@paypal.com")
    urls = [create_url_analysis("paypal.com", brand_rel="OFFICIAL", align="aligned", tls_valid=True)]
    analysis = mock_existing_analysis(auth_pass=True, urls=urls)
    result = analyze_email_with_ai(email, analysis)
    assert "TLS certificate is valid for paypal.com." in result["signals"]

def test_18_invalid_tls():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="https://paypal.com", sender="paypal@paypal.com")
    urls = [create_url_analysis("paypal.com", brand_rel="OFFICIAL", align="aligned", tls_valid=False)]
    analysis = mock_existing_analysis(auth_pass=True, urls=urls)
    result = analyze_email_with_ai(email, analysis)
    assert result["reasoning_state"] == "CONFLICTING_EVIDENCE"

def test_19_no_url():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="Hello, how are you doing today? Just wanted to catch up.", sender="good@good.com")
    analysis = mock_existing_analysis(auth_pass=True, urls=[])
    result = analyze_email_with_ai(email, analysis)
    assert result["context"]["limited_context"] == False

def test_20_attachment_suspicious_content():
    set_model_prediction("SUSPICIOUS")
    email = mock_parsed_email(body="See attached for your invoice", sender="bad@evil.com", attachments=[{"filename": "invoice.exe"}])
    analysis = mock_existing_analysis(auth_pass=False, content={"financial_request": True})
    result = analyze_email_with_ai(email, analysis)
    assert result["recommended_classification"] in ["UNKNOWN", "SUSPICIOUS", "PHISHING"]

def test_21_legitimate_attachment():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="Here is the document.", sender="good@good.com", attachments=[{"filename": "doc.pdf"}])
    analysis = mock_existing_analysis(auth_pass=True, urls=[])
    result = analyze_email_with_ai(email, analysis)
    assert result["recommended_classification"] in ["LIKELY_LEGITIMATE", "VERIFIED_LEGITIMATE", "UNKNOWN"]

def test_22_conflicting_evidence():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="Update your account https://evil.com", sender="good@good.com")
    urls = [create_url_analysis("evil.com", brand_rel="UNKNOWN", align="misaligned")]
    analysis = mock_existing_analysis(auth_pass=True, urls=urls)
    result = analyze_email_with_ai(email, analysis)
    assert result["reasoning_state"] == "CONFLICTING_EVIDENCE"

def test_23_missing_from_header():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="Hello", sender="")
    analysis = mock_existing_analysis(auth_pass=False)
    result = analyze_email_with_ai(email, analysis)

def test_24_missing_filename():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="Hello", sender="good@good.com", attachments=[{"size": 100}])
    analysis = mock_existing_analysis(auth_pass=True)
    result = analyze_email_with_ai(email, analysis)

def test_25_malformed_url():
    set_model_prediction("LEGITIMATE")
    email = mock_parsed_email(body="Check this htttp://malformed", sender="good@good.com")
    analysis = mock_existing_analysis(auth_pass=True)
    result = analyze_email_with_ai(email, analysis)
