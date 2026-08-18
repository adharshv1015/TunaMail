import logging

logger = logging.getLogger(__name__)

class SanityValidator:
    """
    Validates the AI's recommended classification against deterministic facts 
    before it leaves the AI layer.
    """

    def __init__(self):
        pass

    def validate(self, ai_result: dict, auth_analysis: dict, url_analysis: dict, brand_evidence: list, threat_evidence: list, risk_score: int) -> dict:
        """
        Applies logical consistency rules to the AI's prediction.
        Modifies ai_result in place or returns a modified copy.
        """
        rec_class = ai_result.get("recommended_classification", "UNKNOWN")
        reasoning_state = ai_result.get("reasoning_state", "SUFFICIENT_EVIDENCE")
        
        # Determine deterministic flags
        spf_pass = auth_analysis.get("spf") == "pass"
        dkim_pass = auth_analysis.get("dkim") in ["pass", "present_unverified"]
        dmarc_pass = auth_analysis.get("dmarc") == "pass"
        full_auth_pass = spf_pass and dkim_pass and dmarc_pass
        
        # Check for meaningful negative evidence
        has_credential_form = False
        has_malicious_url = False
        
        urls = url_analysis.get("analysis", []) if isinstance(url_analysis, dict) else url_analysis
        for u in urls:
            if u.get("threat_intelligence", {}).get("detections", 0) > 0:
                has_malicious_url = True
            page_intel = u.get("page_analysis", {})
            if page_intel and page_intel.get("forms", {}).get("password_fields", 0) > 0:
                has_credential_form = True
                
        has_brand_impersonation = any(b.get("impersonation_risk", False) for b in brand_evidence)
        
        has_high_negative_evidence = has_credential_form or has_malicious_url or has_brand_impersonation or risk_score >= 60
        
        # -------------------------------------------------------------
        # Rule D: Ignored Malice (Highest Priority)
        # AI says SAFE, but deterministic engine found critical threats
        # -------------------------------------------------------------
        if rec_class in ["LEGITIMATE", "LIKELY_LEGITIMATE", "SAFE", "VERIFIED_LEGITIMATE"]:
            if has_credential_form or has_brand_impersonation or has_malicious_url:
                ai_result["recommended_classification"] = "UNKNOWN"
                ai_result["reasoning_state"] = "CONFLICTING_EVIDENCE"
                ai_result["confidence"] = 0.0
                ai_result["signals"].append("Sanity Validator (Rule D): AI ignored critical deterministic threat evidence.")
                ai_result["negative_evidence"].append("Sanity Validator (Rule D): AI ignored critical deterministic threat evidence.")
                return ai_result

        # -------------------------------------------------------------
        # Rule A: Auth Contradiction
        # AI says PHISHING, but all authentication passes
        # -------------------------------------------------------------
        if rec_class == "PHISHING" and full_auth_pass:
            if reasoning_state != "CONFLICTING_EVIDENCE":
                ai_result["reasoning_state"] = "CONFLICTING_EVIDENCE"
                ai_result["signals"].append("Sanity Validator (Rule A): Phishing prediction contradicts perfect sender authentication.")
                ai_result["positive_evidence"].append("Sanity Validator (Rule A): Perfect sender authentication conflicts with phishing prediction.")
                # We do NOT automatically downgrade to SUSPICIOUS. 
                # Current bad features can still justify Phishing.
                
        # -------------------------------------------------------------
        # Rule B: Unsupported Phishing
        # AI says PHISHING, but risk is low and no critical negative evidence
        # -------------------------------------------------------------
        if rec_class == "PHISHING" and risk_score < 30 and not has_high_negative_evidence:
            ai_result["recommended_classification"] = "SUSPICIOUS"
            ai_result["reasoning_state"] = "INSUFFICIENT_EVIDENCE"
            ai_result["confidence"] = min(ai_result.get("confidence", 50.0), 50.0)
            ai_result["signals"].append("Sanity Validator (Rule B): Phishing prediction lacks deterministic support. Downgraded to Suspicious.")
            ai_result["positive_evidence"].append("Sanity Validator (Rule B): Lack of deterministic threat evidence.")
            
        # -------------------------------------------------------------
        # Rule C: Unsupported Suspicion
        # AI says SUSPICIOUS, but strong positive evidence and NO bad evidence
        # -------------------------------------------------------------
        if rec_class == "SUSPICIOUS" and full_auth_pass and not has_high_negative_evidence:
            # Check if there are no existing unresolved contradictions
            if reasoning_state not in ["CONFLICTING_EVIDENCE"]:
                ai_result["recommended_classification"] = "UNKNOWN"
                ai_result["reasoning_state"] = "INSUFFICIENT_EVIDENCE"
                ai_result["confidence"] = min(ai_result.get("confidence", 50.0), 40.0)
                ai_result["signals"].append("Sanity Validator (Rule C): Suspicious prediction overridden by strong positive evidence and lack of threats.")
                ai_result["positive_evidence"].append("Sanity Validator (Rule C): Strong positive evidence supports safety.")

        return ai_result
