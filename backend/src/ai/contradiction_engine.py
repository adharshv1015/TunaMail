class ContradictionEngine:
    """
    Detects contradictory evidence to prevent the system from blindly
    trusting isolated signals.
    """

    def analyze(
        self,
        authentication: dict,
        url_analysis: list,
        content_analysis: dict,
        attachment_analysis: dict,
        trust_analysis: dict,
        brand_evidence: list,
        reputation_profile: dict = None
    ) -> dict:
        
        has_spf_pass = authentication.get("spf") == "pass"
        has_dkim_pass = authentication.get("dkim") == "pass"
        has_dmarc_pass = authentication.get("dmarc") == "pass"
        has_strong_auth = has_spf_pass and has_dkim_pass and has_dmarc_pass
        
        has_trusted_sender = trust_analysis.get("trust_score", 0) >= 20

        # Extract URL signals
        has_cred_harvesting_url = False
        has_suspicious_redirect = False
        looks_official_url = False
        
        for u in url_analysis:
            threats = u.get("threat_intelligence", {}).get("detections", 0)
            if threats > 0 or u.get("punycode"):
                has_cred_harvesting_url = True
            
            if u.get("redirects", {}).get("external_domain_change"):
                has_suspicious_redirect = True

            # Basic heuristic for "official-looking" (if it hasn't been flagged as fake)
            # This is simplified; ideally we check brand_evidence
            if u.get("tls", {}).get("certificate_valid") and not threats:
                looks_official_url = True
                
        has_brand_impersonation = any(ev.get("impersonation_risk") for ev in brand_evidence)
        has_credential_req = content_analysis.get("credential_request", False)
        
        has_suspicious_attachment = attachment_analysis.get("risk_score", 0) >= 40

        # Evaluate Cases

        # CASE 1 & CASE 2: Strong positive sender info BUT highly malicious content/URL
        if (has_strong_auth or has_trusted_sender) and (has_cred_harvesting_url or has_brand_impersonation):
            return {
                "contradiction_detected": True,
                "state": "CONFLICTING_EVIDENCE",
                "explanation": "Strong sender authentication or trusted sender paired with malicious URL or brand impersonation."
            }
            
        # CASE 3: Official-looking domain BUT credential request + suspicious redirect
        if looks_official_url and has_credential_req and has_suspicious_redirect:
            return {
                "contradiction_detected": True,
                "state": "CONFLICTING_EVIDENCE",
                "explanation": "Official-looking domain but contains a credential request with suspicious external redirects."
            }
            
        # CASE 5: Legitimate domain BUT unrelated suspicious attachment
        if (has_strong_auth or looks_official_url) and has_suspicious_attachment:
            return {
                "contradiction_detected": True,
                "state": "CONFLICTING_EVIDENCE",
                "explanation": "Legitimate sender or domain paired with a suspicious attachment."
            }
            
        # CASE 6: TRUST HISTORY CONFLICT (Compromised Trusted Sender)
        if reputation_profile and reputation_profile.get("reputation") in ["TRUSTED", "ESTABLISHED"]:
            if has_cred_harvesting_url or has_brand_impersonation or has_suspicious_redirect:
                return {
                    "contradiction_detected": True,
                    "state": "TRUST_HISTORY_CONFLICT",
                    "explanation": "Historical sender reputation is trusted, but the current email contains highly suspicious or phishing indicators."
                }
            
        # CASE 4: No authentication evidence BUT URL appears legitimate
        # (Be careful here, as marketing emails often lack DMARC)
        if not has_spf_pass and not has_dkim_pass and looks_official_url:
            return {
                "contradiction_detected": True,
                "state": "INSUFFICIENT_EVIDENCE",
                "explanation": "URL appears legitimate, but there is no domain authentication to verify the sender."
            }
            
        return {
            "contradiction_detected": False,
            "state": None,
            "explanation": None
        }
