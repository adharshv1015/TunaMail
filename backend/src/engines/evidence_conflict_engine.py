class EvidenceConflictEngine:
    def evaluate(
        self,
        parsed_email: dict,
        auth_analysis: dict,
        url_analysis: dict,
        whois_analysis: list,
        content_analysis: dict,
        attachment_analysis: dict,
        trust_analysis: dict,
        ai_analysis: dict,
        url_page_intelligence: dict = None
    ) -> dict:
        
        evidence_list = []
        
        # 1. Evaluate Authentication
        spf_pass = auth_analysis.get("spf", "").lower() == "pass" or auth_analysis.get("spf_result", "").lower() == "pass"
        dkim_pass = auth_analysis.get("dkim", "").lower() == "pass" or auth_analysis.get("dkim_result", "").lower() == "pass"
        dmarc_pass = auth_analysis.get("dmarc", "").lower() == "pass" or auth_analysis.get("dmarc_result", "").lower() == "pass"
        
        has_auth = auth_analysis.get("spf") or auth_analysis.get("dkim")
        
        if spf_pass and dkim_pass:
            evidence_list.append({
                "type": "authentication",
                "signal": "auth_checks",
                "value": "pass",
                "classification": "POSITIVE"
            })
        elif not has_auth:
            evidence_list.append({
                "type": "authentication",
                "signal": "auth_checks",
                "value": "missing",
                "classification": "UNKNOWN"
            })
        else:
            evidence_list.append({
                "type": "authentication",
                "signal": "auth_checks",
                "value": "fail",
                "classification": "NEGATIVE"
            })

        # 2. Evaluate URLs & Brand
        has_urls = len(url_analysis.get("analysis", [])) > 0
        has_impersonation = False
        has_unrelated_domain = False
        has_official_brand = False
        
        for url_item in url_analysis.get("analysis", []):
            brand_rel = url_item.get("brand_relationship", "UNKNOWN")
            align = url_item.get("alignment", "unknown")
            
            if brand_rel == "IMPERSONATION":
                has_impersonation = True
                evidence_list.append({
                    "type": "url",
                    "signal": "brand_relationship",
                    "value": "impersonation",
                    "classification": "NEGATIVE"
                })
            elif brand_rel == "OFFICIAL":
                has_official_brand = True
                evidence_list.append({
                    "type": "url",
                    "signal": "brand_relationship",
                    "value": "official",
                    "classification": "POSITIVE"
                })
                
            if align == "misaligned" and brand_rel != "OFFICIAL":
                has_unrelated_domain = True
                evidence_list.append({
                    "type": "url",
                    "signal": "alignment",
                    "value": "misaligned",
                    "classification": "NEGATIVE"
                })
        
        if not has_urls:
             evidence_list.append({
                "type": "url",
                "signal": "presence",
                "value": "none",
                "classification": "NEUTRAL"
            })

        # 3. Evaluate Content
        content_risk = content_analysis.get("risk_score", 0)
        if content_risk > 0:
            evidence_list.append({
                "type": "content",
                "signal": "risk_score",
                "value": content_risk,
                "classification": "NEGATIVE"
            })
        else:
             evidence_list.append({
                "type": "content",
                "signal": "risk_score",
                "value": 0,
                "classification": "POSITIVE" if len(parsed_email.get("body", "").split()) >= 5 else "UNKNOWN"
            })

        # 4. Determine State
        body_word_count = len(parsed_email.get("body", "").split())
        is_link_only = body_word_count < 5 and has_urls
        is_empty = body_word_count == 0 and not has_urls
        
        sender = parsed_email.get("from", "") or parsed_email.get("sender", "")
        
        state = "UNKNOWN"
        
        if is_empty or not sender:
            state = "INSUFFICIENT_EVIDENCE"
        elif is_link_only:
            state = "LIMITED_CONTEXT"
        else:
            state = "UNKNOWN"

        # Check for contradictions
        contradictions = []
        
        if spf_pass and dkim_pass:
            if has_impersonation:
                contradictions.append("Authentication passes, but brand impersonation detected in URL.")
            if has_unrelated_domain and content_risk > 30:
                contradictions.append("Authentication passes, but URL is misaligned and content is suspicious.")
                
        if ai_analysis.get("recommended_classification") in ["LEGITIMATE", "LIKELY_LEGITIMATE", "SAFE", "VERIFIED_LEGITIMATE"]:
            if has_impersonation:
                contradictions.append("AI predicts legitimate, but brand impersonation detected.")
            if not spf_pass and not dkim_pass and has_urls:
                contradictions.append("AI predicts legitimate, but authentication failed for email containing URLs.")

        if contradictions:
            state = "CONFLICTING_EVIDENCE"
            for c in contradictions:
                evidence_list.append({
                    "type": "conflict",
                    "signal": "contradiction",
                    "value": c,
                    "classification": "CONFLICTING"
                })
        elif state == "UNKNOWN" and spf_pass and dkim_pass and has_official_brand and content_risk == 0:
            state = "CONSISTENT_LEGITIMATE"
            
        # Allow AI reasoning to heavily influence the state if AI found a conflict or link-only
        ai_state = ai_analysis.get("reasoning_state")
        if ai_state in ["CONFLICTING_EVIDENCE", "LINK_ONLY", "LIMITED_CONTEXT", "INSUFFICIENT_EVIDENCE"]:
            if state not in ["CONFLICTING_EVIDENCE", "INSUFFICIENT_EVIDENCE"]:
                state = ai_state
                if state == "LINK_ONLY":
                    state = "LIMITED_CONTEXT"

        return {
            "conflict_state": state,
            "structured_evidence": evidence_list,
            "contradictions": contradictions
        }
