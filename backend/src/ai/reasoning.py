class AIReasoningEngine:
    def __init__(self):
        pass

    def evaluate(self, predicted_class: str, probabilities: dict, features: dict):
        """
        Evaluates the AI model's prediction against deterministic facts to prevent
        the model from making unsafe assertions based purely on text.
        """
        link_only = bool(features.get("link_only", False))
        limited_context = bool(features.get("limited_context", False))
        
        spf_pass = bool(features.get("spf_pass", False))
        dkim_pass = bool(features.get("dkim_pass", False))
        dmarc_pass = bool(features.get("dmarc_pass", False))
        tls_valid = bool(features.get("tls_valid", True))
        
        brand_impersonation = features.get("brand_match", 0) == -1
        brand_official = features.get("brand_match", 0) == 1
        
        sender_url_aligned = features.get("sender_url_alignment", 0) > 0
        has_strong_auth = spf_pass and dkim_pass and dmarc_pass
        
        reasoning_state = "SUFFICIENT_EVIDENCE"
        evidence_log = []
        
        # 1. CONTRADICTION DETECTION: Model says benign, but facts say suspicious
        if predicted_class in ["LEGITIMATE", "LIKELY_LEGITIMATE", "SAFE", "VERIFIED_LEGITIMATE", "UNKNOWN"]:
            if not spf_pass and not dkim_pass and not dmarc_pass and features.get("url_count", 0) > 0:
                if link_only or limited_context:
                    reasoning_state = "LINK_ONLY" if link_only else "LIMITED_CONTEXT"
                    evidence_log.append("Model lacked context, and all authentication checks failed.")
                    predicted_class = "UNKNOWN"
                else:
                    reasoning_state = "CONFLICTING_EVIDENCE"
                    evidence_log.append("Model predicted legitimate, but all authentication checks failed.")
                    predicted_class = "SUSPICIOUS"
                
            if brand_impersonation:
                reasoning_state = "CONFLICTING_EVIDENCE"
                evidence_log.append("Model predicted legitimate, but a URL brand impersonation was detected.")
                predicted_class = "PHISHING"
                
            if not tls_valid:
                reasoning_state = "CONFLICTING_EVIDENCE"
                evidence_log.append("Model predicted legitimate, but a URL has an invalid TLS certificate.")
                
            # If valid auth, but URL is unrelated newly observed domain
            if has_strong_auth and not sender_url_aligned and not brand_official and features.get("url_count", 0) > 0:
                if predicted_class != "PHISHING":
                    reasoning_state = "CONFLICTING_EVIDENCE"
                    evidence_log.append("Authentication passed, but the embedded URL belongs to an unrelated domain. The message therefore contains conflicting legitimacy signals.")
                    predicted_class = "SUSPICIOUS"
                
        # 2. CONTRADICTION DETECTION: Model says suspicious, but facts say highly legitimate
        if predicted_class in ["SUSPICIOUS", "PHISHING"]:
            if has_strong_auth and tls_valid and not brand_impersonation and (sender_url_aligned or brand_official):
                reasoning_state = "CONFLICTING_EVIDENCE"
                evidence_log.append("Model predicted suspicious, but email has perfect authentication and aligned official domains. Preserving conflict.")
                
        # 3. LINK-ONLY DECISION RULE
        if link_only and reasoning_state not in ["CONFLICTING_EVIDENCE"]:
            if predicted_class in ["LEGITIMATE", "LIKELY_LEGITIMATE", "SAFE", "UNKNOWN"]:
                if not has_strong_auth or not brand_official:
                    # Positive legitimacy evidence is insufficient
                    predicted_class = "UNKNOWN"
                    reasoning_state = "LINK_ONLY"
                    evidence_log.append("Model predicted legitimate, but email is link-only without strong official authentication. Downgrading to UNKNOWN.")
                else:
                    reasoning_state = "LINK_ONLY"
                    evidence_log.append("Email is link-only, but strong authentication justifies legitimate rating.")
            else:
                reasoning_state = "LINK_ONLY"
                
        # 4. INSUFFICIENT EVIDENCE (Empty body, no URLs, no strong auth)
        if limited_context and not link_only and features.get("word_count", 0) < 5:
            if not has_strong_auth and reasoning_state not in ["CONFLICTING_EVIDENCE"]:
                reasoning_state = "INSUFFICIENT_EVIDENCE"
                predicted_class = "UNKNOWN"
                evidence_log.append("Empty body with no strong authentication. Insufficient evidence for classification.")

        # 5. LEGITIMATE VERIFICATION ENHANCEMENT
        if predicted_class in ["LEGITIMATE", "LIKELY_LEGITIMATE", "SAFE", "UNKNOWN"]:
            if has_strong_auth and tls_valid and (sender_url_aligned or brand_official) and not brand_impersonation:
                # Strong positive evidence
                if features.get("account_verification", 0) > 0 or features.get("password_reset", 0) > 0:
                    predicted_class = "VERIFIED_LEGITIMATE"
                    evidence_log.append("Verified legitimate account verification request based on strong authentication and context.")
                elif predicted_class == "LEGITIMATE":
                    predicted_class = "VERIFIED_LEGITIMATE"
            
        # Map legacy 'SAFE' or 'LEGITIMATE' to proper Stage 3 states
        if predicted_class in ["SAFE", "LEGITIMATE"]:
            predicted_class = "LIKELY_LEGITIMATE"

        # Recalculate confidence based on probabilities, but cap it if there are conflicts
        max_prob = max(probabilities.values()) if probabilities else 0.0
        confidence = max_prob * 100
        
        if predicted_class == "VERIFIED_LEGITIMATE":
            confidence = max(confidence, 90.0)
            
        if reasoning_state in ["CONFLICTING_EVIDENCE", "LIMITED_CONTEXT", "LINK_ONLY"]:
            confidence = min(confidence, 50.0)
        elif reasoning_state == "INSUFFICIENT_EVIDENCE":
            confidence = 0.0
            
        return {
            "predicted_class": predicted_class,
            "reasoning_state": reasoning_state,
            "confidence": round(confidence, 2),
            "evidence": evidence_log
        }
