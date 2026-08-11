class ExplanationEngine:
    def evaluate(self, verdict: str, confidence: int, risk_score: int, conflict_state: str, structured_evidence: list) -> dict:
        summary = ""
        key_findings = []
        confidence_reason = ""
        
        # Build key findings
        for ev in structured_evidence:
            if ev["classification"] == "POSITIVE" and ev["type"] == "authentication":
                key_findings.append("Sender authentication (SPF/DKIM) passed")
            elif ev["classification"] == "NEGATIVE" and ev["type"] == "authentication":
                key_findings.append("Sender authentication failed or is missing")
            elif ev["classification"] == "POSITIVE" and ev["type"] == "url" and ev["signal"] == "brand_relationship":
                key_findings.append("URL domain matches the official brand")
            elif ev["classification"] == "NEGATIVE" and ev["type"] == "url" and ev["signal"] == "brand_relationship":
                key_findings.append("Brand impersonation detected in URL")
            elif ev["classification"] == "NEGATIVE" and ev["type"] == "url" and ev["signal"] == "alignment":
                key_findings.append("URL domain does not match sender domain")
            elif ev["classification"] == "NEGATIVE" and ev["type"] == "content":
                key_findings.append("Suspicious content or urgency detected")
        
        # Build summary and confidence reason based on state and verdict
        if conflict_state == "CONFLICTING_EVIDENCE":
            summary = "Email contains contradictory signals that require careful inspection."
            confidence_reason = "Confidence is reduced due to conflicting evidence between authentication, content, and URLs."
        elif conflict_state == "INSUFFICIENT_EVIDENCE":
            summary = "Email lacks sufficient context to verify the sender."
            confidence_reason = "Low confidence due to missing sender, body, or authentication details."
        elif conflict_state == "LIMITED_CONTEXT":
            summary = "Email contains only a link with no context."
            confidence_reason = "Confidence is limited because the email lacks natural language content to evaluate."
        else:
            if verdict in ["VERIFIED LEGITIMATE", "LIKELY LEGITIMATE"]:
                summary = "Email appears legitimate based on strong authentication and domain alignment."
                confidence_reason = "High confidence due to consistent positive signals and no malicious indicators."
            elif verdict in ["PHISHING", "HIGH RISK"]:
                summary = "Email exhibits strong indicators of malicious intent or phishing."
                confidence_reason = "High confidence based on multiple suspicious or failed technical checks."
            else:
                summary = "Email exhibits mixed or unknown signals."
                confidence_reason = "Moderate confidence based on the available evidence."

        return {
            "summary": summary,
            "key_findings": list(set(key_findings)),
            "confidence_reason": confidence_reason
        }
