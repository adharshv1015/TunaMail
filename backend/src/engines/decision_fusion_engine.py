class DecisionFusionEngine:
    def evaluate(self, are_result, conflict_result=None):
        risk_score = are_result.get("risk_score", 0)
        
        # In Stage 7, we pull confidence and reasoning state directly from AI layer if available
        confidence = are_result.get("confidence", 50)
        detail_verdict = are_result.get("detail_verdict", "UNKNOWN")
        
        evidence = are_result.get("evidence", {})
        
        technical = len(evidence.get("technical", []))
        behavioral = len(evidence.get("behavioral", []))
        network = len(evidence.get("network", []))

        verdict = "UNKNOWN"

        # -----------------------------
        # Stage 7 Verdict Hierarchy
        # -----------------------------
        
        # 1. Deterministic Phishing / High Risk
        if (
            any("Executable attachment" in e for e in evidence.get("technical", [])) or
            any("Script attachment" in e for e in evidence.get("technical", []))
        ):
            verdict = "PHISHING"
            risk_score = max(risk_score, 85)
        elif technical >= 2 and risk_score >= 40:
            verdict = "PHISHING"
            risk_score = max(risk_score, 80)
        elif behavioral >= 2 and network >= 1 and risk_score >= 60:
            verdict = "PHISHING"
            risk_score = max(risk_score, 80)
        elif risk_score >= 80:
            verdict = "PHISHING"
        elif risk_score >= 60:
            verdict = "HIGH RISK"
        elif risk_score >= 40:
            verdict = "SUSPICIOUS"
        else:
            if confidence >= 90:
                verdict = "VERIFIED LEGITIMATE"
            elif confidence >= 70:
                verdict = "LIKELY LEGITIMATE"
            elif confidence >= 40:
                verdict = "SAFE"
            else:
                verdict = "LOW RISK"

        # -----------------------------
        # Detail Verdict Overrides
        # -----------------------------
        if detail_verdict in ["LIMITED_CONTEXT", "INSUFFICIENT_EVIDENCE", "LINK_ONLY"]:
            if verdict in ["PHISHING", "HIGH RISK"]:
                verdict = "SUSPICIOUS" if risk_score >= 40 else "UNKNOWN"
        elif detail_verdict == "CONFLICTING_EVIDENCE":
            if verdict in ["VERIFIED LEGITIMATE", "LIKELY LEGITIMATE", "LOW RISK", "SAFE"]:
                verdict = "UNKNOWN"
            if verdict == "UNKNOWN" and risk_score >= 40:
                verdict = "SUSPICIOUS"
        elif detail_verdict == "TRUST_HISTORY_CONFLICT":
            if verdict in ["PHISHING", "HIGH RISK"]:
                detail_verdict = "POSSIBLE_COMPROMISED_SENDER"
            else:
                verdict = "SUSPICIOUS"
        elif detail_verdict == "SUSPICIOUS_HISTORY":
            if verdict in ["UNKNOWN", "LOW RISK", "SAFE"]:
                verdict = "SUSPICIOUS"
        elif detail_verdict == "NEW_SENDER":
            if verdict in ["VERIFIED LEGITIMATE", "LIKELY LEGITIMATE"]:
                verdict = "SAFE"
            elif verdict == "LOW RISK" and confidence == 0:
                verdict = "UNKNOWN"
        elif detail_verdict in ["DOMAIN_DRIFT", "AUTHENTICATION_DRIFT"]:
            if verdict in ["VERIFIED LEGITIMATE", "LIKELY LEGITIMATE", "SAFE", "LOW RISK", "UNKNOWN"]:
                verdict = "SUSPICIOUS"

        are_result["risk_score"] = risk_score
        are_result["verdict"] = verdict
        are_result["confidence"] = confidence
        are_result["detail_verdict"] = detail_verdict

        recommendation = self.get_recommendation(verdict)

        structured_evidence = are_result.get("structured_evidence", [])
        
        # Adaptive factors
        adaptive_factors = []
        if are_result.get("structured_evidence"):
            # If orchestrator gave us the raw ai analysis, we can extract it, but it's not here.
            pass
        
        # We need to add adaptive factors. We can pull it from are_result if we pass it out of ARE.
        adaptive = are_result.get("adaptive_info", {})
        if adaptive:
            adaptive_factors = adaptive.get("behavioral_anomalies", [])
        
        explanation = self._build_explanation(verdict, detail_verdict, risk_score, structured_evidence, adaptive_factors)

        return {
            "risk_score": risk_score,
            "confidence": confidence,
            "verdict": verdict,
            "detail_verdict": detail_verdict,
            "recommendation": recommendation,
            "reasoning": evidence,
            "explanation": explanation,
            "evidence_quality": self.get_evidence_quality(confidence)
        }

    def _build_explanation(self, verdict, detail_verdict, risk_score, structured_evidence, adaptive_factors=None):
        positive_ev = [e for e in structured_evidence if e.get("supports", e.get("direction")) in ["BENIGN", "POSITIVE"]]
        negative_ev = [e for e in structured_evidence if e.get("supports", e.get("direction")) in ["MALICIOUS", "NEGATIVE"]]
        
        primary_reason = "No primary reason identified."
        sev_map = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        
        if verdict in ["PHISHING", "HIGH RISK", "SUSPICIOUS"]:
            sorted_neg = sorted(negative_ev, key=lambda x: sev_map.get(x.get("severity", "INFO"), 0), reverse=True)
            if sorted_neg:
                primary_reason = sorted_neg[0].get("explanation", "Negative indicator found.")
                if len(sorted_neg) > 1:
                    primary_reason += " Combined with other risk factors."
        elif verdict in ["VERIFIED LEGITIMATE", "LIKELY LEGITIMATE", "SAFE"]:
            if not positive_ev:
                primary_reason = "No explicit positive evidence found, but no threats detected."
            else:
                primary_reason = "Verified legitimate based on " + ", ".join(set(e.get("type", "").replace("_", " ") for e in positive_ev)) + " and absence of contradictory indicators."
        elif verdict == "UNKNOWN":
            primary_reason = "Insufficient evidence to determine sender intent."

        limitations = []
        if detail_verdict in ["LIMITED_CONTEXT", "INSUFFICIENT_EVIDENCE", "LINK_ONLY"]:
            primary_reason = "Limited email context. The message contains insufficient textual evidence to establish sender intent."
        elif detail_verdict in ["CONFLICTING_EVIDENCE", "TRUST_HISTORY_CONFLICT"]:
            limitations.append("Sender authentication or trust history conflicts with current content indicators.")

        return {
            "summary": f"{verdict.title()} detected.",
            "primary_reason": primary_reason,
            "supporting_evidence": negative_ev if verdict in ["PHISHING", "HIGH RISK", "SUSPICIOUS"] else positive_ev,
            "contradicting_evidence": positive_ev if verdict in ["PHISHING", "HIGH RISK", "SUSPICIOUS"] else negative_ev,
            "positive_evidence": positive_ev,
            "negative_evidence": negative_ev,
            "adaptive_factors": adaptive_factors or [],
            "confidence_factors": [f"{len(positive_ev)} positive signals", f"{len(negative_ev)} negative signals"],
            "limitations": limitations
        }

    def get_evidence_quality(self, confidence):
        if confidence >= 80:
            return "HIGH"
        elif confidence >= 50:
            return "MEDIUM"
        return "LIMITED"

    def get_recommendation(self, verdict):
        recommendations = {
            "VERIFIED LEGITIMATE": "Strong evidence indicates this email is legitimate.",
            "LIKELY LEGITIMATE": "Appears safe, but always verify unexpected requests.",
            "LOW RISK": "No significant threats detected, but sender is not fully verified.",
            "SAFE": "Email has been thoroughly verified as safe.",
            "UNKNOWN": "Insufficient evidence to verify this sender. Exercise caution.",
            "SUSPICIOUS": "Exercise caution before clicking links or downloading files.",
            "HIGH RISK": "Multiple risk factors detected. Do not click links unless verified.",
            "PHISHING": "Do not interact with this email. Report or delete it immediately."
        }
        return recommendations.get(verdict, "Exercise caution.")