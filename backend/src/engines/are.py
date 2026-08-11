from src.config.scoring import SCORING


class AnalyticalReasoningEngine:

    def __init__(self):

        self.rules = SCORING

    def evaluate(
        self,
        authentication,
        url_analysis,
        whois_analysis,
        content_analysis,
        attachment_analysis,
        trust_analysis,
        ai_analysis=None
    ):

        score = 0

        evidence = {

            "technical": [],

            "behavioral": [],

            "network": []

        }

        auth = self.rules["authentication"]

        if authentication["spf"] != "pass":

            score += auth["spf_fail"]

            evidence["technical"].append(
                "SPF validation failed"
            )

        if authentication["dkim"] != "pass":

            score += auth["dkim_fail"]

            evidence["technical"].append(
                "DKIM validation failed"
            )

        if authentication["dmarc"] != "pass":

            score += auth["dmarc_fail"]

            evidence["technical"].append(
                "DMARC validation failed"
            )

        url_rules = self.rules["url"]

        for url in url_analysis.get("analysis", []):

            # Legacy checks
            if url.get("ip_based"):
                score += url_rules.get("ip_url", 20)
                evidence["network"].append(f"IP URL: {url['url']}")

            if url.get("shortener"):
                score += url_rules.get("shortener", 10)
                evidence["network"].append(f"Shortened URL: {url['url']}")

            if url.get("keywords"):
                score += (len(url["keywords"]) * url_rules.get("keyword", 5))
                evidence["network"].append("Suspicious URL keywords: " + ", ".join(url["keywords"]))

            if url.get("obfuscated", False):
                score += url_rules.get("obfuscated", 15)
                evidence["network"].append(f"Obfuscated URL detected: {url['url']}")

            if url.get("punycode", False):
                score += url_rules.get("punycode", 20)
                evidence["network"].append(f"Punycode domain detected: {url['domain']}")

            if url.get("suspicious_port", False):
                score += url_rules.get("suspicious_port", 10)
                evidence["network"].append(f"Suspicious URL port detected: {url['url']}")

            if url.get("subdomain_count", 0) > 3:
                score += url_rules.get("excessive_subdomains", 10)
                evidence["network"].append(f"Excessive subdomains detected: {url['domain']}")

            # New Evidence-Based Rules
            if url.get("brand_impersonation"):
                score += 40
                evidence["network"].append(f"Brand impersonation detected: {url['domain']}")

            if url.get("email_alignment") == "misaligned":
                score += 15
                evidence["network"].append(f"URL domain misaligned with sender: {url['domain']}")
            elif url.get("email_alignment") == "aligned":
                score -= 10
                evidence["network"].append(f"URL domain aligned with sender: {url['domain']}")

            # DNS Evidence
            dns = url.get("dns", {})
            if dns.get("private_ip_detected"):
                score += 50
                evidence["network"].append(f"SSRF Protection blocked private IP resolution for: {url['domain']}")
            
            # Redirect Evidence
            redirects = url.get("redirects", {})
            if redirects.get("external_domain_change"):
                score += 20
                evidence["network"].append(f"Suspicious external redirect chain: {url['domain']}")

            # TLS Evidence
            tls = url.get("tls", {})
            if not tls.get("certificate_valid") and tls.get("status") == "failed":
                score += 10
                evidence["network"].append(f"Invalid TLS certificate: {url['domain']}")
            elif tls.get("certificate_valid"):
                score -= 5

            # Threat Intel Evidence
            threat = url.get("threat_intelligence", {})
            if threat.get("detections", 0) > 0:
                score += 60
                evidence["network"].append(f"Known malicious URL: {url['url']}")

        whois_rules = self.rules.get("whois", {})

        for whois in whois_analysis:

            domain = whois.get("domain", "Unknown")
            age_category = whois.get("age_category")
            error = whois.get("error")

            if error:
                score += whois_rules.get("lookup_error", 0)
                evidence["network"].append(f"WHOIS lookup unavailable for: {domain}")
            
            elif age_category == "new":
                score += whois_rules.get("new_domain", 15)
                evidence["network"].append(f"Newly registered domain detected: {domain}")
                
            elif age_category == "recent":
                score += whois_rules.get("recent_domain", 5)
                evidence["network"].append(f"Recently registered domain: {domain}")

        content = self.rules["content"]

        if content_analysis["urgency"]:

            score += content["urgency"]

            evidence["behavioral"].append(
                "Urgency language detected"
            )

        if content_analysis["credential_request"]:

            score += content["credential_request"]

            evidence["behavioral"].append(
                "Credential harvesting attempt"
            )

        if content_analysis["financial_request"]:

            score += content["financial_request"]

            evidence["behavioral"].append(
                "Financial request detected"
            )

        if content_analysis["impersonation"]:

            score += content["impersonation"]

            evidence["behavioral"].append(
                "Possible impersonation"
            )

        if content_analysis["threat_language"]:

            score += content["threat_language"]

            evidence["behavioral"].append(
                "Threat language detected"
            )

        attachment = self.rules["attachment"]

        score += (
            attachment_analysis["risk_score"] *
            attachment["risk_multiplier"]
        )

        for item in attachment_analysis["evidence"]:
            evidence["technical"].append(item)

        score = min(score, 100)

        # -----------------------------
        # Consistency-Based Confidence
        # -----------------------------
        auth_failed = len(evidence["technical"]) > 0
        has_network_risk = len(evidence["network"]) > 0
        has_behavioral_risk = len(evidence["behavioral"]) > 0
        has_trust = trust_analysis.get("trust_score", 0) >= 20

        # Base confidence
        confidence = 50

        if score < 40:
            # Benign case
            if not auth_failed and has_trust and not has_behavioral_risk and not has_network_risk:
                confidence = 95
            elif not auth_failed and not has_behavioral_risk:
                confidence = 80
            elif not auth_failed and (has_behavioral_risk or has_network_risk):
                confidence = 55 # Mixed signals
            else:
                confidence = 65
        else:
            # Malicious case
            if auth_failed and has_network_risk and has_behavioral_risk:
                confidence = 95
            elif auth_failed and (has_network_risk or has_behavioral_risk):
                confidence = 85
            elif not auth_failed and has_network_risk and has_behavioral_risk:
                confidence = 80
            elif not auth_failed and has_trust and score >= 60:
                confidence = 45 # Strong mixed signals (trusted but malicious score)
            else:
                confidence = 70

        # Link-Only Context rule
        if url_analysis.get("limited_context"):
            confidence = max(10, confidence - 40)
            evidence["behavioral"].append("Limited context: Email contains mostly URLs with no body text")

        if score >= 80:
            verdict = "PHISHING"
        elif score >= 60:
            verdict = "HIGH RISK"
        elif score >= 40:
            verdict = "SUSPICIOUS"
        else:
            if confidence >= 90:
                verdict = "VERIFIED LEGITIMATE"
            elif confidence >= 70:
                verdict = "LIKELY LEGITIMATE"
            else:
                verdict = "UNKNOWN"

        # Integrate AI Evidence
        if ai_analysis:
            ai_state = ai_analysis.get("reasoning_state")
            original_ai_state = ai_state
            ai_conf = ai_analysis.get("confidence", 0.0)
            
            # Append AI contradictions to behavioral evidence
            for contradiction in ai_analysis.get("contradictions", []):
                evidence["behavioral"].append(f"AI Conflict: {contradiction}")
                
            for h_ev in ai_analysis.get("homoglyph", []):
                evidence["network"].append(h_ev.get("evidence", "Homoglyph detected"))
                score += 20
                
            for b_ev in ai_analysis.get("brand_intelligence", []):
                if b_ev.get("impersonation_risk"):
                    evidence["behavioral"].append(b_ev.get("explanation"))
                    score += 40
                elif b_ev.get("brand_mentioned") and not b_ev.get("domain_claimed"):
                    evidence["behavioral"].append(b_ev.get("explanation"))
                    
            for a_ev in ai_analysis.get("adversarial", []):
                evidence["behavioral"].append(a_ev.get("explanation"))
                score += 25 if a_ev.get("severity") == "HIGH" else 15
                
            ce_ev = ai_analysis.get("contradictions_engine", {})
            if ce_ev.get("contradiction_detected"):
                evidence["behavioral"].append(ce_ev.get("explanation"))
                if ce_ev.get("state") == "CONFLICTING_EVIDENCE":
                    score += 30
                    ai_state = "CONFLICTING_EVIDENCE"
                elif ce_ev.get("state") == "INSUFFICIENT_EVIDENCE":
                    ai_state = "INSUFFICIENT_EVIDENCE"
                elif ce_ev.get("state") == "TRUST_HISTORY_CONFLICT":
                    score += 40
                    ai_state = "TRUST_HISTORY_CONFLICT"
                    
            for beh in ai_analysis.get("behavioral", []):
                evidence["behavioral"].append(beh.explanation)
                if beh.direction == "NEGATIVE":
                    score += 15

            for cmp in ai_analysis.get("campaign", []):
                evidence["behavioral"].append(cmp.explanation)
                if cmp.direction == "NEGATIVE":
                    score += 25

            for temp in ai_analysis.get("temporal", []):
                evidence["behavioral"].append(temp.explanation)
                if temp.direction == "NEGATIVE":
                    score += 15
                    
            rep = ai_analysis.get("sender_reputation", {})
            rep_status = rep.get("reputation", "UNKNOWN")
            messages_seen = rep.get("messages_seen", 0)
            
            if rep_status == "UNKNOWN" and messages_seen == 0:
                ai_state = "NEW_SENDER"
            elif rep_status in ["SUSPICIOUS", "HIGH_RISK"]:
                ai_state = "SUSPICIOUS_HISTORY"
            elif rep_status == "TRUSTED" and (verdict in ["PHISHING", "HIGH RISK", "SUSPICIOUS"]):
                ai_state = "POSSIBLE_COMPROMISED_SENDER"
            elif rep_status == "TRUSTED" and ai_state in ["CONFLICTING_EVIDENCE", "BRAND_IMPERSONATION"]:
                ai_state = "TRUST_HISTORY_CONFLICT"
                
            # Stage 10: Adaptive evidence integration
            adaptive = ai_analysis.get("adaptive", {})
            if adaptive:
                for anomaly in adaptive.get("behavioral_anomalies", []):
                    explanation = anomaly.get("explanation")
                    anomaly_type = anomaly.get("type")
                    
                    evidence["behavioral"].append(explanation)
                    score += 20 if anomaly.get("severity") == "HIGH" else 10
                    
                    if anomaly_type in ["DOMAIN_DRIFT", "AUTHENTICATION_DRIFT"]:
                        ai_state = anomaly_type
                        
                trend = adaptive.get("risk_trend", {}).get("trend")
                if trend == "DEGRADING":
                    score += 15
                    evidence["behavioral"].append("Risk trend is degrading over time.")
                elif trend == "IMPROVING":
                    score -= 5
                    
                hist_conf = adaptive.get("history_confidence", {}).get("level")
                if hist_conf in ["VERY_LOW", "LOW"]:
                    evidence["behavioral"].append("Insufficient historical baseline for this sender.")

            # AI states map to new detail verdicts
            if original_ai_state in ["CONFLICTING_EVIDENCE", "LIMITED_CONTEXT", "INSUFFICIENT_EVIDENCE", "LINK_ONLY"]:
                verdict = "UNKNOWN" if verdict not in ["PHISHING", "HIGH RISK", "SUSPICIOUS"] else verdict
                evidence["behavioral"].append(f"AI downgraded certainty due to {original_ai_state}")
                if original_ai_state == "LIMITED_CONTEXT" or original_ai_state == "LINK_ONLY":
                    confidence = max(10, min(confidence - 30, 40))
                else:
                    confidence = min(confidence, 50)
            
            # Boost confidence for positive legitimacy
            if ai_state == "SUFFICIENT_EVIDENCE" and verdict in ["VERIFIED LEGITIMATE", "LIKELY LEGITIMATE"]:
                if ai_analysis.get("recommended_classification") in ["LEGITIMATE", "LIKELY_LEGITIMATE", "VERIFIED_LEGITIMATE"]:
                    confidence = min(100, confidence + int(ai_conf * 0.2))
                    
            if ai_analysis.get("recommended_classification") == "VERIFIED_LEGITIMATE" and verdict == "LIKELY LEGITIMATE":
                verdict = "VERIFIED LEGITIMATE"
                confidence = max(confidence, 90)

        score = min(score, 100)
        
        explanation = self.generate_explanation(

            verdict,

            evidence

        )

        return {
            "risk_score": score,
            "confidence": confidence,
            "verdict": verdict,
            "detail_verdict": ai_state if ai_analysis else None,
            "explanation": explanation,
            "evidence": evidence,
            "adaptive_info": ai_analysis.get("adaptive", {}) if ai_analysis else {},
            "structured_evidence": [e.to_dict() for e in ai_analysis.get("structured_evidence", [])] if ai_analysis else []
        }

    def generate_explanation(

        self,

        verdict,

        evidence

    ):

        lines = [

            f"Overall Verdict: {verdict}",

            ""

        ]

        for category, values in evidence.items():

            if values:

                lines.append(

                    category.capitalize() + ":"

                )

                for item in values:

                    lines.append(

                        f"- {item}"

                    )

                lines.append("")

        if len(lines) == 2:

            lines.append(

                "No suspicious indicators detected."

            )

        return "\n".join(lines)