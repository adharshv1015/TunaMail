from typing import List, Dict, Any
from .evidence_model import EvidenceItem, EvidenceCategory, EvidenceSeverity, EvidenceDirection
from .threat_patterns import ThreatPatterns

class EvidenceCollector:
    def __init__(self):
        pass

    def collect_evidence(self, parsed_email: dict, analysis: dict, ai_analysis: dict) -> List[EvidenceItem]:
        evidence_items = []
        
        # We need to extract signals from analysis and ai_analysis
        auth = analysis.get("authentication", {})
        url_data = analysis.get("url", {})
        content = analysis.get("content", {})
        attachment = analysis.get("attachment", {})
        whois_data = analysis.get("whois", [])
        trust = analysis.get("trust", {})
        
        # 1. Authentication Evidence
        spf = auth.get("spf")
        if spf == "pass":
            evidence_items.append(EvidenceItem(
                category=EvidenceCategory.AUTHENTICATION,
                type="spf_pass",
                severity=EvidenceSeverity.INFO,
                direction=EvidenceDirection.POSITIVE,
                source="auth_analyzer",
                explanation="SPF validation passed, confirming the sender IP is authorized."
            ))
        elif spf:
            evidence_items.append(EvidenceItem(
                category=EvidenceCategory.AUTHENTICATION,
                type="spf_fail",
                severity=EvidenceSeverity.MEDIUM,
                direction=EvidenceDirection.NEGATIVE,
                source="auth_analyzer",
                explanation="SPF validation failed or soft-failed."
            ))

        dkim = auth.get("dkim")
        if dkim == "pass":
            evidence_items.append(EvidenceItem(
                category=EvidenceCategory.AUTHENTICATION,
                type="dkim_pass",
                severity=EvidenceSeverity.INFO,
                direction=EvidenceDirection.POSITIVE,
                source="auth_analyzer",
                explanation="DKIM validation passed, confirming message integrity."
            ))
        elif dkim:
            evidence_items.append(EvidenceItem(
                category=EvidenceCategory.AUTHENTICATION,
                type="dkim_fail",
                severity=EvidenceSeverity.MEDIUM,
                direction=EvidenceDirection.NEGATIVE,
                source="auth_analyzer",
                explanation="DKIM validation failed."
            ))

        dmarc = auth.get("dmarc")
        if dmarc == "pass":
            evidence_items.append(EvidenceItem(
                category=EvidenceCategory.AUTHENTICATION,
                type="dmarc_pass",
                severity=EvidenceSeverity.INFO,
                direction=EvidenceDirection.POSITIVE,
                source="auth_analyzer",
                explanation="DMARC validation passed, confirming domain alignment."
            ))
        elif dmarc:
            evidence_items.append(EvidenceItem(
                category=EvidenceCategory.AUTHENTICATION,
                type="dmarc_fail",
                severity=EvidenceSeverity.HIGH,
                direction=EvidenceDirection.NEGATIVE,
                source="auth_analyzer",
                explanation="DMARC validation failed."
            ))

        if not auth:
            evidence_items.append(EvidenceItem(
                category=EvidenceCategory.AUTHENTICATION,
                type="auth_unavailable",
                severity=EvidenceSeverity.LOW,
                direction=EvidenceDirection.NEUTRAL,
                source="auth_analyzer",
                explanation="UNAVAILABLE: Authentication details could not be found."
            ))

        # 2. Sender Evidence
        sender = parsed_email.get("from", "")
        if sender:
            evidence_items.append(EvidenceItem(
                category=EvidenceCategory.SENDER,
                type="sender_domain",
                severity=EvidenceSeverity.INFO,
                direction=EvidenceDirection.NEUTRAL,
                source="email_parser",
                explanation=f"Sender domain identified as {sender}",
                value={"domain": sender}
            ))

        # 3. URL Evidence
        urls = url_data.get("analysis", [])
        if urls:
            for u in urls:
                domain = u.get("domain", "")
                
                # DNS
                dns = u.get("dns", {})
                if dns.get("private_ip_detected"):
                    evidence_items.append(EvidenceItem(
                        category=EvidenceCategory.URL,
                        type="private_ip",
                        severity=EvidenceSeverity.HIGH,
                        direction=EvidenceDirection.NEGATIVE,
                        source="url_analyzer",
                        explanation=f"URL resolves to a private IP (SSRF protection). Domain: {domain}"
                    ))
                
                # TLS
                tls = u.get("tls", {})
                if tls:
                    if tls.get("certificate_valid"):
                        evidence_items.append(EvidenceItem(
                            category=EvidenceCategory.URL,
                            type="tls_valid",
                            severity=EvidenceSeverity.INFO,
                            direction=EvidenceDirection.POSITIVE,
                            source="url_analyzer",
                            explanation=f"TLS certificate is valid for {domain}"
                        ))
                    else:
                        evidence_items.append(EvidenceItem(
                            category=EvidenceCategory.URL,
                            type="tls_invalid",
                            severity=EvidenceSeverity.MEDIUM,
                            direction=EvidenceDirection.NEGATIVE,
                            source="url_analyzer",
                            explanation=f"Invalid or missing TLS certificate for {domain}"
                        ))
                elif tls_unavailable:
                     evidence.append(
                        EvidenceItem(
                        category=EvidenceCategory.NETWORK,
                        direction=EvidenceDirection.NEUTRAL,
                        type="TLS_INSPECTION_UNAVAILABLE",
                        severity="INFO",
                        confidence=0.0,
                        weight=0,
                        explanation=(
                            f"TLS inspection could not be completed for {domain}. "
                            "This is an inspection limitation and is not evidence "
                            "of malicious intent."
                        )
                    )
                )
                

                # Redirects
                redirects = u.get("redirects", {})
                if redirects.get("external_domain_change"):
                    evidence_items.append(EvidenceItem(
                        category=EvidenceCategory.URL,
                        type="suspicious_redirect",
                        severity=EvidenceSeverity.HIGH,
                        direction=EvidenceDirection.NEGATIVE,
                        source="url_analyzer",
                        explanation=f"Suspicious external redirect chain starting at {domain}"
                    ))

                # Threat intel
                threat = u.get("threat_intelligence", {})
                if threat.get("detections", 0) > 0:
                    evidence_items.append(EvidenceItem(
                        category=EvidenceCategory.URL,
                        type="known_malicious",
                        severity=EvidenceSeverity.CRITICAL,
                        direction=EvidenceDirection.NEGATIVE,
                        source="url_analyzer",
                        explanation=f"Known malicious URL detected: {u.get('url')}"
                    ))

        # 4. WHOIS Evidence
        for w in whois_data:
            domain = w.get("domain", "")
            error = w.get("error")
            age = w.get("age_category")
            if error:
                evidence_items.append(EvidenceItem(
                    category=EvidenceCategory.DOMAIN,
                    type="whois_unavailable",
                    severity=EvidenceSeverity.INFO,
                    direction=EvidenceDirection.NEUTRAL,
                    source="url_analyzer",
                    explanation=f"UNAVAILABLE: WHOIS lookup unavailable for {domain}"
                ))
            elif age == "new":
                evidence_items.append(EvidenceItem(
                    category=EvidenceCategory.DOMAIN,
                    type="new_domain",
                    severity=EvidenceSeverity.HIGH,
                    direction=EvidenceDirection.NEGATIVE,
                    source="url_analyzer",
                    explanation=f"Newly registered domain detected: {domain}"
                ))
            elif age == "established":
                evidence_items.append(EvidenceItem(
                    category=EvidenceCategory.DOMAIN,
                    type="established_domain",
                    severity=EvidenceSeverity.INFO,
                    direction=EvidenceDirection.POSITIVE,
                    source="url_analyzer",
                    explanation=f"Domain has an established reputation based on age: {domain}"
                ))

        # 5. Content Evidence (Deduplicated via ThreatPatterns contextual awareness later, but we gather raw here)
        body = parsed_email.get("body", "")
        if ThreatPatterns.match_urgency(body) or content.get("urgency"):
            evidence_items.append(EvidenceItem(
                category=EvidenceCategory.CONTENT,
                type="urgency",
                severity=EvidenceSeverity.LOW,
                direction=EvidenceDirection.NEGATIVE,
                source="content_analyzer",
                explanation="Email contains urgent language."
            ))
            
        if ThreatPatterns.match_credential_harvesting(body) or content.get("credential_request"):
            evidence_items.append(EvidenceItem(
                category=EvidenceCategory.CONTENT,
                type="credential_request",
                severity=EvidenceSeverity.MEDIUM,
                direction=EvidenceDirection.NEGATIVE,
                source="content_analyzer",
                explanation="Email contains a credential request or login prompt."
            ))

        if ThreatPatterns.match_financial_request(body) or content.get("financial_request"):
            evidence_items.append(EvidenceItem(
                category=EvidenceCategory.CONTENT,
                type="financial_request",
                severity=EvidenceSeverity.LOW,
                direction=EvidenceDirection.NEGATIVE,
                source="content_analyzer",
                explanation="Email contains a financial request or invoice language."
            ))

        # 6. Attachments
        if attachment.get("risk_score", 0) > 0:
            for ev in attachment.get("evidence", []):
                evidence_items.append(EvidenceItem(
                    category=EvidenceCategory.ATTACHMENT,
                    type="suspicious_attachment",
                    severity=EvidenceSeverity.HIGH,
                    direction=EvidenceDirection.NEGATIVE,
                    source="attachment_analyzer",
                    explanation=ev
                ))

        # 7. Brand Intelligence
        for brand in ai_analysis.get("brand_intelligence", []):
            if brand.get("impersonation_risk"):
                evidence_items.append(EvidenceItem(
                    category=EvidenceCategory.BRAND,
                    type="brand_impersonation",
                    severity=EvidenceSeverity.CRITICAL,
                    direction=EvidenceDirection.NEGATIVE,
                    source="brand_intelligence",
                    explanation=brand.get("explanation")
                ))
            elif brand.get("brand_mentioned") and not brand.get("domain_claimed"):
                evidence_items.append(EvidenceItem(
                    category=EvidenceCategory.BRAND,
                    type="brand_mention_unclaimed",
                    severity=EvidenceSeverity.INFO,
                    direction=EvidenceDirection.NEUTRAL,
                    source="brand_intelligence",
                    explanation=brand.get("explanation")
                ))

        # 8. Adversarial
        for adv in ai_analysis.get("adversarial", []):
            evidence_items.append(EvidenceItem(
                category=EvidenceCategory.AI,
                type="adversarial_tactics",
                severity=EvidenceSeverity.HIGH,
                direction=EvidenceDirection.NEGATIVE,
                source="adversarial_analyzer",
                explanation=adv.get("explanation")
            ))

        # 9. Contradictions
        ce = ai_analysis.get("contradictions_engine", {})
        if ce.get("contradiction_detected"):
            evidence_items.append(EvidenceItem(
                category=EvidenceCategory.AI,
                type="evidence_contradiction",
                severity=EvidenceSeverity.HIGH,
                direction=EvidenceDirection.NEGATIVE,
                source="contradiction_engine",
                explanation=ce.get("explanation")
            ))

        # 10. Homoglyphs
        for homo in ai_analysis.get("homoglyph", []):
            evidence_items.append(EvidenceItem(
                category=EvidenceCategory.URL,
                type="homoglyph",
                severity=EvidenceSeverity.HIGH,
                direction=EvidenceDirection.NEGATIVE,
                source="homoglyph_detector",
                explanation=homo.get("evidence")
            ))

        # 11. Context Quality
        context = ai_analysis.get("context", {})
        if context.get("link_only") or context.get("limited_context"):
            evidence_items.append(EvidenceItem(
                category=EvidenceCategory.CONTENT,
                type="insufficient_context",
                severity=EvidenceSeverity.INFO,
                direction=EvidenceDirection.NEGATIVE,
                source="ai_orchestrator",
                explanation="INSUFFICIENT_EVIDENCE: Email contains limited text context or only links."
            ))

        return evidence_items
