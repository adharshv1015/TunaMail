"""
Stage 13 — ExplanationEngine
============================
Consumes the already-computed analysis and decision produced by the pipeline.

CRITICAL RULE: This engine MUST NEVER modify risk_score, verdict, confidence,
or recommendation. It is a read-only consumer of existing intelligence.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class ExplanationEngine:
    """
    Generates structured, human-readable, analyst-grade explanations from the
    existing analysis and decision.

    All verdicts remain authoritative from DecisionFusionEngine.
    This engine ONLY explains. It NEVER scores, overrides, or recalculates.
    """

    def generate(
        self,
        parsed_email: dict,
        analysis: dict,
        decision: dict,
    ) -> dict:
        """
        Generate explanation from already-computed intelligence.

        Args:
            parsed_email: Parsed email fields (read-only).
            analysis:     Full analysis dict from the pipeline (read-only).
            decision:     Final decision from DecisionFusionEngine (read-only).

        Returns:
            Explanation dict. Never modifies decision.
        """
        # Defensive: work on copies so we cannot accidentally mutate
        analysis = analysis or {}
        decision_snap = dict(decision or {})

        # ----------------------------------------------------------------
        # Initialise output structure
        # ----------------------------------------------------------------
        explanation: dict = {
            "primary_reason": "",
            "final_reason": "",
            "confidence_explanation": "",
            "agreement": {
                "positive_sources": 0,
                "negative_sources": 0,
                "contradictory_sources": 0,
                "independent_sources": 0,
            },
            "groups": {
                "PRIMARY_REASON": [],
                "SUPPORTING_EVIDENCE": [],
                "POSITIVE_EVIDENCE": [],
                "NEGATIVE_EVIDENCE": [],
                "CONTRADICTIONS": [],
                "CONTEXT_LIMITATIONS": [],
                "BEHAVIORAL_FINDINGS": [],
                "URL_FINDINGS": [],
                "AUTHENTICATION_FINDINGS": [],
                "BRAND_FINDINGS": [],
                "FINAL_REASON": [],
            },
        }

        # ----------------------------------------------------------------
        # Pull sub-analyses from analysis dict
        # NOTE: in the gmail.py pipeline the keys are:
        #   analysis["authentication"], analysis["url"], analysis["content"],
        #   analysis["whois"], analysis["attachment"], analysis["trust"],
        #   analysis["ai"], analysis["conflict"], analysis["reasoning"]
        # ----------------------------------------------------------------
        auth = analysis.get("authentication") or {}
        # url_analysis may be stored as "url" (pipeline) or "urls" (schema default)
        url_analysis = analysis.get("url") or analysis.get("urls") or {}
        urls = url_analysis.get("analysis") or []
        content = analysis.get("content") or {}
        whois_list = analysis.get("whois") or []
        attachment = analysis.get("attachment") or {}
        trust = analysis.get("trust") or {}
        ai = analysis.get("ai") or {}
        conflict = analysis.get("conflict") or {}
        # ARE result is stored under "reasoning" as the evidence sub-dict
        are_evidence = analysis.get("reasoning") or {}

        verdict = decision_snap.get("verdict", "UNKNOWN")
        detail_verdict = decision_snap.get("detail_verdict", "")
        confidence_pct = int(decision_snap.get("confidence", 0))
        conflict_state = conflict.get("conflict_state", "")

        # ----------------------------------------------------------------
        # Tracking counters
        # ----------------------------------------------------------------
        positive_count = 0
        negative_count = 0
        independent_sources: set[str] = set()
        all_evidence: list[dict] = []

        # ----------------------------------------------------------------
        # Helper: add an evidence item
        # ----------------------------------------------------------------
        def add_ev(
            group: str,
            source: str,
            etype: str,
            severity: str,
            weight: int,
            conf: float,
            direction: str,
            title: str,
            exp: str,
            raw: dict | None = None,
        ) -> None:
            nonlocal positive_count, negative_count
            item = {
                "source": source,
                "type": etype,
                "severity": severity,
                "weight": weight,
                "confidence": conf,
                "direction": direction,
                "title": title,
                "explanation": exp,
                "evidence": raw or {},
            }
            explanation["groups"][group].append(item)
            all_evidence.append(item)
            if direction == "POSITIVE":
                positive_count += 1
            elif direction == "NEGATIVE":
                negative_count += 1
            independent_sources.add(source)

        # ================================================================
        # 1. AUTHENTICATION
        # ================================================================
        auth_status = auth.get("analysis_status", "AVAILABLE")
        if auth_status != "UNAVAILABLE":
            spf_pass = auth.get("spf") == "pass" or auth.get("spf_result") == "pass"
            dkim_pass = auth.get("dkim") == "pass" or auth.get("dkim_result") == "pass"
            dmarc_pass = auth.get("dmarc") == "pass" or auth.get("dmarc_result") == "pass"
            all_auth_pass = spf_pass and dkim_pass and dmarc_pass

            if all_auth_pass:
                add_ev(
                    "POSITIVE_EVIDENCE",
                    "AuthenticationAnalyzer",
                    "AUTHENTICATION_PASS",
                    "LOW", 15, 0.96, "POSITIVE",
                    "Sender authentication passed",
                    "SPF, DKIM, and DMARC checks all passed. Cryptographic signatures and "
                    "domain policy records confirm the email originated from the claimed domain.",
                )
                add_ev(
                    "AUTHENTICATION_FINDINGS",
                    "AuthenticationAnalyzer",
                    "AUTHENTICATION_PASS",
                    "LOW", 15, 0.96, "POSITIVE",
                    "All three authentication protocols passed",
                    "SPF verified sending IP authorisation, DKIM confirmed message integrity, "
                    "and DMARC enforced domain-level policy compliance.",
                )
            else:
                if not spf_pass:
                    add_ev(
                        "NEGATIVE_EVIDENCE",
                        "AuthenticationAnalyzer",
                        "SPF_FAIL",
                        "MEDIUM", 20, 0.90, "NEGATIVE",
                        "SPF validation failed",
                        "The sender IP is not authorised to send email on behalf of this domain. "
                        "This weakens confidence in sender identity.",
                    )
                    add_ev(
                        "AUTHENTICATION_FINDINGS",
                        "AuthenticationAnalyzer",
                        "SPF_FAIL",
                        "MEDIUM", 20, 0.90, "NEGATIVE",
                        "SPF failed",
                        "Sender Policy Framework check did not pass.",
                    )
                if not dkim_pass:
                    add_ev(
                        "NEGATIVE_EVIDENCE",
                        "AuthenticationAnalyzer",
                        "DKIM_FAIL",
                        "MEDIUM", 20, 0.90, "NEGATIVE",
                        "DKIM validation failed",
                        "The email's cryptographic signature is invalid or missing. "
                        "The message may have been altered in transit.",
                    )
                    add_ev(
                        "AUTHENTICATION_FINDINGS",
                        "AuthenticationAnalyzer",
                        "DKIM_FAIL",
                        "MEDIUM", 20, 0.90, "NEGATIVE",
                        "DKIM failed",
                        "Email cryptographic signature check failed.",
                    )
                if not dmarc_pass:
                    add_ev(
                        "NEGATIVE_EVIDENCE",
                        "AuthenticationAnalyzer",
                        "DMARC_FAIL",
                        "MEDIUM", 15, 0.85, "NEGATIVE",
                        "DMARC policy check failed",
                        "The domain owner's email security policy was not satisfied.",
                    )
                    add_ev(
                        "AUTHENTICATION_FINDINGS",
                        "AuthenticationAnalyzer",
                        "DMARC_FAIL",
                        "MEDIUM", 15, 0.85, "NEGATIVE",
                        "DMARC failed",
                        "Domain-level authentication policy not satisfied.",
                    )
        else:
            add_ev(
                "CONTEXT_LIMITATIONS",
                "AuthenticationAnalyzer",
                "AUTHENTICATION_UNAVAILABLE",
                "INFO", 0, 0.5, "NEUTRAL",
                "Authentication data unavailable",
                "Authentication results could not be retrieved for this message.",
            )

        # ================================================================
        # 2. URL ANALYSIS
        # ================================================================
        if urls:
            malicious_urls = 0
            safe_urls = 0
            for u in urls:
                detections = u.get("threat_intelligence", {}).get("detections", 0)
                redirect_risk = u.get("redirect_chain", {}).get("final_risk", "")
                is_suspicious = detections > 0 or redirect_risk in ("HIGH", "CRITICAL")

                if is_suspicious:
                    malicious_urls += 1
                    add_ev(
                        "NEGATIVE_EVIDENCE",
                        "URLAnalyzer",
                        "SUSPICIOUS_URL",
                        "HIGH", 35, 0.91, "NEGATIVE",
                        "Suspicious destination detected",
                        f"URL threat intelligence indicates a high-risk destination domain: "
                        f"{u.get('domain', 'unknown')}. "
                        "The destination may redirect to credential-harvesting infrastructure.",
                        {"domain": u.get("domain", ""), "url": u.get("url", "")},
                    )
                    add_ev(
                        "URL_FINDINGS",
                        "URLAnalyzer",
                        "SUSPICIOUS_URL",
                        "HIGH", 35, 0.91, "NEGATIVE",
                        f"High-risk destination: {u.get('domain', 'unknown')}",
                        "The destination domain does not align with the claimed organisation's "
                        "canonical infrastructure.",
                        {"domain": u.get("domain", "")},
                    )
                else:
                    safe_urls += 1

            if safe_urls > 0 and malicious_urls == 0:
                add_ev(
                    "POSITIVE_EVIDENCE",
                    "URLAnalyzer",
                    "SAFE_URLS",
                    "LOW", 10, 0.80, "POSITIVE",
                    "No malicious URLs detected",
                    f"All {safe_urls} URL(s) resolved to benign destinations with no "
                    "threat intelligence detections.",
                )
                add_ev(
                    "URL_FINDINGS",
                    "URLAnalyzer",
                    "SAFE_URLS",
                    "LOW", 10, 0.80, "POSITIVE",
                    "URLs appear benign",
                    "All inspected URLs passed threat intelligence checks.",
                )
        elif url_analysis.get("risk_score", 0) == 0 and not urls:
            # No URLs in the email at all
            add_ev(
                "CONTEXT_LIMITATIONS",
                "URLAnalyzer",
                "NO_URLS",
                "INFO", 0, 0.9, "NEUTRAL",
                "No URLs found",
                "This message contains no hyperlinks for inspection.",
            )

        # ================================================================
        # 3. WHOIS
        # ================================================================
        if isinstance(whois_list, list) and whois_list:
            for w in whois_list:
                if not isinstance(w, dict):
                    continue
                age_days = w.get("age_days")
                domain = w.get("domain", "unknown")

                if age_days is not None and age_days <= 30:
                    add_ev(
                        "NEGATIVE_EVIDENCE",
                        "WhoisAnalyzer",
                        "NEWLY_REGISTERED_DOMAIN",
                        "HIGH", 30, 0.88, "NEGATIVE",
                        f"Newly registered domain: {domain}",
                        f"The domain {domain} was registered only {age_days} day(s) ago. "
                        "Newly registered domains are frequently used in phishing campaigns "
                        "and have no established reputation.",
                    )
                    add_ev(
                        "URL_FINDINGS",
                        "WhoisAnalyzer",
                        "NEWLY_REGISTERED_DOMAIN",
                        "HIGH", 30, 0.88, "NEGATIVE",
                        f"Domain age: {age_days} day(s)",
                        f"{domain} was registered very recently with no prior history.",
                    )
                elif age_days is not None and age_days > 365:
                    add_ev(
                        "POSITIVE_EVIDENCE",
                        "WhoisAnalyzer",
                        "ESTABLISHED_DOMAIN",
                        "LOW", 8, 0.75, "POSITIVE",
                        f"Established domain: {domain}",
                        f"The domain {domain} has been registered for "
                        f"{age_days // 365} year(s), indicating an established presence.",
                    )

        # ================================================================
        # 4. CONTENT ANALYSIS
        # ================================================================
        content_status = content.get("analysis_status", "AVAILABLE")
        if content_status != "UNAVAILABLE":
            if content.get("credential_request"):
                add_ev(
                    "NEGATIVE_EVIDENCE",
                    "ContentAnalyzer",
                    "CREDENTIAL_HARVESTING",
                    "HIGH", 40, 0.85, "NEGATIVE",
                    "Credential harvesting language",
                    "The email contains language strongly associated with credential theft — "
                    "requesting usernames, passwords, or account details.",
                )
            if content.get("financial_request"):
                add_ev(
                    "NEGATIVE_EVIDENCE",
                    "ContentAnalyzer",
                    "FINANCIAL_REQUEST",
                    "MEDIUM", 30, 0.80, "NEGATIVE",
                    "Financial request detected",
                    "The email contains requests for payments, wire transfers, or financial data.",
                )
            if content.get("urgency"):
                add_ev(
                    "SUPPORTING_EVIDENCE",
                    "ContentAnalyzer",
                    "URGENCY",
                    "LOW", 10, 0.65, "NEUTRAL",
                    "Urgency language detected",
                    "The sender uses high-pressure language. Urgency alone is not sufficient "
                    "evidence of malicious intent without additional signals.",
                )
            if content.get("verification_request"):
                add_ev(
                    "SUPPORTING_EVIDENCE",
                    "ContentAnalyzer",
                    "VERIFICATION_REQUEST",
                    "INFO", 0, 0.90, "NEUTRAL",
                    "Verification language detected",
                    "The email asks the user to verify an account or identity. Verification "
                    "requests from authenticated senders with canonical domains are typically "
                    "legitimate — this alone does not indicate phishing.",
                )
        else:
            add_ev(
                "CONTEXT_LIMITATIONS",
                "ContentAnalyzer",
                "CONTENT_UNAVAILABLE",
                "INFO", 0, 0.5, "NEUTRAL",
                "Content analysis unavailable",
                "The content analyser could not process this message.",
            )

        # ================================================================
        # 5. ATTACHMENT ANALYSIS
        # ================================================================
        attachment_status = attachment.get("analysis_status", "AVAILABLE")
        if attachment_status != "UNAVAILABLE":
            attach_risk = attachment.get("risk_score", 0)
            attach_evidence = attachment.get("evidence") or []
            for ev_str in attach_evidence:
                ev_lower = str(ev_str).lower()
                if "executable" in ev_lower or "script" in ev_lower or "macro" in ev_lower:
                    add_ev(
                        "NEGATIVE_EVIDENCE",
                        "AttachmentAnalyzer",
                        "DANGEROUS_ATTACHMENT",
                        "CRITICAL", 60, 0.95, "NEGATIVE",
                        "Dangerous attachment type detected",
                        f"The email contains an attachment with a high-risk file type: {ev_str}. "
                        "Executable and script files are commonly used to deliver malware.",
                    )
                elif "suspicious" in ev_lower:
                    add_ev(
                        "NEGATIVE_EVIDENCE",
                        "AttachmentAnalyzer",
                        "SUSPICIOUS_ATTACHMENT",
                        "HIGH", 35, 0.85, "NEGATIVE",
                        "Suspicious attachment",
                        f"An attachment exhibits suspicious characteristics: {ev_str}",
                    )
            if attach_risk == 0 and not attach_evidence:
                add_ev(
                    "POSITIVE_EVIDENCE",
                    "AttachmentAnalyzer",
                    "CLEAN_ATTACHMENTS",
                    "LOW", 5, 0.80, "POSITIVE",
                    "No dangerous attachments detected",
                    "Attachment analysis produced no malicious indicators.",
                )

        # ================================================================
        # 6. TRUST ANALYSIS
        # ================================================================
        if trust.get("trusted") is True:
            add_ev(
                "POSITIVE_EVIDENCE",
                "TrustAnalyzer",
                "TRUSTED_SENDER",
                "MEDIUM", 25, 0.90, "POSITIVE",
                "Trusted sender history",
                "The sender domain has an established history of legitimate correspondence "
                "and has not been associated with previous threats.",
            )
        elif trust.get("trusted") is False and trust.get("risk_score", 0) > 20:
            add_ev(
                "NEGATIVE_EVIDENCE",
                "TrustAnalyzer",
                "UNTRUSTED_SENDER",
                "MEDIUM", 20, 0.80, "NEGATIVE",
                "Sender has no established trust history",
                "This sender has no prior positive history in this system.",
            )

        # ================================================================
        # 7. AI — BRAND INTELLIGENCE
        # ================================================================
        brand_list = ai.get("brand_intelligence") or []
        if isinstance(brand_list, list):
            for b in brand_list:
                if not isinstance(b, dict):
                    continue
                if b.get("impersonation_risk") or b.get("brand_mismatch"):
                    brand_name = b.get("brand") or b.get("brand_name") or "a known brand"
                    add_ev(
                        "NEGATIVE_EVIDENCE",
                        "BrandIntelligence",
                        "BRAND_IMPERSONATION",
                        "CRITICAL", 80, 0.95, "NEGATIVE",
                        f"Brand Impersonation — {brand_name}",
                        f"The message references {brand_name} but the destination domain is "
                        "not owned by or technically aligned with the canonical brand domain. "
                        "This is a strong indicator of a phishing attempt.",
                        {"brand": brand_name},
                    )
                    add_ev(
                        "BRAND_FINDINGS",
                        "BrandIntelligence",
                        "BRAND_IMPERSONATION",
                        "CRITICAL", 80, 0.95, "NEGATIVE",
                        f"Domain mismatch for {brand_name}",
                        "The visual brand representation does not match the technical infrastructure.",
                    )

        # ================================================================
        # 8. AI — HOMOGLYPH DETECTION
        # ================================================================
        homoglyph_list = ai.get("homoglyph") or []
        if isinstance(homoglyph_list, list) and homoglyph_list:
            add_ev(
                "NEGATIVE_EVIDENCE",
                "AdversarialAnalyzer",
                "HOMOGLYPH_DOMAIN",
                "HIGH", 60, 0.98, "NEGATIVE",
                "Visual Domain Deception (Homoglyph)",
                "The domain contains characters designed to visually resemble a legitimate "
                "organisation. This is a deliberate technique used in phishing attacks.",
            )
            add_ev(
                "BRAND_FINDINGS",
                "AdversarialAnalyzer",
                "HOMOGLYPH_DOMAIN",
                "HIGH", 60, 0.98, "NEGATIVE",
                "Homoglyph characters detected",
                "Unicode lookalike characters were found in the domain.",
            )

        # ================================================================
        # 9. AI — BEHAVIORAL ANALYSIS
        # ================================================================
        behavioral_list = ai.get("behavioral") or []
        if isinstance(behavioral_list, list) and behavioral_list:
            for b_item in behavioral_list:
                if not isinstance(b_item, dict):
                    continue
                b_type = str(b_item.get("type") or b_item.get("signal") or "anomaly").upper()
                if "BURST" in b_type or "RATE" in b_type:
                    add_ev(
                        "BEHAVIORAL_FINDINGS",
                        "BehavioralAnalyzer",
                        "SENDER_BURST",
                        "MEDIUM", 25, 0.80, "NEGATIVE",
                        "Unusual sending frequency",
                        "This sender has exhibited an abnormal sending rate inconsistent "
                        "with prior patterns.",
                    )
                elif "DOMAIN" in b_type or "SHIFT" in b_type:
                    add_ev(
                        "BEHAVIORAL_FINDINGS",
                        "BehavioralAnalyzer",
                        "BEHAVIORAL_SHIFT",
                        "MEDIUM", 25, 0.85, "NEGATIVE",
                        "Behavioral Shift",
                        "This sender previously used a consistent domain and authentication "
                        "pattern but this message introduces previously unseen infrastructure.",
                    )
                    add_ev(
                        "NEGATIVE_EVIDENCE",
                        "BehavioralAnalyzer",
                        "BEHAVIORAL_SHIFT",
                        "MEDIUM", 25, 0.85, "NEGATIVE",
                        "Sender behaviour changed",
                        "The observed sending pattern diverges significantly from historical norms.",
                    )
                elif "AUTH" in b_type:
                    add_ev(
                        "BEHAVIORAL_FINDINGS",
                        "BehavioralAnalyzer",
                        "AUTHENTICATION_DROP",
                        "MEDIUM", 20, 0.85, "NEGATIVE",
                        "Authentication drop detected",
                        "This sender previously sent with passing authentication but this "
                        "message shows degraded authentication results.",
                    )
                else:
                    add_ev(
                        "BEHAVIORAL_FINDINGS",
                        "BehavioralAnalyzer",
                        "BEHAVIORAL_ANOMALY",
                        "LOW", 15, 0.75, "NEGATIVE",
                        "Anomalous sending behaviour",
                        "A behavioural anomaly was detected compared to this sender's "
                        "historical patterns.",
                    )

        # ================================================================
        # 10. AI — CAMPAIGN DETECTION
        # ================================================================
        campaign_list = ai.get("campaign") or []
        if isinstance(campaign_list, list) and campaign_list:
            for c_item in campaign_list:
                if not isinstance(c_item, dict):
                    continue
                campaign_id = c_item.get("campaign_id") or c_item.get("id") or "Unknown"
                add_ev(
                    "BEHAVIORAL_FINDINGS",
                    "CampaignDetector",
                    "CAMPAIGN_MATCH",
                    "MEDIUM", 25, 0.88, "NEGATIVE",
                    f"Campaign Match — {campaign_id}",
                    f"This message shares subject patterns or URL infrastructure with "
                    f"previously observed phishing campaign {campaign_id}. "
                    f"Matched indicators: {c_item.get('matched_messages', 'N/A')} related messages.",
                    {"campaign_id": campaign_id},
                )
                add_ev(
                    "NEGATIVE_EVIDENCE",
                    "CampaignDetector",
                    "CAMPAIGN_MATCH",
                    "MEDIUM", 25, 0.88, "NEGATIVE",
                    "Campaign infrastructure match",
                    "This email was identified as part of a known phishing campaign.",
                )

        # ================================================================
        # 11. AI — SENDER REPUTATION
        # ================================================================
        sender_rep = ai.get("sender_reputation") or {}
        if isinstance(sender_rep, dict):
            rep_label = str(sender_rep.get("reputation_label") or "").upper()
            if rep_label in ("TRUSTED", "HIGH_TRUST"):
                add_ev(
                    "POSITIVE_EVIDENCE",
                    "SenderReputation",
                    "POSITIVE_SENDER_REPUTATION",
                    "LOW", 15, 0.85, "POSITIVE",
                    "Positive sender reputation",
                    "This sender has a strong historical reputation in the local intelligence store.",
                )
            elif rep_label in ("SUSPICIOUS", "MALICIOUS", "LOW_TRUST"):
                add_ev(
                    "NEGATIVE_EVIDENCE",
                    "SenderReputation",
                    "NEGATIVE_SENDER_REPUTATION",
                    "HIGH", 30, 0.88, "NEGATIVE",
                    "Negative sender reputation",
                    "This sender has a history of suspicious or malicious behaviour in the "
                    "local intelligence store.",
                )

        # ================================================================
        # 12. AI — CONTEXT QUALITY
        # ================================================================
        context_quality = ai.get("context_quality") or {}
        link_only = context_quality.get("link_only") or ai.get("link_only", False)
        limited_context = (
            context_quality.get("limited_context")
            or ai.get("limited_context", False)
            or detail_verdict in ("LIMITED_CONTEXT", "LINK_ONLY")
        )

        if link_only:
            add_ev(
                "CONTEXT_LIMITATIONS",
                "LocalAI",
                "LINK_ONLY",
                "INFO", 0, 0.90, "NEUTRAL",
                "Link-only email",
                "The email contains a link but provides insufficient surrounding information "
                "to establish sender intent. Limited context means this message cannot be "
                "verified as safe without external domain intelligence.",
            )
        elif limited_context:
            add_ev(
                "CONTEXT_LIMITATIONS",
                "LocalAI",
                "LIMITED_CONTEXT",
                "INFO", 0, 0.90, "NEUTRAL",
                "Limited Context",
                "The email provides insufficient context to confidently establish sender intent. "
                "Analysis is based on available technical signals only.",
            )

        if detail_verdict == "INSUFFICIENT_EVIDENCE":
            add_ev(
                "CONTEXT_LIMITATIONS",
                "DecisionFusionEngine",
                "INSUFFICIENT_EVIDENCE",
                "INFO", 0, 0.90, "NEUTRAL",
                "Insufficient evidence",
                "The available evidence is insufficient to verify sender intent. "
                "No strong positive or negative signals were produced.",
            )

        # ================================================================
        # 13. CONTRADICTIONS
        # ================================================================
        if conflict_state == "CONFLICTING_EVIDENCE":
            explanation["agreement"]["contradictory_sources"] += 1
            has_auth_pass = auth.get("spf") == "pass" and auth.get("dkim") == "pass"
            has_suspicious_url = any(e["type"] in ("SUSPICIOUS_URL", "BRAND_IMPERSONATION") for e in all_evidence)
            has_credential = any(e["type"] == "CREDENTIAL_HARVESTING" for e in all_evidence)
            is_trusted = trust.get("trusted") is True

            if has_auth_pass and has_suspicious_url:
                add_ev(
                    "CONTRADICTIONS",
                    "ContradictionEngine",
                    "AUTH_URL_CONFLICT",
                    "HIGH", 0, 0.90, "NEGATIVE",
                    "Authentication passed but URL is suspicious",
                    "Authentication evidence supports sender identity, but URL intelligence "
                    "provides independent evidence inconsistent with the claimed organisation. "
                    "Authentication success does NOT override malicious destination evidence — "
                    "these are independent security signals.",
                )
            if is_trusted and (has_suspicious_url or has_credential):
                add_ev(
                    "CONTRADICTIONS",
                    "ContradictionEngine",
                    "TRUST_HISTORY_CONFLICT",
                    "HIGH", 0, 0.90, "NEGATIVE",
                    "Trust history conflict — possible compromised sender",
                    "Historical sender trust conflicts with the current message behaviour. "
                    "This pattern may indicate the sender's account has been compromised or "
                    "is being abused. Trust history does not override current threat signals.",
                )
            if not (has_auth_pass and has_suspicious_url) and not (is_trusted and has_suspicious_url):
                add_ev(
                    "CONTRADICTIONS",
                    "ContradictionEngine",
                    "MIXED_SIGNALS",
                    "MEDIUM", 0, 0.80, "NEGATIVE",
                    "Contradictory intelligence signals",
                    "Different analysis components produced strongly opposing classifications. "
                    "The final verdict accounts for this uncertainty.",
                )

        # ================================================================
        # 14. ARE — STRUCTURED EVIDENCE
        # ================================================================
        are_technical = are_evidence.get("technical") or []
        are_behavioral = are_evidence.get("behavioral") or []
        are_network = are_evidence.get("network") or []

        for ev_str in are_technical:
            ev_lower = str(ev_str).lower()
            if "pass" in ev_lower or "valid" in ev_lower or "verified" in ev_lower:
                add_ev(
                    "SUPPORTING_EVIDENCE",
                    "AnalyticalReasoningEngine",
                    "TECHNICAL_POSITIVE",
                    "INFO", 5, 0.80, "POSITIVE",
                    ev_str,
                    "Technical signal from the Analytical Reasoning Engine.",
                )
            elif "fail" in ev_lower or "suspicious" in ev_lower or "malicious" in ev_lower or "risk" in ev_lower:
                add_ev(
                    "SUPPORTING_EVIDENCE",
                    "AnalyticalReasoningEngine",
                    "TECHNICAL_NEGATIVE",
                    "LOW", 10, 0.80, "NEGATIVE",
                    ev_str,
                    "Technical risk signal from the Analytical Reasoning Engine.",
                )

        for ev_str in are_behavioral:
            add_ev(
                "SUPPORTING_EVIDENCE",
                "AnalyticalReasoningEngine",
                "BEHAVIORAL_SIGNAL",
                "INFO", 5, 0.75, "NEUTRAL",
                ev_str,
                "Behavioural signal from the Analytical Reasoning Engine.",
            )

        for ev_str in are_network:
            ev_lower = str(ev_str).lower()
            if "suspicious" in ev_lower or "malicious" in ev_lower:
                add_ev(
                    "SUPPORTING_EVIDENCE",
                    "AnalyticalReasoningEngine",
                    "NETWORK_NEGATIVE",
                    "MEDIUM", 15, 0.82, "NEGATIVE",
                    ev_str,
                    "Network risk signal from the Analytical Reasoning Engine.",
                )
            elif "clean" in ev_lower or "safe" in ev_lower:
                add_ev(
                    "SUPPORTING_EVIDENCE",
                    "AnalyticalReasoningEngine",
                    "NETWORK_POSITIVE",
                    "INFO", 5, 0.80, "POSITIVE",
                    ev_str,
                    "Network safety signal from the Analytical Reasoning Engine.",
                )

        # ================================================================
        # 15. AGGREGATE COUNTS
        # ================================================================
        explanation["agreement"]["positive_sources"] = positive_count
        explanation["agreement"]["negative_sources"] = negative_count
        explanation["agreement"]["independent_sources"] = len(independent_sources)

        # ================================================================
        # 16. PRIMARY REASON — from existing evidence, not fabricated
        # ================================================================
        types_present = {e["type"] for e in all_evidence}

        if "BRAND_IMPERSONATION" in types_present:
            explanation["primary_reason"] = "Brand impersonation detected"
        elif "DANGEROUS_ATTACHMENT" in types_present:
            explanation["primary_reason"] = "Dangerous attachment detected"
        elif "CREDENTIAL_HARVESTING" in types_present:
            explanation["primary_reason"] = "Credential harvesting behaviour detected"
        elif "HOMOGLYPH_DOMAIN" in types_present:
            explanation["primary_reason"] = "Visual domain deception (homoglyph) detected"
        elif "CAMPAIGN_MATCH" in types_present:
            explanation["primary_reason"] = "Phishing campaign infrastructure detected"
        elif "SUSPICIOUS_URL" in types_present:
            explanation["primary_reason"] = "Suspicious destination URL detected"
        elif "NEWLY_REGISTERED_DOMAIN" in types_present:
            explanation["primary_reason"] = "Newly registered destination domain"
        elif "TRUST_HISTORY_CONFLICT" in types_present:
            explanation["primary_reason"] = "Trust history conflict — possible compromised sender"
        elif "BEHAVIORAL_SHIFT" in types_present:
            explanation["primary_reason"] = "Sender behavioural shift detected"
        elif "LINK_ONLY" in types_present:
            explanation["primary_reason"] = "Link-only email — limited context"
        elif "LIMITED_CONTEXT" in types_present:
            explanation["primary_reason"] = "Limited email context"
        elif "INSUFFICIENT_EVIDENCE" in types_present:
            explanation["primary_reason"] = "Insufficient evidence"
        elif verdict in ("VERIFIED LEGITIMATE", "LIKELY LEGITIMATE") and positive_count > 0:
            if "VERIFICATION_REQUEST" in types_present:
                explanation["primary_reason"] = (
                    "Verification language present — supported by strong authentication "
                    "and domain alignment"
                )
            else:
                explanation["primary_reason"] = "Strong sender authentication and domain alignment"
        elif verdict == "SAFE":
            explanation["primary_reason"] = "No significant threat signals detected"
        else:
            explanation["primary_reason"] = "Mixed or anomalous signals detected"

        # ================================================================
        # 17. CONFIDENCE EXPLANATION
        # ================================================================
        if confidence_pct >= 80:
            supporting = []
            if negative_count > 1:
                supporting.append("multiple independent negative indicators agree")
            if positive_count > 1:
                supporting.append("multiple positive authentication signals confirm the assessment")
            if "BRAND_IMPERSONATION" in types_present:
                supporting.append("brand intelligence confirms domain mismatch")
            if explanation["agreement"]["contradictory_sources"] == 0:
                supporting.append("no unresolved contradictions remain")
            explanation["confidence_explanation"] = (
                f"Confidence is high ({confidence_pct}%) because: "
                + "; ".join(supporting) + "."
                if supporting
                else f"Confidence is high ({confidence_pct}%) — multiple independent signals agree."
            )
        elif confidence_pct >= 50:
            explanation["confidence_explanation"] = (
                f"Confidence is moderate ({confidence_pct}%). Some indicators are present but "
                "the available evidence does not reach a definitive threshold."
            )
        else:
            limiting = []
            if "LIMITED_CONTEXT" in types_present or "LINK_ONLY" in types_present:
                limiting.append("email context is sparse")
            if "AUTHENTICATION_UNAVAILABLE" in types_present:
                limiting.append("authentication results are unavailable")
            if len(urls) <= 1:
                limiting.append("only one or no URLs are available for inspection")
            if "INSUFFICIENT_EVIDENCE" in types_present:
                limiting.append("independent reputation evidence is unavailable")
            explanation["confidence_explanation"] = (
                f"Confidence is low ({confidence_pct}%) because: "
                + "; ".join(limiting) + "."
                if limiting
                else f"Confidence is low ({confidence_pct}%) due to limited available evidence."
            )

        # ================================================================
        # 18. FINAL REASON — based on existing verdict, never recalculated
        # ================================================================
        if verdict in ("PHISHING", "HIGH RISK"):
            if "BRAND_IMPERSONATION" in types_present and "CREDENTIAL_HARVESTING" in types_present:
                explanation["final_reason"] = (
                    "Multiple independent indicators support a high-risk classification, "
                    "including brand impersonation, credential harvesting behaviour, and "
                    "destination-domain mismatch. These signals were independently verified "
                    "by multiple analysis components."
                )
            elif "BRAND_IMPERSONATION" in types_present:
                explanation["final_reason"] = (
                    "Brand impersonation was independently confirmed by technical domain analysis. "
                    "The message claims association with a known organisation but uses unrelated infrastructure."
                )
            elif "SUSPICIOUS_URL" in types_present:
                explanation["final_reason"] = (
                    "URL threat intelligence identified high-risk destination infrastructure. "
                    "Multiple independent indicators support a high-risk classification."
                )
            else:
                explanation["final_reason"] = (
                    "Multiple independent indicators support a high-risk classification. "
                    "The accumulated evidence from deterministic analysis exceeds the "
                    "threshold for a high-risk verdict."
                )
        elif verdict in ("VERIFIED LEGITIMATE", "LIKELY LEGITIMATE"):
            if "VERIFICATION_REQUEST" in types_present:
                explanation["final_reason"] = (
                    "Verification language was detected, but independent authentication and "
                    "domain-alignment evidence supports legitimacy. Verification requests from "
                    "authenticated senders with canonical domains are typically legitimate. "
                    "The presence of verification language alone does not constitute evidence "
                    "of malicious intent."
                )
            else:
                explanation["final_reason"] = (
                    "Multiple independent authentication and domain-alignment signals support "
                    "a legitimate classification. The message passed cryptographic authentication "
                    "and all inspected URLs align with the claimed sender infrastructure."
                )
        elif verdict == "SUSPICIOUS":
            explanation["final_reason"] = (
                "The message exhibits characteristics that warrant caution. While definitive "
                "proof of malicious intent was not established, multiple anomalous signals "
                "were identified that deviate from trusted sender patterns."
            )
        elif verdict == "UNKNOWN":
            if "LINK_ONLY" in types_present or "LIMITED_CONTEXT" in types_present:
                explanation["final_reason"] = (
                    "The available evidence is insufficient to establish legitimacy or malicious "
                    "intent. The email contains limited context and should not be treated as "
                    "verified safe. More context is required for a definitive assessment."
                )
            elif "INSUFFICIENT_EVIDENCE" in types_present:
                explanation["final_reason"] = (
                    "Insufficient independent evidence was available to reach a confident verdict. "
                    "The message should be treated with caution until additional context is available."
                )
            elif explanation["agreement"]["contradictory_sources"] > 0:
                explanation["final_reason"] = (
                    "Conflicting intelligence signals prevented a definitive verdict. "
                    "Some indicators support legitimacy while others indicate risk — "
                    "the contradiction could not be resolved without additional evidence."
                )
            else:
                explanation["final_reason"] = (
                    "The available evidence is insufficient to establish legitimacy or malicious "
                    "intent. This message should not be treated as verified safe."
                )
        else:
            explanation["final_reason"] = (
                "The message exhibits anomalies requiring caution, but lacks definitive "
                "proof of malicious intent. Proceed with care."
            )

        # Final safety check: ensure we never return a decision modification
        # (This method returns only explanation — callers must never pass our output back as decision)
        return explanation
