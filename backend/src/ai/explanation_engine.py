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
        parsed = parsed_email if isinstance(parsed_email, dict) else {}

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
                    "Sender identity verified",
                    "We confirmed this email really came from who it says it's from. "
                    "Three separate security checks all passed — the sender is genuine.",
                )
                add_ev(
                    "POSITIVE_EVIDENCE",
                    "AuthenticationAnalyzer",
                    "AUTHENTICATION_PASS",
                    "LOW", 15, 0.96, "POSITIVE",
                    "All security checks passed",
                    "The email passed all three standard email security checks. "
                    "This means it wasn't faked or tampered with on the way to you.",
                )
                add_ev(
                    "AUTHENTICATION_FINDINGS",
                    "AuthenticationAnalyzer",
                    "AUTHENTICATION_PASS",
                    "LOW", 15, 0.96, "POSITIVE",
                    "All security checks passed",
                    "The email passed all three standard email security checks. "
                    "This means it wasn't faked or tampered with on the way to you.",
                )
            else:
                if not spf_pass:
                    add_ev(
                        "NEGATIVE_EVIDENCE",
                        "AuthenticationAnalyzer",
                        "SPF_FAIL",
                        "MEDIUM", 20, 0.90, "NEGATIVE",
                        "Sender identity check failed",
                        "The computer that sent this email is not allowed to send on behalf of this address. "
                        "Someone may be pretending to be this sender.",
                    )
                    add_ev(
                        "AUTHENTICATION_FINDINGS",
                        "AuthenticationAnalyzer",
                        "SPF_FAIL",
                        "MEDIUM", 20, 0.90, "NEGATIVE",
                        "Sender identity check failed",
                        "The sender couldn't prove they are who they claim to be.",
                    )
                if not dkim_pass:
                    add_ev(
                        "NEGATIVE_EVIDENCE",
                        "AuthenticationAnalyzer",
                        "DKIM_FAIL",
                        "MEDIUM", 20, 0.90, "NEGATIVE",
                        "Email may have been tampered with",
                        "This email failed a check that verifies it wasn't changed after it was sent. "
                        "Someone may have altered its contents.",
                    )
                    add_ev(
                        "AUTHENTICATION_FINDINGS",
                        "AuthenticationAnalyzer",
                        "DKIM_FAIL",
                        "MEDIUM", 20, 0.90, "NEGATIVE",
                        "Email may have been tampered with",
                        "We couldn't confirm the email arrived unchanged from the sender.",
                    )
                if not dmarc_pass:
                    add_ev(
                        "NEGATIVE_EVIDENCE",
                        "AuthenticationAnalyzer",
                        "DMARC_FAIL",
                        "MEDIUM", 15, 0.85, "NEGATIVE",
                        "Sender's security rules were broken",
                        "The company that owns this email address has rules about how their emails should be sent. "
                        "This email broke those rules, which is a warning sign.",
                    )
                    add_ev(
                        "AUTHENTICATION_FINDINGS",
                        "AuthenticationAnalyzer",
                        "DMARC_FAIL",
                        "MEDIUM", 15, 0.85, "NEGATIVE",
                        "Sender's security rules were broken",
                        "This email didn't follow the sender's own security rules.",
                    )
        else:
            add_ev(
                "CONTEXT_LIMITATIONS",
                "AuthenticationAnalyzer",
                "AUTHENTICATION_UNAVAILABLE",
                "INFO", 0, 0.5, "NEUTRAL",
                "Could not check sender identity",
                "We were unable to run security checks to verify who sent this email.",
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
                        "Dangerous link detected",
                        f"A link in this email leads to a website that looks dangerous: "
                        f"{u.get('domain', 'unknown')}. "
                        "Clicking it could put your account or personal information at risk.",
                        {"domain": u.get("domain", ""), "url": u.get("url", "")},
                    )
                    add_ev(
                        "URL_FINDINGS",
                        "URLAnalyzer",
                        "SUSPICIOUS_URL",
                        "HIGH", 35, 0.91, "NEGATIVE",
                        f"Dangerous website: {u.get('domain', 'unknown')}",
                        "This link doesn't go where the sender claims — it leads somewhere unrelated and risky.",
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
                    "All links are safe",
                    f"We checked all {safe_urls} link(s) in this email. "
                    "None of them lead to harmful or suspicious websites.",
                )
                add_ev(
                    "POSITIVE_EVIDENCE",
                    "URLAnalyzer",
                    "SAFE_URLS",
                    "LOW", 10, 0.80, "POSITIVE",
                    "Links checked and safe",
                    "Every link in this email was checked and found to be safe.",
                )
                add_ev(
                    "URL_FINDINGS",
                    "URLAnalyzer",
                    "SAFE_URLS",
                    "LOW", 10, 0.80, "POSITIVE",
                    "Links checked and safe",
                    "Every link in this email was checked and found to be safe.",
                )
        elif url_analysis.get("risk_score", 0) == 0 and not urls:
            # No URLs in the email at all
            add_ev(
                "CONTEXT_LIMITATIONS",
                "URLAnalyzer",
                "NO_URLS",
                "INFO", 0, 0.9, "NEUTRAL",
                "No links in this email",
                "This email contains no clickable links, so there's nothing to check.",
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
                        f"Brand new website: {domain}",
                        f"The website {domain} was only created {age_days} day(s) ago. "
                        "Scammers often create brand new websites just before sending fake emails "
                        "because they have no bad history yet.",
                    )
                    add_ev(
                        "URL_FINDINGS",
                        "WhoisAnalyzer",
                        "NEWLY_REGISTERED_DOMAIN",
                        "HIGH", 30, 0.88, "NEGATIVE",
                        f"Website is only {age_days} day(s) old",
                        f"{domain} was just created and has no history — a common sign of a scam site.",
                    )
                elif age_days is not None and age_days > 365:
                    add_ev(
                        "POSITIVE_EVIDENCE",
                        "WhoisAnalyzer",
                        "ESTABLISHED_DOMAIN",
                        "LOW", 8, 0.75, "POSITIVE",
                        f"Long-established website: {domain}",
                        f"The website {domain} has existed for "
                        f"{age_days // 365} year(s). Old, established websites are less likely to be scams.",
                    )

        # ================================================================
        # 4. CONTENT ANALYSIS
        # ================================================================
        content_status = content.get("analysis_status", "AVAILABLE")
        if content_status != "UNAVAILABLE":
            if content.get("impersonation"):
                # Extract specific brand and domain details to present concrete evidence
                brand_mentions = content.get("brand_mentions") or []
                org_rels = content.get("organization_relationships") or []
                sender_field = parsed_email.get("sender") if isinstance(parsed_email, dict) else {}
                sender_dict = sender_field if isinstance(sender_field, dict) else {}
                sender_domain = content.get("sender_domain") or sender_dict.get("domain") or ""
                if not sender_domain and isinstance(parsed_email, dict):
                    sender_val = sender_dict.get("email") or parsed_email.get("from") or (sender_field if isinstance(sender_field, str) else "")
                    if "@" in str(sender_val):
                        sender_domain = str(sender_val).split("@")[-1].rstrip(">").strip()

                unmatched_rel = next((r for r in org_rels if isinstance(r, dict) and not r.get("legitimate")), None)
                claimed_org = ""
                mismatched_url = ""
                if unmatched_rel:
                    claimed_org = str(unmatched_rel.get("organization", "")).title()
                    mismatched_url = unmatched_rel.get("url_domain", "")
                    sender_domain = sender_domain or unmatched_rel.get("sender_domain", "")
                elif brand_mentions:
                    claimed_org = str(brand_mentions[0]).title()

                ca_expl = ""
                for sev in content.get("structured_evidence", []):
                    if isinstance(sev, dict) and sev.get("type") == "BRAND_IMPERSONATION" and sev.get("explanation"):
                        ca_expl = sev.get("explanation")
                        break

                if claimed_org and sender_domain:
                    title_1 = f"Brand impersonation: {claimed_org}"
                    exp_1 = (
                        f"The message references or claims association with {claimed_org}, "
                        f"but originated from '{sender_domain}', which is not an authorized sender domain for {claimed_org}."
                    )
                    title_2 = f"Sender mismatch for {claimed_org}"
                    exp_2 = f"Sending domain '{sender_domain}' does not match official infrastructure for {claimed_org}."
                elif ca_expl:
                    title_1 = "Possible brand impersonation detected"
                    exp_1 = ca_expl
                    title_2 = "Potential brand impersonation"
                    exp_2 = "The message claims association with an organization inconsistent with the sending domain."
                else:
                    title_1 = "Possible brand impersonation detected"
                    exp_1 = (
                        "Content analysis identified indicators of brand or sender impersonation. "
                        "The message claims association with an organization or authority "
                        "inconsistent with the sending domain."
                    )
                    title_2 = "Potential brand impersonation"
                    exp_2 = "The message exhibits characteristics of brand impersonation or spoofing."

                ev_meta = {
                    "claimed_brand": claimed_org,
                    "sender_domain": sender_domain,
                    "mismatched_url": mismatched_url,
                    "issue": exp_1,
                }

                add_ev(
                    "NEGATIVE_EVIDENCE",
                    "ContentAnalyzer",
                    "BRAND_IMPERSONATION",
                    "CRITICAL", 80, 0.95, "NEGATIVE",
                    title_1,
                    exp_1,
                    ev_meta,
                )
                add_ev(
                    "NEGATIVE_EVIDENCE",
                    "BrandIntelligence",
                    "BRAND_IMPERSONATION",
                    "HIGH", 75, 0.90, "NEGATIVE",
                    title_2,
                    exp_2,
                    ev_meta,
                )
                add_ev(
                    "BRAND_FINDINGS",
                    "BrandIntelligence",
                    "BRAND_IMPERSONATION",
                    "HIGH", 75, 0.90, "NEGATIVE",
                    title_2,
                    exp_2,
                    ev_meta,
                )
            if content.get("credential_request"):
                add_ev(
                    "NEGATIVE_EVIDENCE",
                    "ContentAnalyzer",
                    "CREDENTIAL_HARVESTING",
                    "HIGH", 40, 0.85, "NEGATIVE",
                    "Asking for your password or login details",
                    "This email is asking for your username, password, or account information. "
                    "Genuine companies never ask for your password by email.",
                )
            if content.get("financial_request"):
                add_ev(
                    "NEGATIVE_EVIDENCE",
                    "ContentAnalyzer",
                    "FINANCIAL_REQUEST",
                    "MEDIUM", 30, 0.80, "NEGATIVE",
                    "Asking for money or payment",
                    "This email is asking you to send money, make a payment, or share your bank details. Be very careful.",
                )
            if content.get("urgency"):
                add_ev(
                    "SUPPORTING_EVIDENCE",
                    "ContentAnalyzer",
                    "URGENCY",
                    "LOW", 10, 0.65, "NEUTRAL",
                    "Creating a sense of urgency",
                    "This email is trying to make you act quickly or feel panicked. "
                    "Scammers do this to stop you thinking carefully. Slow down before clicking anything.",
                )
            if content.get("verification_request"):
                add_ev(
                    "SUPPORTING_EVIDENCE",
                    "ContentAnalyzer",
                    "VERIFICATION_REQUEST",
                    "INFO", 0, 0.90, "NEUTRAL",
                    "Asking you to verify your account",
                    "This email asks you to confirm or verify your account. "
                    "On its own, this is not necessarily dangerous — many real companies do this. "
                    "Check the other signals to decide if this is genuine.",
                )
        else:
            add_ev(
                "CONTEXT_LIMITATIONS",
                "ContentAnalyzer",
                "CONTENT_UNAVAILABLE",
                "INFO", 0, 0.5, "NEUTRAL",
                "Could not read email content",
                "We were unable to read the text of this email to check for warning signs.",
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
                        "Dangerous file attached",
                        f"This email has a file attached that can run programs on your computer: {ev_str}. "
                        "These types of files are commonly used by hackers to install viruses. Do not open it.",
                    )
                elif "suspicious" in ev_lower:
                    add_ev(
                        "NEGATIVE_EVIDENCE",
                        "AttachmentAnalyzer",
                        "SUSPICIOUS_ATTACHMENT",
                        "HIGH", 35, 0.85, "NEGATIVE",
                        "Suspicious file attached",
                        f"The attached file looks unusual and may be harmful: {ev_str}",
                    )
            if attach_risk == 0 and not attach_evidence:
                add_ev(
                    "POSITIVE_EVIDENCE",
                    "AttachmentAnalyzer",
                    "CLEAN_ATTACHMENTS",
                    "LOW", 5, 0.80, "POSITIVE",
                    "No dangerous files attached",
                    "We scanned all attachments and found nothing harmful.",
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
                "Sender is known and trusted",
                "We've seen emails from this sender before and they've always been safe. "
                "This is a good sign.",
            )
        elif trust.get("trusted") is False and trust.get("risk_score", 0) > 20:
            add_ev(
                "NEGATIVE_EVIDENCE",
                "TrustAnalyzer",
                "UNTRUSTED_SENDER",
                "MEDIUM", 20, 0.80, "NEGATIVE",
                "Sender is unknown to us",
                "We have no previous history with this sender. Be extra careful with this email.",
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
                        f"Pretending to be {brand_name}",
                        f"This email claims to be from {brand_name}, but it was actually sent from "
                        "a completely different and unrelated website. This is a classic scam trick.",
                        {"brand": brand_name},
                    )
                    add_ev(
                        "BRAND_FINDINGS",
                        "BrandIntelligence",
                        "BRAND_IMPERSONATION",
                        "CRITICAL", 80, 0.95, "NEGATIVE",
                        f"Fake {brand_name} email",
                        "The email looks like it's from a well-known company, but the website behind it is not theirs.",
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
                "Fake look-alike website address",
                "The website address in this email uses letters that look almost identical to a real company's address, "
                "but are subtly different. For example, using a zero '0' instead of the letter 'O'. This is a trick scammers use.",
            )
            add_ev(
                "BRAND_FINDINGS",
                "AdversarialAnalyzer",
                "HOMOGLYPH_DOMAIN",
                "HIGH", 60, 0.98, "NEGATIVE",
                "Fake look-alike website address",
                "The web address is designed to visually trick you into thinking it's from a real company.",
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
                        "Sending a lot of emails very quickly",
                        "This sender is sending emails much faster than usual. "
                        "Scammers often send huge numbers of emails all at once.",
                    )
                elif "DOMAIN" in b_type or "SHIFT" in b_type:
                    add_ev(
                        "BEHAVIORAL_FINDINGS",
                        "BehavioralAnalyzer",
                        "BEHAVIORAL_SHIFT",
                        "MEDIUM", 25, 0.85, "NEGATIVE",
                        "Sender is acting differently than before",
                        "This sender used to send emails in a consistent way, but this email "
                        "comes from a different place than their previous messages. That's unusual.",
                    )
                    add_ev(
                        "NEGATIVE_EVIDENCE",
                        "BehavioralAnalyzer",
                        "BEHAVIORAL_SHIFT",
                        "MEDIUM", 25, 0.85, "NEGATIVE",
                        "Sender is acting differently than before",
                        "This email doesn't match how this sender normally sends emails.",
                    )
                elif "AUTH" in b_type:
                    add_ev(
                        "BEHAVIORAL_FINDINGS",
                        "BehavioralAnalyzer",
                        "AUTHENTICATION_DROP",
                        "MEDIUM", 20, 0.85, "NEGATIVE",
                        "Security checks suddenly failing for this sender",
                        "This sender's emails used to pass security checks, but this one doesn't. "
                        "Their account may have been hacked.",
                    )
                else:
                    add_ev(
                        "BEHAVIORAL_FINDINGS",
                        "BehavioralAnalyzer",
                        "BEHAVIORAL_ANOMALY",
                        "LOW", 15, 0.75, "NEGATIVE",
                        "Something unusual about this sender",
                        "This email is different from what we'd normally expect from this sender.",
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
                    f"Part of a known scam wave",
                    f"This email looks almost identical to other scam emails we've already seen "
                    f"(Group: {campaign_id}). "
                    f"About {c_item.get('matched_messages', 'N/A')} similar scam emails were spotted recently.",
                    {"campaign_id": campaign_id},
                )
                add_ev(
                    "NEGATIVE_EVIDENCE",
                    "CampaignDetector",
                    "CAMPAIGN_MATCH",
                    "MEDIUM", 25, 0.88, "NEGATIVE",
                    "Part of a known scam wave",
                    "This email matches a pattern of scam emails that have already been reported.",
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
                    "Sender has a good reputation",
                    "This sender has a track record of sending safe, legitimate emails.",
                )
            elif rep_label in ("SUSPICIOUS", "MALICIOUS", "LOW_TRUST"):
                add_ev(
                    "NEGATIVE_EVIDENCE",
                    "SenderReputation",
                    "NEGATIVE_SENDER_REPUTATION",
                    "HIGH", 30, 0.88, "NEGATIVE",
                    "Sender has a bad reputation",
                    "This sender has previously sent suspicious or harmful emails. "
                    "Be very careful with this message.",
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
                "Email is just a link with no explanation",
                "This email only contains a link and barely any text. "
                "We can't fully judge it without more information. Don't click the link unless you're 100% sure who sent it.",
            )
        elif limited_context:
            add_ev(
                "CONTEXT_LIMITATIONS",
                "LocalAI",
                "LIMITED_CONTEXT",
                "INFO", 0, 0.90, "NEUTRAL",
                "Not enough information to be certain",
                "This email doesn't give us enough information to say for sure whether it's safe. "
                "Use extra caution.",
            )

        if detail_verdict == "INSUFFICIENT_EVIDENCE":
            add_ev(
                "CONTEXT_LIMITATIONS",
                "DecisionFusionEngine",
                "INSUFFICIENT_EVIDENCE",
                "INFO", 0, 0.90, "NEUTRAL",
                "Not enough clues to decide",
                "We didn't find enough information in this email to give a strong verdict either way. "
                "Treat it with caution.",
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
                    "HIGH", 0, 0.90, "NEUTRAL",
                    "Sender identity checks out, but links are dangerous",
                    "The email appears to be genuinely from who it claims — but the links inside "
                    "lead to dangerous websites. A real sender's account may have been hacked, or "
                    "someone copied their style to trick you. Don't click the links.",
                )
            if is_trusted and (has_suspicious_url or has_credential):
                add_ev(
                    "CONTRADICTIONS",
                    "ContradictionEngine",
                    "TRUST_HISTORY_CONFLICT",
                    "HIGH", 0, 0.90, "NEUTRAL",
                    "Known sender, but something is very wrong",
                    "We've received safe emails from this sender before, but this one looks dangerous. "
                    "Their account may have been hacked. Do not click any links or share any information.",
                )
            if not (has_auth_pass and has_suspicious_url) and not (is_trusted and has_suspicious_url):
                add_ev(
                    "CONTRADICTIONS",
                    "ContradictionEngine",
                    "MIXED_SIGNALS",
                    "MEDIUM", 0, 0.80, "NEUTRAL",
                    "Mixed signals — we're not fully sure",
                    "Some checks say this email is fine, others say it could be risky. "
                    "We've taken that into account in the final verdict. Proceed carefully.",
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
                    "A technical check passed for this email.",
                )
            elif "fail" in ev_lower or "suspicious" in ev_lower or "malicious" in ev_lower or "risk" in ev_lower:
                add_ev(
                    "SUPPORTING_EVIDENCE",
                    "AnalyticalReasoningEngine",
                    "TECHNICAL_NEGATIVE",
                    "LOW", 10, 0.80, "NEGATIVE",
                    ev_str,
                    "A technical check flagged a potential problem with this email.",
                )

        for ev_str in are_behavioral:
            ev_lower = str(ev_str).lower()
            if "impersonation" in ev_lower:
                if not any(e["type"] == "BRAND_IMPERSONATION" for e in all_evidence):
                    add_ev(
                        "NEGATIVE_EVIDENCE",
                        "AnalyticalReasoningEngine",
                        "BRAND_IMPERSONATION",
                        "CRITICAL", 80, 0.90, "NEGATIVE",
                        "Someone may be pretending to be someone else",
                        "Our analysis found signs that this email is pretending to be from a well-known person or company.",
                    )
                    add_ev(
                        "BRAND_FINDINGS",
                        "AnalyticalReasoningEngine",
                        "BRAND_IMPERSONATION",
                        "CRITICAL", 80, 0.90, "NEGATIVE",
                        "Someone may be pretending to be someone else",
                        "This email shows signs of impersonating a real person or brand.",
                    )
            elif "credential" in ev_lower:
                if not any(e["type"] == "CREDENTIAL_HARVESTING" for e in all_evidence):
                    add_ev(
                        "NEGATIVE_EVIDENCE",
                        "AnalyticalReasoningEngine",
                        "CREDENTIAL_HARVESTING",
                        "HIGH", 40, 0.85, "NEGATIVE",
                        "Trying to steal your password or login details",
                        "This email appears to be trying to get you to hand over your login details.",
                    )
            else:
                add_ev(
                    "SUPPORTING_EVIDENCE",
                    "AnalyticalReasoningEngine",
                    "BEHAVIORAL_SIGNAL",
                    "INFO", 5, 0.75, "NEUTRAL",
                    ev_str,
                    "An additional behaviour pattern was noted during analysis.",
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
                    "A network check found something concerning about where this email came from.",
                )
            elif "clean" in ev_lower or "safe" in ev_lower:
                add_ev(
                    "SUPPORTING_EVIDENCE",
                    "AnalyticalReasoningEngine",
                    "NETWORK_POSITIVE",
                    "INFO", 5, 0.80, "POSITIVE",
                    ev_str,
                    "A network check came back clean for this email.",
                )

        # Check decision structured_evidence for any uncaught critical negative evidence
        decision_structured_ev = decision_snap.get("structured_evidence") or []
        for sev in decision_structured_ev:
            if not isinstance(sev, dict):
                continue
            s_type = str(sev.get("type", "")).upper()
            s_dir = str(sev.get("direction", "")).upper()
            s_sev = str(sev.get("severity", "HIGH")).upper()
            s_source = sev.get("source") or "AnalyticalReasoningEngine"
            s_exp = sev.get("explanation") or ""
            s_conf = float(sev.get("confidence", 0.85))

            if s_dir == "NEGATIVE" and s_type in ("BRAND_IMPERSONATION", "CREDENTIAL_HARVESTING", "MALICIOUS_URL", "DANGEROUS_ATTACHMENT"):
                if not any(e["type"] == s_type for e in all_evidence):
                    title = "Someone may be pretending to be someone else" if s_type == "BRAND_IMPERSONATION" else f"Warning: {s_type.replace('_', ' ').title()}"
                    add_ev(
                        "NEGATIVE_EVIDENCE",
                        s_source,
                        s_type,
                        s_sev, 80 if s_sev == "CRITICAL" else 40, s_conf, "NEGATIVE",
                        title,
                        s_exp or f"Our security scan detected a problem: {s_type.replace('_', ' ').lower()}.",
                    )
                    if s_type == "BRAND_IMPERSONATION" and not any(e["type"] == "BRAND_IMPERSONATION" for e in explanation["groups"]["BRAND_FINDINGS"]):
                        add_ev(
                            "BRAND_FINDINGS",
                            s_source,
                            s_type,
                            s_sev, 80, s_conf, "NEGATIVE",
                            "Fake company name or logo detected",
                            s_exp or "This email is using a real company's name or branding, but was not sent by them.",
                        )

        # ================================================================
        # 15. AGGREGATE COUNTS
        # ================================================================
        explanation["agreement"]["positive_sources"] = len(explanation["groups"]["POSITIVE_EVIDENCE"])
        explanation["agreement"]["negative_sources"] = len(explanation["groups"]["NEGATIVE_EVIDENCE"])
        explanation["agreement"]["independent_sources"] = len(independent_sources)

        # ================================================================
        # 16. PRIMARY REASON — from existing evidence, not fabricated
        # ================================================================
        types_present = {e["type"] for e in all_evidence}

        if "BRAND_IMPERSONATION" in types_present:
            explanation["primary_reason"] = "This email is pretending to be from a real company"
        elif "DANGEROUS_ATTACHMENT" in types_present:
            explanation["primary_reason"] = "This email has a dangerous file attached"
        elif "CREDENTIAL_HARVESTING" in types_present:
            explanation["primary_reason"] = "This email is trying to steal your password"
        elif "HOMOGLYPH_DOMAIN" in types_present:
            explanation["primary_reason"] = "The link uses a fake look-alike website address"
        elif "CAMPAIGN_MATCH" in types_present:
            explanation["primary_reason"] = "This email is part of a known scam campaign"
        elif "SUSPICIOUS_URL" in types_present:
            explanation["primary_reason"] = "This email contains a dangerous link"
        elif "NEWLY_REGISTERED_DOMAIN" in types_present:
            explanation["primary_reason"] = "The link goes to a brand new, untrusted website"
        elif "TRUST_HISTORY_CONFLICT" in types_present:
            explanation["primary_reason"] = "Known sender, but this email looks suspicious — account may be hacked"
        elif "BEHAVIORAL_SHIFT" in types_present:
            explanation["primary_reason"] = "This sender is acting differently than usual"
        elif "LINK_ONLY" in types_present:
            explanation["primary_reason"] = "This email is just a link — not enough info to be sure it's safe"
        elif "LIMITED_CONTEXT" in types_present:
            explanation["primary_reason"] = "Not enough information to make a confident decision"
        elif "INSUFFICIENT_EVIDENCE" in types_present:
            explanation["primary_reason"] = "Not enough clues to decide if this is safe or not"
        elif verdict in ("VERIFIED LEGITIMATE", "LIKELY LEGITIMATE") and positive_count > 0:
            if "VERIFICATION_REQUEST" in types_present:
                explanation["primary_reason"] = (
                    "Asking you to verify your account — but sender checks out and looks genuine"
                )
            else:
                explanation["primary_reason"] = "Sender identity verified and all checks passed"
        elif verdict == "SAFE":
            explanation["primary_reason"] = "No threats or warning signs found"
        else:
            explanation["primary_reason"] = "Some unusual signals found — proceed with caution"

        # ================================================================
        # 17. CONFIDENCE EXPLANATION
        # ================================================================
        if confidence_pct >= 80:
            supporting = []
            if negative_count > 1:
                supporting.append("multiple warning signs were found")
            if positive_count > 1:
                supporting.append("multiple safety checks all passed")
            if "BRAND_IMPERSONATION" in types_present:
                supporting.append("we confirmed the sender is not who they claim to be")
            if explanation["agreement"]["contradictory_sources"] == 0:
                supporting.append("all checks agree with each other")
            explanation["confidence_explanation"] = (
                f"We are very confident ({confidence_pct}%) in this result because: "
                + "; ".join(supporting) + "."
                if supporting
                else f"We are very confident ({confidence_pct}%) — multiple independent checks all agree."
            )
        elif confidence_pct >= 50:
            explanation["confidence_explanation"] = (
                f"We are fairly confident ({confidence_pct}%) in this result, "
                "but some checks were inconclusive. Use your own judgement too."
            )
        else:
            limiting = []
            if "LIMITED_CONTEXT" in types_present or "LINK_ONLY" in types_present:
                limiting.append("the email has very little text to analyse")
            if "AUTHENTICATION_UNAVAILABLE" in types_present:
                limiting.append("we couldn't verify who sent it")
            if len(urls) <= 1:
                limiting.append("there were few or no links to check")
            if "INSUFFICIENT_EVIDENCE" in types_present:
                limiting.append("we don't have enough information about this sender")
            explanation["confidence_explanation"] = (
                f"We are not very confident ({confidence_pct}%) in this result because: "
                + "; ".join(limiting) + "."
                if limiting
                else f"We are not very confident ({confidence_pct}%) — there wasn't enough information to be sure."
            )

        # ================================================================
        # 18. FINAL REASON — based on existing verdict, never recalculated
        # ================================================================
        if verdict in ("PHISHING", "HIGH RISK"):
            if "BRAND_IMPERSONATION" in types_present and "CREDENTIAL_HARVESTING" in types_present:
                explanation["final_reason"] = (
                    "This email is almost certainly a scam. It is pretending to be from a well-known company "
                    "and is trying to steal your password or personal information. "
                    "Do not click any links, do not reply, and do not enter any details."
                )
            elif "BRAND_IMPERSONATION" in types_present:
                explanation["final_reason"] = (
                    "This email is pretending to be from a real company, but was sent from a completely different "
                    "and unrelated website. This is a classic scam. Delete it and do not click anything."
                )
            elif "SUSPICIOUS_URL" in types_present:
                explanation["final_reason"] = (
                    "The links in this email lead to dangerous websites. Multiple checks flagged this email as high risk. "
                    "Do not click any links in this email."
                )
            else:
                explanation["final_reason"] = (
                    "Multiple warning signs were found in this email. "
                    "Our checks strongly suggest this is a scam or phishing attempt. "
                    "Do not click links, open files, or reply with personal information."
                )
        elif verdict in ("SAFE", "CLEAN", "VERIFIED LEGITIMATE", "LIKELY LEGITIMATE"):
            if "VERIFICATION_REQUEST" in types_present:
                explanation["final_reason"] = (
                    "This email asks you to verify your account, but we confirmed it really is from who it claims. "
                    "The sender passed all our security checks. It appears to be a genuine request."
                )
            else:
                explanation["final_reason"] = (
                    "This email passed all our safety checks. The sender is who they say they are, "
                    "and all the links lead to safe, expected websites. It appears to be a genuine email."
                )
        elif verdict == "SUSPICIOUS":
            explanation["final_reason"] = (
                "Something about this email looks unusual, but we can't say for certain it's a scam. "
                "Be careful — don't click links or share personal details unless you're 100% sure it's genuine."
            )
        elif verdict == "UNKNOWN":
            if "LINK_ONLY" in types_present or "LIMITED_CONTEXT" in types_present:
                explanation["final_reason"] = (
                    "This email doesn't give us enough information to say whether it's safe or not. "
                    "Don't click any links unless you know and trust the sender personally."
                )
            elif "INSUFFICIENT_EVIDENCE" in types_present:
                explanation["final_reason"] = (
                    "We couldn't find enough information to give a confident verdict. "
                    "Treat this email with caution until you can verify who sent it."
                )
            elif explanation["agreement"]["contradictory_sources"] > 0:
                explanation["final_reason"] = (
                    "Some checks say this email is fine, others say it could be risky. "
                    "We couldn't come to a clear conclusion. Be careful with this email."
                )
            else:
                explanation["final_reason"] = (
                    "We don't have enough information to confirm this email is safe. "
                    "Treat it with caution."
                )
        else:
            explanation["final_reason"] = (
                "This email has some unusual features. We recommend being careful "
                "and not clicking anything until you're sure it's genuine."
            )

        # Provide clean frontend-compatible fields
        explanation["summary"] = explanation.get("final_reason") or explanation.get("primary_reason") or ""
        explanation["positive_signals"] = [
            item.get("explanation") or item.get("title")
            for item in explanation["groups"].get("POSITIVE_EVIDENCE", [])
            if isinstance(item, dict)
        ]
        explanation["negative_signals"] = [
            item.get("explanation") or item.get("title")
            for item in (
                explanation["groups"].get("NEGATIVE_EVIDENCE", [])
                + explanation["groups"].get("SUPPORTING_EVIDENCE", [])
            )
            if isinstance(item, dict) and item.get("direction") == "NEGATIVE"
        ]

        # Final safety check: ensure we never return a decision modification
        # (This method returns only explanation — callers must never pass our output back as decision)
        return explanation
