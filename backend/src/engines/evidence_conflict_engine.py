# ============================================================
# backend/src/engines/evidence_conflict_engine.py
# ============================================================

from __future__ import annotations

from typing import Any, Dict, List


class EvidenceConflictEngine:
    """
    Builds structured evidence and identifies contradictions between
    deterministic analysis, Local AI, page intelligence, trust history,
    and historical verdict evidence.

    IMPORTANT:
    This engine does NOT calculate the final verdict.
    It produces evidence/state for:

        EvidenceConflictEngine
                    ↓
                   ARE
                    ↓
          DecisionFusionEngine
                    ↓
      DecisionConsistencyValidator
                    ↓
              FINAL VERDICT
    """

    CRITICAL_TYPES = {
        "CREDENTIAL_HARVESTING",
        "MALICIOUS_URL",
        "KNOWN_MALICIOUS_URL",
        "MALICIOUS_REDIRECT",
        "BRAND_IMPERSONATION",
        "EXECUTABLE_ATTACHMENT",
        "SCRIPT_ATTACHMENT",
        "MALICIOUS_ATTACHMENT",
        "PRIVATE_IP_DESTINATION",
    }

    STRONG_TYPES = {
        "DOMAIN_MISMATCH",
        "URL_DOMAIN_MISMATCH",
        "SUSPICIOUS_URL",
        "SUSPICIOUS_REDIRECT",
        "HOMOGRAPH_DOMAIN",
        "PUNYCODE_DOMAIN",
        "HOSTNAME_MISMATCH",
        "CREDENTIAL_REQUEST",
        "FINANCIAL_REQUEST",
        "AUTHENTICATION_FAILURE",
        "AUTHENTICATION_DRIFT",
        "DOMAIN_DRIFT",
        "URL_BEHAVIOR_DRIFT",
        "CAMPAIGN_ANOMALY",
        "TRUST_HISTORY_CONFLICT",
        "ADVERSARIAL_INDICATOR",
        "NEW_DOMAIN",
    }

    CONTRADICTION_TYPES = {
        "CONFLICTING_EVIDENCE",
        "HISTORICAL_CURRENT_CONFLICT",
        "TRUST_HISTORY_CONFLICT",
        "AI_IGNORED_DUE_TO_MALICE",
        "AI_LEGITIMACY_CONFLICT",
    }

    POSITIVE_TYPES = {
        "AUTHENTICATION_PASS",
        "DOMAIN_ALIGNMENT",
        "URL_ALIGNMENT",
        "OFFICIAL_BRAND",
        "TRUSTED_DOMAIN",
        "TRUSTED_SENDER",
        "VALID_HISTORICAL_EVIDENCE",
        "NORMAL_BEHAVIOR",
        "VALID_TLS",
    }

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
        url_page_intelligence: dict = None,
        historical_evidence: dict = None,
    ) -> dict:

        parsed_email = parsed_email or {}
        auth_analysis = auth_analysis or {}
        url_analysis = url_analysis or {}
        whois_analysis = whois_analysis or []
        content_analysis = content_analysis or {}
        attachment_analysis = attachment_analysis or {}
        trust_analysis = trust_analysis or {}
        ai_analysis = ai_analysis or {}
        url_page_intelligence = url_page_intelligence or {}
        historical_evidence = historical_evidence or {}

        evidence_list: List[Dict[str, Any]] = []
        contradictions: List[str] = []

        # ========================================================
        # 1. AUTHENTICATION
        # ========================================================

        auth_state = self._authentication_state(
            auth_analysis
        )

        if auth_state == "PASSED":

            evidence_list.append(
                self._evidence(
                    type_="AUTHENTICATION_PASS",
                    signal="auth_checks",
                    value="SPF + DKIM + DMARC passed",
                    direction="POSITIVE",
                    severity="LOW",
                    source="AuthenticationAnalyzer",
                    explanation=(
                        "SPF, DKIM and DMARC all passed."
                    ),
                    confidence=0.96,
                )
            )

        elif auth_state == "FAILED":

            evidence_list.append(
                self._evidence(
                    type_="AUTHENTICATION_FAILURE",
                    signal="auth_checks",
                    value="one_or_more_failed",
                    direction="NEGATIVE",
                    severity="HIGH",
                    source="AuthenticationAnalyzer",
                    explanation=(
                        "One or more sender authentication checks failed."
                    ),
                    confidence=0.95,
                )
            )

        elif auth_state == "PARTIAL":

            evidence_list.append(
                self._evidence(
                    type_="AUTHENTICATION_PARTIAL",
                    signal="auth_checks",
                    value="partial",
                    direction="NEUTRAL",
                    severity="LOW",
                    source="AuthenticationAnalyzer",
                    explanation=(
                        "Authentication evidence is incomplete."
                    ),
                    confidence=0.70,
                )
            )

        else:

            evidence_list.append(
                self._evidence(
                    type_="AUTHENTICATION_UNAVAILABLE",
                    signal="auth_checks",
                    value="unavailable",
                    direction="NEUTRAL",
                    severity="LOW",
                    source="AuthenticationAnalyzer",
                    explanation=(
                        "Authentication analysis is unavailable."
                    ),
                    confidence=0.0,
                )
            )

        spf_pass = self._auth_value(
            auth_analysis,
            "spf",
            "spf_result",
        ) == "pass"

        dkim_pass = self._auth_value(
            auth_analysis,
            "dkim",
            "dkim_result",
        ) == "pass"

        dmarc_pass = self._auth_value(
            auth_analysis,
            "dmarc",
            "dmarc_result",
        ) == "pass"

        auth_all_pass = (
            spf_pass
            and dkim_pass
            and dmarc_pass
        )

        # ========================================================
        # 2. URL + BRAND + ALIGNMENT
        # ========================================================

        url_items = (
            url_analysis.get(
                "analysis",
                [],
            )
            or []
        )

        has_urls = bool(url_items)

        has_impersonation = False
        has_unrelated_domain = False
        has_official_brand = False
        has_malicious_url = False
        has_suspicious_url = False
        has_tls_violation = False
        has_http_warning = False

        for url_item in url_items:

            if not isinstance(
                url_item,
                dict,
            ):
                continue

            brand_relationship = str(
                url_item.get(
                    "brand_relationship",
                    "",
                )
            ).upper()

            alignment = str(
                url_item.get(
                    "alignment",
                    url_item.get(
                        "email_alignment",
                        "unknown",
                    ),
                )
            ).lower()

            # -----------------------------------------------
            # Brand relationship
            # -----------------------------------------------

            if (
                brand_relationship
                in {
                    "IMPERSONATION",
                    "BRAND_IMPERSONATION",
                }
                or url_item.get(
                    "brand_impersonation"
                )
            ):

                has_impersonation = True

                evidence_list.append(
                    self._evidence(
                        type_="BRAND_IMPERSONATION",
                        signal="brand_relationship",
                        value="impersonation",
                        direction="NEGATIVE",
                        severity="CRITICAL",
                        source="BrandIntelligence",
                        explanation=(
                            "The URL appears to impersonate a legitimate brand."
                        ),
                        confidence=0.95,
                    )
                )

            elif brand_relationship == "OFFICIAL":

                has_official_brand = True

                evidence_list.append(
                    self._evidence(
                        type_="OFFICIAL_BRAND",
                        signal="brand_relationship",
                        value="official",
                        direction="POSITIVE",
                        severity="LOW",
                        source="BrandIntelligence",
                        explanation=(
                            "The URL domain matches a recognized official brand domain."
                        ),
                        confidence=0.95,
                    )
                )

            # -----------------------------------------------
            # Alignment
            # -----------------------------------------------

            if alignment == "misaligned":

                has_unrelated_domain = True

                evidence_list.append(
                    self._evidence(
                        type_="DOMAIN_MISMATCH",
                        signal="alignment",
                        value="misaligned",
                        direction="NEGATIVE",
                        severity="HIGH",
                        source="URLAnalyzer",
                        explanation=(
                            "The destination domain is not aligned with the sender."
                        ),
                        confidence=0.90,
                    )
                )

            elif alignment == "aligned":

                evidence_list.append(
                    self._evidence(
                        type_="DOMAIN_ALIGNMENT",
                        signal="alignment",
                        value="aligned",
                        direction="POSITIVE",
                        severity="LOW",
                        source="URLAnalyzer",
                        explanation=(
                            "The destination domain is aligned with the sender."
                        ),
                        confidence=0.90,
                    )
                )

            # -----------------------------------------------
            # Legacy / current URL indicators
            # -----------------------------------------------

            if url_item.get(
                "ip_based"
            ):

                has_suspicious_url = True

                evidence_list.append(
                    self._evidence(
                        type_="SUSPICIOUS_URL",
                        signal="ip_based_url",
                        value=True,
                        direction="NEGATIVE",
                        severity="HIGH",
                        source="URLAnalyzer",
                        explanation=(
                            "The URL uses an IP address instead of a domain."
                        ),
                        confidence=0.90,
                    )
                )

            if url_item.get(
                "shortener"
            ):

                has_suspicious_url = True

                evidence_list.append(
                    self._evidence(
                        type_="SUSPICIOUS_URL",
                        signal="url_shortener",
                        value=True,
                        direction="NEGATIVE",
                        severity="MEDIUM",
                        source="URLAnalyzer",
                        explanation=(
                            "The URL uses a URL-shortening service."
                        ),
                        confidence=0.80,
                    )
                )

            if url_item.get(
                "obfuscated"
            ):

                has_suspicious_url = True

                evidence_list.append(
                    self._evidence(
                        type_="SUSPICIOUS_URL",
                        signal="obfuscated_url",
                        value=True,
                        direction="NEGATIVE",
                        severity="HIGH",
                        source="URLAnalyzer",
                        explanation=(
                            "The URL contains obfuscation indicators."
                        ),
                        confidence=0.90,
                    )
                )

            if url_item.get(
                "punycode"
            ):

                has_suspicious_url = True

                evidence_list.append(
                    self._evidence(
                        type_="PUNYCODE_DOMAIN",
                        signal="punycode",
                        value=True,
                        direction="NEGATIVE",
                        severity="HIGH",
                        source="URLAnalyzer",
                        explanation=(
                            "The destination domain uses Punycode."
                        ),
                        confidence=0.90,
                    )
                )

            if url_item.get(
                "suspicious_port"
            ):

                has_suspicious_url = True

                evidence_list.append(
                    self._evidence(
                        type_="SUSPICIOUS_URL",
                        signal="suspicious_port",
                        value=True,
                        direction="NEGATIVE",
                        severity="MEDIUM",
                        source="URLAnalyzer",
                        explanation=(
                            "The URL uses a suspicious network port."
                        ),
                        confidence=0.85,
                    )
                )

            if (
                url_item.get(
                    "threat_intelligence",
                    {},
                )
                or {}
            ).get(
                "detections",
                0,
            ) > 0:

                has_malicious_url = True

                evidence_list.append(
                    self._evidence(
                        type_="KNOWN_MALICIOUS_URL",
                        signal="threat_intelligence",
                        value=True,
                        direction="NEGATIVE",
                        severity="CRITICAL",
                        source="ThreatIntelligence",
                        explanation=(
                            "The URL has malicious threat-intelligence detections."
                        ),
                        confidence=0.99,
                    )
                )

            # -----------------------------------------------
            # Redirect intelligence
            # -----------------------------------------------

            redirects = (
                url_item.get(
                    "redirects",
                    {},
                )
                or {}
            )

            if redirects.get(
                "external_domain_change"
            ):

                has_suspicious_url = True

                evidence_list.append(
                    self._evidence(
                        type_="SUSPICIOUS_REDIRECT",
                        signal="external_domain_change",
                        value=True,
                        direction="NEGATIVE",
                        severity="HIGH",
                        source="URLInspector",
                        explanation=(
                            "The URL redirects to another external domain."
                        ),
                        confidence=0.90,
                    )
                )

            # -----------------------------------------------
            # TLS
            # -----------------------------------------------

            tls = (
                url_item.get(
                    "tls",
                    {},
                )
                or {}
            )

            if url_item.get(
                "tls_policy_violation"
            ):

                has_tls_violation = True

                severity = str(
                    tls.get(
                        "severity",
                        "MEDIUM",
                    )
                ).upper()

                evidence_list.append(
                    self._evidence(
                        type_="TLS_POLICY_VIOLATION",
                        signal="tls_policy",
                        value=tls.get(
                            "violation",
                            "UNKNOWN",
                        ),
                        direction="NEGATIVE",
                        severity=severity,
                        source="TLSInspector",
                        explanation=(
                            tls.get(
                                "error_detail",
                                "TLS policy violation detected.",
                            )
                        ),
                        confidence=0.90,
                    )
                )

            if url_item.get(
                "http_policy_warning"
            ):

                has_http_warning = True

                evidence_list.append(
                    self._evidence(
                        type_="HTTP_POLICY_WARNING",
                        signal="transport",
                        value="http",
                        direction="NEGATIVE",
                        severity="LOW",
                        source="TLSInspector",
                        explanation=(
                            "The destination uses plain HTTP without TLS."
                        ),
                        confidence=0.90,
                    )
                )

        # Explicit empty URL state
        if not has_urls:

            evidence_list.append(
                self._evidence(
                    type_="NO_URLS",
                    signal="presence",
                    value="none",
                    direction="NEUTRAL",
                    severity="INFO",
                    source="URLAnalyzer",
                    explanation=(
                        "No URLs were found in the message."
                    ),
                    confidence=1.0,
                )
            )

        # ========================================================
        # 3. CONTENT ANALYSIS
        # ========================================================

        content_risk = self._number(
            content_analysis.get(
                "risk_score",
                0,
            ),
            0,
        )

        if (
            content_analysis.get(
                "credential_request"
            )
            or content_analysis.get(
                "financial_request"
            )
            or content_analysis.get(
                "impersonation"
            )
            or content_analysis.get(
                "threat_language"
            )
            or content_analysis.get(
                "urgency"
            )
        ):

            if content_analysis.get(
                "credential_request"
            ):

                evidence_list.append(
                    self._evidence(
                        type_="CREDENTIAL_REQUEST",
                        signal="content",
                        value=True,
                        direction="NEGATIVE",
                        severity="HIGH",
                        source="ContentAnalyzer",
                        explanation=(
                            "The email contains credential/account request language."
                        ),
                        confidence=0.85,
                    )
                )

            if content_analysis.get(
                "financial_request"
            ):

                evidence_list.append(
                    self._evidence(
                        type_="FINANCIAL_REQUEST",
                        signal="content",
                        value=True,
                        direction="NEGATIVE",
                        severity="HIGH",
                        source="ContentAnalyzer",
                        explanation=(
                            "The email contains financial request language."
                        ),
                        confidence=0.85,
                    )
                )

            if content_analysis.get(
                "impersonation"
            ):

                evidence_list.append(
                    self._evidence(
                        type_="BRAND_IMPERSONATION",
                        signal="content",
                        value=True,
                        direction="NEGATIVE",
                        severity="HIGH",
                        source="ContentAnalyzer",
                        explanation=(
                            "Content analysis detected possible impersonation."
                        ),
                        confidence=0.85,
                    )
                )

            if content_analysis.get(
                "threat_language"
            ):

                evidence_list.append(
                    self._evidence(
                        type_="THREAT_LANGUAGE",
                        signal="content",
                        value=True,
                        direction="NEGATIVE",
                        severity="MEDIUM",
                        source="ContentAnalyzer",
                        explanation=(
                            "Threat language was detected in the message."
                        ),
                        confidence=0.80,
                    )
                )

            if content_analysis.get(
                "urgency"
            ):

                evidence_list.append(
                    self._evidence(
                        type_="URGENCY_LANGUAGE",
                        signal="content",
                        value=True,
                        direction="NEGATIVE",
                        severity="MEDIUM",
                        source="ContentAnalyzer",
                        explanation=(
                            "Urgency language was detected in the message."
                        ),
                        confidence=0.80,
                    )
                )

        elif content_risk <= 0:

            body = str(
                parsed_email.get(
                    "body",
                    "",
                )
                or ""
            )

            if len(
                body.split()
            ) >= 5:

                evidence_list.append(
                    self._evidence(
                        type_="CONTENT_NEUTRAL",
                        signal="risk_score",
                        value=0,
                        direction="NEUTRAL",
                        severity="INFO",
                        source="ContentAnalyzer",
                        explanation=(
                            "No significant content-risk indicators were detected."
                        ),
                        confidence=0.70,
                    )
                )

            else:

                evidence_list.append(
                    self._evidence(
                        type_="INSUFFICIENT_CONTENT",
                        signal="context",
                        value="sparse",
                        direction="NEUTRAL",
                        severity="LOW",
                        source="ContentAnalyzer",
                        explanation=(
                            "The email contains limited textual context."
                        ),
                        confidence=0.60,
                    )
                )

        # ========================================================
        # 4. ATTACHMENTS
        # ========================================================

        attachment_items = (
            attachment_analysis.get(
                "evidence",
                [],
            )
            or []
        )

        attachment_risk = self._number(
            attachment_analysis.get(
                "risk_score",
                0,
            ),
            0,
        )

        for raw in attachment_items:

            text = str(raw)
            lowered = text.lower()

            if (
                "executable attachment"
                in lowered
            ):

                evidence_list.append(
                    self._evidence(
                        type_="EXECUTABLE_ATTACHMENT",
                        signal="attachment",
                        value=text,
                        direction="NEGATIVE",
                        severity="CRITICAL",
                        source="AttachmentAnalyzer",
                        explanation=text,
                        confidence=0.98,
                    )
                )

            elif (
                "script attachment"
                in lowered
            ):

                evidence_list.append(
                    self._evidence(
                        type_="SCRIPT_ATTACHMENT",
                        signal="attachment",
                        value=text,
                        direction="NEGATIVE",
                        severity="CRITICAL",
                        source="AttachmentAnalyzer",
                        explanation=text,
                        confidence=0.97,
                    )
                )

            elif (
                "macro-enabled"
                in lowered
            ):

                evidence_list.append(
                    self._evidence(
                        type_="MACRO_ATTACHMENT",
                        signal="attachment",
                        value=text,
                        direction="NEGATIVE",
                        severity="HIGH",
                        source="AttachmentAnalyzer",
                        explanation=text,
                        confidence=0.95,
                    )
                )

        if (
            attachment_risk > 0
            and not attachment_items
        ):

            evidence_list.append(
                self._evidence(
                    type_="SUSPICIOUS_ATTACHMENT",
                    signal="attachment_risk",
                    value=attachment_risk,
                    direction="NEGATIVE",
                    severity="HIGH"
                    if attachment_risk >= 30
                    else "MEDIUM",
                    source="AttachmentAnalyzer",
                    explanation=(
                        "Attachment analysis produced a "
                        "non-zero security risk."
                    ),
                    confidence=0.85,
                )
            )

        # ========================================================
        # 5. TRUST ANALYSIS
        # ========================================================

        trust_score = self._number(
            trust_analysis.get(
                "trust_score",
                0,
            ),
            0,
        )

        reputation = str(
            trust_analysis.get(
                "reputation",
                trust_analysis.get(
                    "status",
                    "",
                ),
            )
        ).upper()

        if (
            auth_all_pass
            and trust_score >= 40
        ):

            evidence_list.append(
                self._evidence(
                    type_="TRUSTED_SENDER",
                    signal="trust_score",
                    value=trust_score,
                    direction="POSITIVE",
                    severity="LOW",
                    source="TrustAnalyzer",
                    explanation=(
                        "Sender has strong authentication and "
                        "an established positive trust signal."
                    ),
                    confidence=0.90,
                )
            )

        elif reputation in {
            "SUSPICIOUS",
            "HIGH_RISK",
        }:

            evidence_list.append(
                self._evidence(
                    type_="SUSPICIOUS_HISTORY",
                    signal="reputation",
                    value=reputation,
                    direction="NEGATIVE",
                    severity="HIGH",
                    source="TrustAnalyzer",
                    explanation=(
                        "Sender reputation is suspicious or high risk."
                    ),
                    confidence=0.85,
                )
            )

        # ========================================================
        # 6. WHOIS
        # ========================================================

        for whois in whois_analysis:

            if not isinstance(
                whois,
                dict,
            ):
                continue

            domain = whois.get(
                "domain",
                "Unknown",
            )

            if whois.get(
                "error"
            ):

                evidence_list.append(
                    self._evidence(
                        type_="WHOIS_UNAVAILABLE",
                        signal="whois",
                        value=domain,
                        direction="NEUTRAL",
                        severity="LOW",
                        source="WhoisAnalyzer",
                        explanation=(
                            f"WHOIS lookup was unavailable for {domain}."
                        ),
                        confidence=0.0,
                    )
                )

                continue

            age_category = str(
                whois.get(
                    "age_category",
                    "",
                )
            ).lower()

            if age_category == "new":

                evidence_list.append(
                    self._evidence(
                        type_="NEW_DOMAIN",
                        signal="domain_age",
                        value=domain,
                        direction="NEGATIVE",
                        severity="MEDIUM",
                        source="WhoisAnalyzer",
                        explanation=(
                            f"Domain {domain} appears newly registered."
                        ),
                        confidence=0.80,
                    )
                )

            elif age_category == "recent":

                evidence_list.append(
                    self._evidence(
                        type_="RECENT_DOMAIN",
                        signal="domain_age",
                        value=domain,
                        direction="NEGATIVE",
                        severity="LOW",
                        source="WhoisAnalyzer",
                        explanation=(
                            f"Domain {domain} appears recently registered."
                        ),
                        confidence=0.75,
                    )
                )

        # ========================================================
        # 7. LINK-ONLY / LIMITED CONTEXT
        # ========================================================

        body = str(
            parsed_email.get(
                "body",
                "",
            )
            or ""
        )

        body_word_count = len(
            body.split()
        )

        existing_link_only = bool(
            content_analysis.get(
                "link_only"
            )
            or url_analysis.get(
                "link_only"
            )
            or url_analysis.get(
                "limited_context"
            )
        )

        is_link_only = (
            existing_link_only
            or (
                has_urls
                and body_word_count <= 5
            )
        )

        is_empty = (
            body_word_count == 0
            and not has_urls
        )

        sender = (
            parsed_email.get(
                "from",
                "",
            )
            or parsed_email.get(
                "sender",
                "",
            )
            or ""
        ).strip()

        # ========================================================
        # 8. DEEP PAGE INTELLIGENCE
        # ========================================================

        page_has_credential_form = False
        page_has_malicious_intent = False
        page_has_brand_mismatch = False

        for url, page_data in (
            url_page_intelligence.items()
            if isinstance(
                url_page_intelligence,
                dict,
            )
            else []
        ):

            if not isinstance(
                page_data,
                dict,
            ):
                continue

            forms = (
                page_data.get(
                    "forms",
                    {},
                )
                or {}
            )

            password_fields = self._number(
                forms.get(
                    "password_fields",
                    0,
                ),
                0,
            )

            email_fields = self._number(
                forms.get(
                    "email_fields",
                    0,
                ),
                0,
            )

            if password_fields > 0:

                page_has_credential_form = True

                evidence_list.append(
                    self._evidence(
                        type_="CREDENTIAL_HARVESTING",
                        signal="password_form",
                        value=url,
                        direction="NEGATIVE",
                        severity="CRITICAL",
                        source="URLPageInspection",
                        explanation=(
                            "Destination page contains a password input."
                        ),
                        confidence=0.95,
                    )
                )

            elif email_fields > 0:

                evidence_list.append(
                    self._evidence(
                        type_="CREDENTIAL_FORM",
                        signal="email_form",
                        value=url,
                        direction="NEGATIVE",
                        severity="HIGH",
                        source="URLPageInspection",
                        explanation=(
                            "Destination page contains an email/login input."
                        ),
                        confidence=0.90,
                    )
                )

            page_ai = (
                page_data.get(
                    "ai",
                    {},
                )
                or {}
            )

            page_intent = str(
                page_ai.get(
                    "intent",
                    "",
                )
            ).upper()

            if page_intent in {
                "CREDENTIAL_HARVESTING",
                "PAYMENT_SCAM",
                "MALWARE_DISTRIBUTION",
                "TECH_SUPPORT_SCAM",
            }:

                page_has_malicious_intent = True

                evidence_list.append(
                    self._evidence(
                        type_=page_intent,
                        signal="page_intent",
                        value=url,
                        direction="NEGATIVE",
                        severity="CRITICAL",
                        source="LocalAI",
                        explanation=(
                            f"Destination page intent classified as "
                            f"{page_intent}."
                        ),
                        confidence=self._number(
                            page_ai.get(
                                "confidence",
                                0,
                            ),
                            0,
                        ),
                    )
                )

            page_brand = (
                page_data.get(
                    "brand",
                    {},
                )
                or {}
            )

            if (
                page_brand.get(
                    "domain_match"
                )
                is False
            ):

                page_has_brand_mismatch = True

                evidence_list.append(
                    self._evidence(
                        type_="DOMAIN_MISMATCH",
                        signal="page_brand_alignment",
                        value=url,
                        direction="NEGATIVE",
                        severity="HIGH",
                        source="URLPageInspection",
                        explanation=(
                            "Page brand identity does not match "
                            "the destination domain."
                        ),
                        confidence=0.90,
                    )
                )

        # ========================================================
        # 9. AI CONTRADICTIONS
        # ========================================================

        ai_recommendation = str(
            ai_analysis.get(
                "recommended_classification",
                "",
            )
        ).upper()

        ai_state = str(
            ai_analysis.get(
                "reasoning_state",
                "",
            )
        ).upper()

        if (
            ai_state
            in {
                "CONFLICTING_EVIDENCE",
                "LINK_ONLY",
                "LIMITED_CONTEXT",
                "INSUFFICIENT_EVIDENCE",
            }
        ):

            evidence_list.append(
                self._evidence(
                    type_=ai_state
                    if ai_state != "LINK_ONLY"
                    else "LIMITED_CONTEXT",
                    signal="ai_state",
                    value=ai_state,
                    direction="NEUTRAL",
                    severity="MEDIUM",
                    source="LocalAI",
                    explanation=(
                        f"Local AI reported reasoning state: {ai_state}."
                    ),
                    confidence=self._number(
                        ai_analysis.get(
                            "confidence",
                            0,
                        ),
                        0,
                    ),
                )
            )

        # AI says legitimate but deterministic malicious
        # evidence exists.
        if (
            ai_recommendation
            in {
                "SAFE",
                "LEGITIMATE",
                "LIKELY_LEGITIMATE",
                "VERIFIED_LEGITIMATE",
            }
            and (
                has_impersonation
                or has_malicious_url
                or page_has_credential_form
                or page_has_malicious_intent
            )
        ):

            contradiction = (
                "AI recommends a legitimate classification, "
                "but deterministic malicious evidence is present."
            )

            contradictions.append(
                contradiction
            )

            evidence_list.append(
                self._evidence(
                    type_="AI_IGNORED_DUE_TO_MALICE",
                    signal="ai_vs_deterministic",
                    value=ai_recommendation,
                    direction="NEUTRAL",
                    severity="HIGH",
                    source="EvidenceConflictEngine",
                    explanation=contradiction,
                    confidence=0.95,
                    reasoning_state="CONFLICTING_EVIDENCE",
                )
            )

        # AI says phishing while there is effectively no
        # meaningful malicious evidence.
        meaningful_negative = [
            item
            for item in evidence_list
            if (
                item.get(
                    "direction"
                ) == "NEGATIVE"
                and item.get(
                    "severity"
                )
                in {
                    "MEDIUM",
                    "HIGH",
                    "CRITICAL",
                }
            )
        ]

        if (
            ai_recommendation == "PHISHING"
            and not meaningful_negative
        ):

            contradiction = (
                "AI recommends phishing, but no meaningful "
                "deterministic malicious evidence is present."
            )

            contradictions.append(
                contradiction
            )

            evidence_list.append(
                self._evidence(
                    type_="AI_LEGITIMACY_CONFLICT",
                    signal="ai_vs_deterministic",
                    value="unsupported_phishing",
                    direction="NEUTRAL",
                    severity="MEDIUM",
                    source="EvidenceConflictEngine",
                    explanation=contradiction,
                    confidence=0.90,
                    reasoning_state="CONFLICTING_EVIDENCE",
                )
            )

        # ========================================================
        # 10. AUTHENTICATION + URL CONTRADICTIONS
        # ========================================================

        if auth_all_pass:

            if (
                has_impersonation
            ):

                contradiction = (
                    "Sender authentication passed, "
                    "but brand impersonation was detected."
                )

                contradictions.append(
                    contradiction
                )

                evidence_list.append(
                    self._evidence(
                        type_="CONFLICTING_EVIDENCE",
                        signal="auth_vs_brand",
                        value=contradiction,
                        direction="NEUTRAL",
                        severity="HIGH",
                        source="EvidenceConflictEngine",
                        explanation=contradiction,
                        confidence=0.95,
                        reasoning_state="CONFLICTING_EVIDENCE",
                    )
                )

            if (
                has_unrelated_domain
                and (
                    content_risk > 0
                    or page_has_credential_form
                    or page_has_malicious_intent
                )
            ):

                contradiction = (
                    "Sender authentication passed, "
                    "but the destination domain is misaligned "
                    "and additional suspicious evidence exists."
                )

                contradictions.append(
                    contradiction
                )

                evidence_list.append(
                    self._evidence(
                        type_="CONFLICTING_EVIDENCE",
                        signal="auth_vs_url",
                        value=contradiction,
                        direction="NEUTRAL",
                        severity="HIGH",
                        source="EvidenceConflictEngine",
                        explanation=contradiction,
                        confidence=0.95,
                        reasoning_state="CONFLICTING_EVIDENCE",
                    )
                )

        # ========================================================
        # 11. TRUSTED SENDER + CURRENT MALICIOUS EVIDENCE
        # ========================================================

        is_trusted_sender = (
            auth_all_pass
            and self._number(
                trust_analysis.get(
                    "trust_score",
                    0,
                ),
                0,
            ) >= 40
        )

        if (
            is_trusted_sender
            and (
                has_impersonation
                or has_malicious_url
                or page_has_credential_form
                or page_has_malicious_intent
            )
        ):

            contradiction = (
                "Historical or authentication trust conflicts "
                "with current malicious evidence; possible sender compromise."
            )

            contradictions.append(
                contradiction
            )

            evidence_list.append(
                self._evidence(
                    type_="TRUST_HISTORY_CONFLICT",
                    signal="trusted_sender_vs_current_risk",
                    value=contradiction,
                    direction="NEUTRAL",
                    severity="HIGH",
                    source="EvidenceConflictEngine",
                    explanation=contradiction,
                    confidence=0.95,
                    reasoning_state="TRUST_HISTORY_CONFLICT",
                )
            )

        # ========================================================
        # 12. HISTORICAL EVIDENCE
        # ========================================================

        historical_status = str(
            historical_evidence.get(
                "status",
                "",
            )
        ).upper()

        if (
            historical_status
            == "VALID_HISTORICAL_EVIDENCE"
        ):

            historical_record = (
                historical_evidence.get(
                    "record",
                    {},
                )
                or {}
            )

            freshness = self._number(
                (
                    historical_record.get(
                        "history_state",
                        {},
                    )
                    or {}
                ).get(
                    "freshness",
                    0,
                ),
                0,
            )

            evidence_list.append(
                self._evidence(
                    type_="VALID_HISTORICAL_EVIDENCE",
                    signal="historical_verdict",
                    value=(
                        historical_record.get(
                            "historical",
                            {},
                        )
                        or {}
                    ).get(
                        "verdict",
                        "UNKNOWN",
                    ),
                    direction="POSITIVE",
                    severity="LOW",
                    source="VerdictStore",
                    explanation=(
                        "Historical positive evidence is available "
                        f"with freshness {freshness:.2f}."
                    ),
                    confidence=max(
                        0.0,
                        min(
                            1.0,
                            freshness,
                        ),
                    ),
                )
            )

        elif (
            historical_status
            == "STALE_HISTORICAL_EVIDENCE"
        ):

            evidence_list.append(
                self._evidence(
                    type_="STALE_HISTORICAL_EVIDENCE",
                    signal="historical_verdict",
                    value="stale",
                    direction="NEUTRAL",
                    severity="INFO",
                    source="VerdictStore",
                    explanation=(
                        "Historical evidence is retained for audit "
                        "but is not used as current decision evidence."
                    ),
                    confidence=0.0,
                )
            )

        # ========================================================
        # 13. FINAL CONFLICT STATE
        # ========================================================

        # Remove duplicate contradiction messages.
        contradictions = list(
            dict.fromkeys(
                contradictions
            )
        )

        has_critical = any(
            item.get(
                "severity"
            ) == "CRITICAL"
            and item.get(
                "direction"
            ) == "NEGATIVE"
            for item in evidence_list
        )

        has_strong = any(
            (
                item.get(
                    "severity"
                )
                in {
                    "HIGH",
                    "CRITICAL",
                }
            )
            and item.get(
                "direction"
            ) == "NEGATIVE"
            for item in evidence_list
        )

        # State classification is explanatory only.
        # Final risk/verdict belongs to ARE/Fusion.
        if has_critical:
            state = "MALICIOUS_EVIDENCE"

        elif contradictions:
            state = "CONFLICTING_EVIDENCE"

        elif is_empty:
            state = "INSUFFICIENT_EVIDENCE"

        elif is_link_only:
            state = "LIMITED_CONTEXT"

        elif auth_all_pass and has_official_brand and not has_strong:
            state = "CONSISTENT_LEGITIMATE"

        else:
            state = "UNKNOWN"

        # AI can provide a context limitation only when
        # stronger deterministic contradictions do not exist.
        if (
            state == "UNKNOWN"
            and ai_state
            in {
                "LIMITED_CONTEXT",
                "LINK_ONLY",
                "INSUFFICIENT_EVIDENCE",
            }
        ):
            state = (
                "LIMITED_CONTEXT"
                if ai_state == "LINK_ONLY"
                else ai_state
            )

        # ========================================================
        # 14. Return
        # ========================================================

        return {
            "conflict_state": state,
            "structured_evidence": evidence_list,
            "contradictions": contradictions,
            "has_critical_evidence": has_critical,
            "has_strong_evidence": has_strong,
            "has_urls": has_urls,
            "has_impersonation": has_impersonation,
            "has_unrelated_domain": has_unrelated_domain,
            "has_official_brand": has_official_brand,
            "has_malicious_url": has_malicious_url,
            "has_tls_violation": has_tls_violation,
            "has_http_warning": has_http_warning,
            "has_page_credential_form": page_has_credential_form,
            "has_malicious_page_intent": page_has_malicious_intent,
            "is_link_only": is_link_only,
            "is_empty": is_empty,
            "is_trusted_sender": is_trusted_sender,
            "authentication_state": auth_state,
        }

    # ========================================================
    # Helpers
    # ========================================================

    @staticmethod
    def _auth_value(
        auth_analysis: dict,
        primary: str,
        fallback: str,
    ) -> str:

        value = auth_analysis.get(
            primary,
            auth_analysis.get(
                fallback,
                "",
            ),
        )

        return str(
            value or ""
        ).strip().lower()

    @staticmethod
    def _authentication_state(
        auth_analysis: dict,
    ) -> str:

        if not auth_analysis:
            return "UNAVAILABLE"

        status = str(
            auth_analysis.get(
                "analysis_status",
                "AVAILABLE",
            )
        ).upper()

        if status == "UNAVAILABLE":
            return "UNAVAILABLE"

        spf = EvidenceConflictEngine._auth_value(
            auth_analysis,
            "spf",
            "spf_result",
        )

        dkim = EvidenceConflictEngine._auth_value(
            auth_analysis,
            "dkim",
            "dkim_result",
        )

        dmarc = EvidenceConflictEngine._auth_value(
            auth_analysis,
            "dmarc",
            "dmarc_result",
        )

        if (
            spf == "pass"
            and dkim == "pass"
            and dmarc == "pass"
        ):
            return "PASSED"

        if (
            spf == "fail"
            or dkim == "fail"
            or dmarc == "fail"
        ):
            return "FAILED"

        if (
            spf
            or dkim
            or dmarc
        ):
            return "PARTIAL"

        return "UNAVAILABLE"

    @staticmethod
    def _number(
        value: Any,
        fallback: float = 0.0,
    ) -> float:

        try:
            return float(value)
        except (
            TypeError,
            ValueError,
        ):
            return fallback

    @staticmethod
    def _evidence(
        type_: str,
        signal: str,
        value: Any,
        direction: str,
        severity: str,
        source: str,
        explanation: str,
        confidence: float = 0.0,
        reasoning_state: str = "",
    ) -> Dict[str, Any]:

        direction = str(
            direction
        ).upper()

        if direction in {
            "BENIGN",
            "POSITIVE",
        }:
            direction = "POSITIVE"

        elif direction in {
            "MALICIOUS",
            "NEGATIVE",
        }:
            direction = "NEGATIVE"

        else:
            direction = "NEUTRAL"

        severity = str(
            severity
        ).upper()

        if severity not in {
            "INFO",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }:
            severity = "INFO"

        return {
            "type": str(
                type_
            ).strip().upper().replace(
                "-",
                "_",
            ).replace(
                " ",
                "_",
            ),
            "signal": signal,
            "value": value,
            "direction": direction,
            "severity": severity,
            "source": source,
            "explanation": explanation,
            "confidence": max(
                0.0,
                min(
                    1.0,
                    EvidenceConflictEngine._number(
                        confidence,
                        0.0,
                    ),
                ),
            ),
            "reasoning_state": (
                reasoning_state
                if reasoning_state
                else None
            ),
        }