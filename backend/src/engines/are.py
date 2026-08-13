# pyrefly: ignore [missing-import]
from src.config.scoring import SCORING


class AnalyticalReasoningEngine:
    """
    Evidence-first Analytical Reasoning Engine.

    Design principles:
    - Collect ALL available evidence before calculating the final verdict.
    - Risk score and confidence remain separate.
    - Historical evidence never overrides current evidence.
    - Authentication failure is distinct from authentication unavailability.
    - Structured evidence is preferred over string parsing.
    - Local AI contributes evidence but does not independently control the verdict.
    """

    TRUSTED_DOMAINS = [
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "accounts.google.com",
        "myaccount.google.com",
        "microsoft.com",
        "microsoftonline.com",
        "apple.com",
        "icloud.com",
        "paypal.com",
        "github.com",
        "linkedin.com",
        "amazon.com",
    ]

    CRITICAL_NEGATIVE_TYPES = {
        "CREDENTIAL_HARVESTING",
        "MALICIOUS_URL",
        "MALICIOUS_REDIRECT",
        "BRAND_IMPERSONATION",
        "MALICIOUS_ATTACHMENT",
        "EXECUTABLE_ATTACHMENT",
        "SCRIPT_ATTACHMENT",
        "MACRO_ATTACHMENT",
        "KNOWN_MALICIOUS_URL",
    }

    STRONG_NEGATIVE_TYPES = {
        "DOMAIN_MISMATCH",
        "URL_DOMAIN_MISMATCH",
        "SUSPICIOUS_URL",
        "SUSPICIOUS_REDIRECT",
        "HOMOGRAPH_DOMAIN",
        "PUNYCODE_DOMAIN",
        "HOSTNAME_MISMATCH",
        "TLS_POLICY_VIOLATION",
        "CREDENTIAL_REQUEST",
        "FINANCIAL_REQUEST",
        "AUTHENTICATION_DRIFT",
        "DOMAIN_DRIFT",
        "URL_BEHAVIOR_DRIFT",
        "CAMPAIGN_ANOMALY",
        "TRUST_HISTORY_CONFLICT",
    }

    def __init__(self):
        self.rules = SCORING

    # =========================================================
    # DOMAIN HELPERS
    # =========================================================

    def _is_trusted_domain(self, domain):
        domain = (domain or "").lower().strip(".")

        if not domain:
            return False

        for trusted in self.TRUSTED_DOMAINS:
            if domain == trusted or domain.endswith("." + trusted):
                return True

        return False

    def _is_trusted_url_domain(self, url_analysis, url_item):
        domain = url_item.get("domain", "")
        return self._is_trusted_domain(domain)

    # =========================================================
    # NORMALIZATION HELPERS
    # =========================================================

    @staticmethod
    def _safe_number(value, default=0):
        try:
            return float(value)
        except (TypeError, ValueError):
            return float(default)

    @staticmethod
    def _normalize_direction(value):
        value = str(value or "NEUTRAL").upper()

        if value not in {
            "POSITIVE",
            "NEGATIVE",
            "NEUTRAL",
        }:
            return "NEUTRAL"

        return value

    @staticmethod
    def _normalize_severity(value):
        value = str(value or "INFO").upper()

        if value not in {
            "INFO",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }:
            return "INFO"

        return value

    @staticmethod
    def _normalize_type(value):
        return (
            str(value or "UNKNOWN")
            .strip()
            .upper()
            .replace("-", "_")
            .replace(" ", "_")
        )

    def _structured_evidence(self, item):
        """
        Normalize both dictionaries and existing object-based evidence.
        """
        if isinstance(item, dict):
            return {
                "type": self._normalize_type(item.get("type")),
                "severity": self._normalize_severity(
                    item.get("severity")
                ),
                "direction": self._normalize_direction(
                    item.get("direction")
                ),
                "source": str(
                    item.get("source", "UNKNOWN")
                ),
                "explanation": str(
                    item.get("explanation", "")
                ),
                "confidence": self._safe_number(
                    item.get("confidence", 0),
                    0,
                ),
            }

        return {
            "type": self._normalize_type(
                getattr(item, "type", None)
            ),
            "severity": self._normalize_severity(
                getattr(item, "severity", None)
            ),
            "direction": self._normalize_direction(
                getattr(item, "direction", None)
            ),
            "source": str(
                getattr(item, "source", "UNKNOWN")
            ),
            "explanation": str(
                getattr(item, "explanation", "")
            ),
            "confidence": self._safe_number(
                getattr(item, "confidence", 0),
                0,
            ),
        }

    def _collect_structured_items(
        self,
        target,
        items,
        default_category="behavioral",
    ):
        for item in items or []:
            normalized = self._structured_evidence(item)

            target[default_category].append(
                normalized["explanation"]
                or normalized["type"]
            )

    # =========================================================
    # AUTHENTICATION STATE
    # =========================================================

    @staticmethod
    def _authentication_state(authentication):
        if not authentication:
            return "UNAVAILABLE"

        status = str(
            authentication.get(
                "analysis_status",
                "AVAILABLE",
            )
        ).upper()

        if status == "UNAVAILABLE":
            return "UNAVAILABLE"

        spf = str(
            authentication.get("spf", "")
        ).lower()

        dkim = str(
            authentication.get("dkim", "")
        ).lower()

        dmarc = str(
            authentication.get("dmarc", "")
        ).lower()

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
            spf in {"", "unknown", "none"}
            and dkim in {"", "unknown", "none"}
            and dmarc in {"", "unknown", "none"}
        ):
            return "UNAVAILABLE"

        return "PARTIAL"

    # =========================================================
    # CURRENT EVIDENCE ANALYSIS
    # =========================================================

    def _has_current_negative_evidence(
        self,
        structured_items,
    ):
        for item in structured_items:
            if (
                item["direction"] == "NEGATIVE"
                and item["type"]
                in (
                    self.CRITICAL_NEGATIVE_TYPES
                    | self.STRONG_NEGATIVE_TYPES
                )
            ):
                return True

        return False

    def _has_current_critical_evidence(
        self,
        structured_items,
    ):
        for item in structured_items:
            if (
                item["direction"] == "NEGATIVE"
                and (
                    item["severity"] == "CRITICAL"
                    or item["type"]
                    in self.CRITICAL_NEGATIVE_TYPES
                )
            ):
                return True

        return False

    def _has_current_strong_evidence(
        self,
        structured_items,
    ):
        for item in structured_items:
            if (
                item["direction"] == "NEGATIVE"
                and (
                    item["severity"]
                    in {"HIGH", "CRITICAL"}
                    or item["type"]
                    in self.CRITICAL_NEGATIVE_TYPES
                    | self.STRONG_NEGATIVE_TYPES
                )
            ):
                return True

        return False

    def _has_supporting_malicious_evidence(
        self,
        structured_items,
    ):
        return any(
            item["direction"] == "NEGATIVE"
            for item in structured_items
            if item["severity"]
            in {"MEDIUM", "HIGH", "CRITICAL"}
        )

    def _has_unresolved_contradiction(
        self,
        ai_analysis,
        structured_items,
        historical_evidence,
    ):
        ai_state = str(
            ai_analysis.get(
                "reasoning_state",
                "",
            )
        ).upper()

        if ai_state == "CONFLICTING_EVIDENCE":
            return True

        contradiction_engine = (
            ai_analysis.get(
                "contradictions_engine",
                {},
            )
            if ai_analysis
            else {}
        )

        if (
            contradiction_engine.get(
                "state"
            )
            == "CONFLICTING_EVIDENCE"
        ):
            return True

        if historical_evidence:
            status = historical_evidence.get("status")
            if status == "CONFLICTING_EVIDENCE":
                return True

        return any(
            item.get("type")
            == "CONFLICTING_EVIDENCE"
            for item in structured_items
        )

    # =========================================================
    # SCORE HELPERS
    # =========================================================

    @staticmethod
    def _clamp_score(score):
        return max(
            0,
            min(
                100,
                int(round(score)),
            ),
        )

    @staticmethod
    def _clamp_confidence(confidence):
        return max(
            0,
            min(
                100,
                int(round(confidence)),
            ),
        )

    # =========================================================
    # MAIN EVALUATION
    # =========================================================

    def evaluate(
        self,
        authentication,
        url_analysis,
        whois_analysis,
        content_analysis,
        attachment_analysis,
        trust_analysis,
        ai_analysis=None,
        url_page_intelligence=None,
        historical_evidence=None,
    ):
        authentication = authentication or {}
        url_analysis = url_analysis or {}
        whois_analysis = whois_analysis or []
        content_analysis = content_analysis or {}
        attachment_analysis = attachment_analysis or {}
        trust_analysis = trust_analysis or {}
        ai_analysis = ai_analysis or {}
        url_page_intelligence = (
            url_page_intelligence or {}
        )

        score = 0

        evidence = {
            "technical": [],
            "behavioral": [],
            "network": [],
            "positive": [],
            "negative": [],
        }

        structured_evidence = []

        auth_rules = self.rules["authentication"]
        url_rules = self.rules["url"]
        content_rules = self.rules["content"]
        whois_rules = self.rules.get(
            "whois",
            {},
        )

        # =====================================================
        # 1. AUTHENTICATION
        # =====================================================

        auth_state = self._authentication_state(
            authentication
        )

        if auth_state == "UNAVAILABLE":

            evidence["technical"].append(
                "Authentication analysis unavailable"
            )

        elif auth_state == "FAILED":

            spf = str(
                authentication.get("spf", "")
            ).lower()

            dkim = str(
                authentication.get("dkim", "")
            ).lower()

            dmarc = str(
                authentication.get("dmarc", "")
            ).lower()

            if spf != "pass":
                score += auth_rules["spf_fail"]
                evidence["technical"].append(
                    "SPF validation failed"
                )

                structured_evidence.append({
                    "type": "AUTHENTICATION_FAILURE",
                    "severity": "HIGH",
                    "direction": "NEGATIVE",
                    "source": "AuthenticationAnalyzer",
                    "explanation": (
                        "SPF validation failed."
                    ),
                    "confidence": 0.95,
                })

            if dkim != "pass":
                score += auth_rules["dkim_fail"]
                evidence["technical"].append(
                    "DKIM validation failed"
                )

                structured_evidence.append({
                    "type": "AUTHENTICATION_FAILURE",
                    "severity": "HIGH",
                    "direction": "NEGATIVE",
                    "source": "AuthenticationAnalyzer",
                    "explanation": (
                        "DKIM validation failed."
                    ),
                    "confidence": 0.95,
                })

            if dmarc != "pass":
                score += auth_rules["dmarc_fail"]
                evidence["technical"].append(
                    "DMARC validation failed"
                )

                structured_evidence.append({
                    "type": "AUTHENTICATION_FAILURE",
                    "severity": "HIGH",
                    "direction": "NEGATIVE",
                    "source": "AuthenticationAnalyzer",
                    "explanation": (
                        "DMARC validation failed."
                    ),
                    "confidence": 0.95,
                })

        elif auth_state == "PARTIAL":

            evidence["technical"].append(
                "Authentication evidence incomplete"
            )

        # =====================================================
        # 2. TRUST SIGNAL
        # =====================================================

        trust_score = self._safe_number(
            trust_analysis.get(
                "trust_score",
                0,
            ),
            0,
        )

        auth_fully_passed = (
            auth_state == "PASSED"
        )

        if (
            auth_fully_passed
            and trust_score >= 40
        ):
            score -= 30

            evidence["technical"].append(
                "Trusted sender with full authentication"
            )

            evidence["positive"].append(
                "Sender has strong authentication "
                "and established trust."
            )

            structured_evidence.append({
                "type": "AUTHENTICATION_PASS",
                "severity": "LOW",
                "direction": "POSITIVE",
                "source": "AuthenticationAnalyzer",
                "explanation": (
                    "SPF, DKIM and DMARC passed."
                ),
                "confidence": 0.96,
            })

        elif (
            auth_fully_passed
            and trust_score >= 20
        ):
            score -= 15

            evidence["technical"].append(
                "Authenticated sender with partial trust signal"
            )

            evidence["positive"].append(
                "Sender authentication passed."
            )

        # =====================================================
        # 3. URL ANALYSIS
        # =====================================================

        for url in url_analysis.get(
            "analysis",
            [],
        ):
            url = url or {}

            # Legacy indicators
            if url.get("ip_based"):
                score += url_rules.get(
                    "ip_url",
                    20,
                )

                evidence["network"].append(
                    f"IP URL: {url.get('url', '')}"
                )

                structured_evidence.append({
                    "type": "SUSPICIOUS_URL",
                    "severity": "HIGH",
                    "direction": "NEGATIVE",
                    "source": "URLAnalyzer",
                    "explanation": (
                        "URL uses an IP address "
                        "instead of a domain."
                    ),
                    "confidence": 0.90,
                })

            if url.get("shortener"):
                score += url_rules.get(
                    "shortener",
                    10,
                )

                evidence["network"].append(
                    f"Shortened URL: {url.get('url', '')}"
                )

            keywords = url.get(
                "keywords",
                [],
            )

            if keywords:
                score += (
                    len(keywords)
                    * url_rules.get(
                        "keyword",
                        5,
                    )
                )

                evidence["network"].append(
                    "Suspicious URL keywords: "
                    + ", ".join(keywords)
                )

            if url.get("obfuscated"):
                score += url_rules.get(
                    "obfuscated",
                    15,
                )

                evidence["network"].append(
                    f"Obfuscated URL detected: "
                    f"{url.get('url', '')}"
                )

            if url.get("punycode"):
                score += url_rules.get(
                    "punycode",
                    20,
                )

                evidence["network"].append(
                    f"Punycode domain detected: "
                    f"{url.get('domain', '')}"
                )

                structured_evidence.append({
                    "type": "PUNYCODE_DOMAIN",
                    "severity": "HIGH",
                    "direction": "NEGATIVE",
                    "source": "URLAnalyzer",
                    "explanation": (
                        "Punycode domain detected."
                    ),
                    "confidence": 0.90,
                })

            if url.get("suspicious_port"):
                score += url_rules.get(
                    "suspicious_port",
                    10,
                )

                evidence["network"].append(
                    f"Suspicious URL port detected: "
                    f"{url.get('url', '')}"
                )

            if url.get(
                "subdomain_count",
                0,
            ) > 3:
                score += url_rules.get(
                    "excessive_subdomains",
                    10,
                )

                evidence["network"].append(
                    "Excessive subdomains detected: "
                    f"{url.get('domain', '')}"
                )

            # Brand intelligence
            if url.get(
                "brand_impersonation"
            ):
                score += 40

                domain = url.get(
                    "domain",
                    "",
                )

                evidence["network"].append(
                    f"Brand impersonation detected: {domain}"
                )

                structured_evidence.append({
                    "type": "BRAND_IMPERSONATION",
                    "severity": "CRITICAL",
                    "direction": "NEGATIVE",
                    "source": "BrandIntelligence",
                    "explanation": (
                        f"Brand impersonation detected "
                        f"for {domain}."
                    ),
                    "confidence": 0.95,
                })

            # Email alignment
            alignment = url.get(
                "email_alignment"
            )

            if alignment == "misaligned":
                score += 15

                evidence["network"].append(
                    "URL domain misaligned with sender: "
                    f"{url.get('domain', '')}"
                )

                structured_evidence.append({
                    "type": "DOMAIN_MISMATCH",
                    "severity": "HIGH",
                    "direction": "NEGATIVE",
                    "source": "URLAnalyzer",
                    "explanation": (
                        "URL domain is misaligned "
                        "with the sender."
                    ),
                    "confidence": 0.90,
                })

            elif alignment == "aligned":
                score -= 10

                evidence["positive"].append(
                    "URL domain is aligned with sender."
                )

            # DNS
            dns = url.get(
                "dns",
                {},
            ) or {}

            if dns.get(
                "private_ip_detected"
            ):
                score += 50

                evidence["network"].append(
                    "SSRF protection blocked private "
                    f"IP resolution for: "
                    f"{url.get('domain', '')}"
                )

                structured_evidence.append({
                    "type": "PRIVATE_IP_DESTINATION",
                    "severity": "CRITICAL",
                    "direction": "NEGATIVE",
                    "source": "DNSInspector",
                    "explanation": (
                        "Private IP destination "
                        "was blocked by SSRF protection."
                    ),
                    "confidence": 1.0,
                })

            # Redirects
            redirects = url.get(
                "redirects",
                {},
            ) or {}

            if (
                redirects.get(
                    "external_domain_change"
                )
                and not self._is_trusted_url_domain(
                    url_analysis,
                    url,
                )
            ):
                score += 20

                evidence["network"].append(
                    "Suspicious external redirect chain: "
                    f"{url.get('domain', '')}"
                )

                structured_evidence.append({
                    "type": "SUSPICIOUS_REDIRECT",
                    "severity": "HIGH",
                    "direction": "NEGATIVE",
                    "source": "URLInspector",
                    "explanation": (
                        "URL redirects to an external "
                        "domain."
                    ),
                    "confidence": 0.90,
                })

            # TLS
            tls = url.get(
                "tls",
                {},
            ) or {}

            if tls.get(
                "certificate_valid"
            ) is True:
                score -= 5

                evidence["positive"].append(
                    "TLS certificate validated successfully."
                )

            if url.get(
                "tls_policy_violation"
            ):
                severity = self._normalize_severity(
                    tls.get(
                        "severity",
                        "MEDIUM",
                    )
                )

                violation = tls.get(
                    "violation",
                    "UNKNOWN",
                )

                tls_score = {
                    "HIGH": 20,
                    "MEDIUM": 10,
                    "LOW": 5,
                }.get(
                    severity,
                    10,
                )

                score += tls_score

                evidence["network"].append(
                    f"TLS Policy Violation "
                    f"({violation}) on: "
                    f"{url.get('domain', '')}"
                )

                structured_evidence.append({
                    "type": "TLS_POLICY_VIOLATION",
                    "severity": severity,
                    "direction": "NEGATIVE",
                    "source": "TLSInspector",
                    "explanation": (
                        f"TLS policy violation: "
                        f"{violation}."
                    ),
                    "confidence": 0.90,
                })

            elif url.get(
                "http_policy_warning"
            ):
                score += 5

                evidence["network"].append(
                    "Insecure transport (HTTP) on: "
                    f"{url.get('domain', '')}"
                )

            elif url.get(
                "tls_inspection_unavailable"
            ):
                evidence["network"].append(
                    "TLS inspection unavailable for: "
                    f"{url.get('domain', '')}"
                )

        # =====================================================
        # 4. WHOIS
        # =====================================================

        for whois in whois_analysis:

            whois = whois or {}

            domain = whois.get(
                "domain",
                "Unknown",
            )

            age_category = whois.get(
                "age_category"
            )

            error = whois.get(
                "error"
            )

            if error:
                evidence["network"].append(
                    f"WHOIS lookup unavailable for: "
                    f"{domain}"
                )

            elif age_category == "new":
                score += whois_rules.get(
                    "new_domain",
                    15,
                )

                evidence["network"].append(
                    f"Newly registered domain detected: "
                    f"{domain}"
                )

                structured_evidence.append({
                    "type": "NEW_DOMAIN",
                    "severity": "MEDIUM",
                    "direction": "NEGATIVE",
                    "source": "WhoisAnalyzer",
                    "explanation": (
                        f"Newly registered domain: "
                        f"{domain}"
                    ),
                    "confidence": 0.80,
                })

            elif age_category == "recent":
                score += whois_rules.get(
                    "recent_domain",
                    5,
                )

                evidence["network"].append(
                    f"Recently registered domain: "
                    f"{domain}"
                )

        # =====================================================
        # 5. CONTENT ANALYSIS
        # =====================================================

        content_status = str(
            content_analysis.get(
                "analysis_status",
                "AVAILABLE",
            )
        ).upper()

        if content_status == "UNAVAILABLE":

            evidence["behavioral"].append(
                "Content analysis unavailable"
            )

        else:
            # A trusted/authenticated sender does not make
            # credential requests automatically legitimate.
            #
            # Context is evaluated together with URL/brand/page
            # evidence below.

            if content_analysis.get(
                "urgency"
            ):
                score += content_rules.get(
                    "urgency",
                    20,
                )

                evidence["behavioral"].append(
                    "Urgency language detected"
                )

                structured_evidence.append({
                    "type": "URGENCY_LANGUAGE",
                    "severity": "MEDIUM",
                    "direction": "NEGATIVE",
                    "source": "ContentAnalyzer",
                    "explanation": (
                        "Urgency language detected."
                    ),
                    "confidence": 0.80,
                })

            if content_analysis.get(
                "credential_request"
            ):
                score += content_rules.get(
                    "credential_request",
                    25,
                )

                evidence["behavioral"].append(
                    "Credential request detected"
                )

                structured_evidence.append({
                    "type": "CREDENTIAL_REQUEST",
                    "severity": "HIGH",
                    "direction": "NEGATIVE",
                    "source": "ContentAnalyzer",
                    "explanation": (
                        "The message requests "
                        "credential/account information."
                    ),
                    "confidence": 0.85,
                })

            if content_analysis.get(
                "financial_request"
            ):
                score += content_rules.get(
                    "financial_request",
                    25,
                )

                evidence["behavioral"].append(
                    "Financial request detected"
                )

                structured_evidence.append({
                    "type": "FINANCIAL_REQUEST",
                    "severity": "HIGH",
                    "direction": "NEGATIVE",
                    "source": "ContentAnalyzer",
                    "explanation": (
                        "Financial request detected."
                    ),
                    "confidence": 0.85,
                })

            if content_analysis.get(
                "impersonation"
            ):
                score += content_rules.get(
                    "impersonation",
                    10,
                )

                evidence["behavioral"].append(
                    "Possible impersonation"
                )

                structured_evidence.append({
                    "type": "BRAND_IMPERSONATION",
                    "severity": "HIGH",
                    "direction": "NEGATIVE",
                    "source": "ContentAnalyzer",
                    "explanation": (
                        "Possible impersonation detected."
                    ),
                    "confidence": 0.80,
                })

            if content_analysis.get(
                "threat_language"
            ):
                score += content_rules.get(
                    "threat_language",
                    20,
                )

                evidence["behavioral"].append(
                    "Threat language detected"
                )

        # =====================================================
        # 6. ATTACHMENTS
        # =====================================================

        attachment_status = str(
            attachment_analysis.get(
                "analysis_status",
                "AVAILABLE",
            )
        ).upper()

        if attachment_status == "UNAVAILABLE":

            evidence["technical"].append(
                "Attachment analysis unavailable"
            )

        else:

            attachment_score = (
                self._safe_number(
                    attachment_analysis.get(
                        "risk_score",
                        0,
                    ),
                    0,
                )
                * self._safe_number(
                    self.rules[
                        "attachment"
                    ].get(
                        "risk_multiplier",
                        1,
                    ),
                    1,
                )
            )

            score += attachment_score

            for item in (
                attachment_analysis.get(
                    "evidence",
                    [],
                )
                or []
            ):
                text = str(item)

                evidence["technical"].append(
                    text
                )

                lowered = text.lower()

                if "executable attachment" in lowered:
                    structured_evidence.append({
                        "type": "EXECUTABLE_ATTACHMENT",
                        "severity": "CRITICAL",
                        "direction": "NEGATIVE",
                        "source": "AttachmentAnalyzer",
                        "explanation": text,
                        "confidence": 0.98,
                    })

                elif "script attachment" in lowered:
                    structured_evidence.append({
                        "type": "SCRIPT_ATTACHMENT",
                        "severity": "CRITICAL",
                        "direction": "NEGATIVE",
                        "source": "AttachmentAnalyzer",
                        "explanation": text,
                        "confidence": 0.97,
                    })

                elif "macro-enabled" in lowered:
                    structured_evidence.append({
                        "type": "MACRO_ATTACHMENT",
                        "severity": "HIGH",
                        "direction": "NEGATIVE",
                        "source": "AttachmentAnalyzer",
                        "explanation": text,
                        "confidence": 0.95,
                    })

        # =====================================================
        # 7. LINK-ONLY / LIMITED CONTEXT + PAGE INTELLIGENCE
        # =====================================================

        limited_context = bool(
            url_analysis.get(
                "limited_context"
            )
            or content_analysis.get(
                "link_only"
            )
        )

        if limited_context:

            evidence["behavioral"].append(
                "Limited context: Email contains "
                "mostly URLs with minimal surrounding text"
            )

            if url_page_intelligence:

                page_risk_found = False

                for url, page_data in (
                    url_page_intelligence.items()
                ):

                    page_data = page_data or {}

                    security = page_data.get(
                        "security",
                        {},
                    ) or {}

                    if security.get("error"):

                        evidence["network"].append(
                            f"Page fetch failed/blocked "
                            f"for {url}"
                        )

                    forms = page_data.get(
                        "forms",
                        {},
                    ) or {}

                    password_fields = self._safe_number(
                        forms.get(
                            "password_fields",
                            0,
                        ),
                        0,
                    )

                    email_fields = self._safe_number(
                        forms.get(
                            "email_fields",
                            0,
                        ),
                        0,
                    )

                    if password_fields > 0:

                        score += 40
                        page_risk_found = True

                        evidence["behavioral"].append(
                            "Destination page requests "
                            f"a password: {url}"
                        )

                        structured_evidence.append({
                            "type": "CREDENTIAL_HARVESTING",
                            "severity": "CRITICAL",
                            "direction": "NEGATIVE",
                            "source": "URLPageInspection",
                            "explanation": (
                                "Destination page contains "
                                "a password input."
                            ),
                            "confidence": 0.95,
                        })

                    elif email_fields > 0:

                        score += 20
                        page_risk_found = True

                        evidence["behavioral"].append(
                            "Destination page requests "
                            f"an email/login: {url}"
                        )

                        structured_evidence.append({
                            "type": "CREDENTIAL_FORM",
                            "severity": "HIGH",
                            "direction": "NEGATIVE",
                            "source": "URLPageInspection",
                            "explanation": (
                                "Destination page contains "
                                "an email/login input."
                            ),
                            "confidence": 0.90,
                        })

                    page_ai = page_data.get(
                        "ai",
                        {},
                    ) or {}

                    page_intent = self._normalize_type(
                        page_ai.get(
                            "intent",
                            "",
                        )
                    )

                    if page_intent in {
                        "CREDENTIAL_HARVESTING",
                        "PAYMENT_SCAM",
                        "MALWARE_DISTRIBUTION",
                        "TECH_SUPPORT_SCAM",
                    }:

                        score += 40
                        page_risk_found = True

                        structured_evidence.append({
                            "type": page_intent,
                            "severity": "CRITICAL",
                            "direction": "NEGATIVE",
                            "source": "LocalAI",
                            "explanation": (
                                "Local page-intent analysis "
                                f"identified {page_intent}."
                            ),
                            "confidence": self._safe_number(
                                page_ai.get(
                                    "confidence",
                                    0,
                                ),
                                0,
                            ),
                        })

                if not page_risk_found:

                    evidence["positive"].append(
                        "Deep URL inspection found no "
                        "immediate page-level risk."
                    )

        # =====================================================
        # 8. LOCAL AI / STAGE 6-10 EVIDENCE
        # =====================================================

        ai_state = str(
            ai_analysis.get(
                "reasoning_state",
                "",
            )
        ).upper()

        ai_confidence = (
            self._safe_number(
                ai_analysis.get(
                    "confidence",
                    0,
                ),
                0,
            )
        )

        original_ai_state = ai_state

        ai_structured = []

        # Structured evidence from Local AI
        for item in (
            ai_analysis.get(
                "structured_evidence",
                [],
            )
            or []
        ):

            normalized = self._structured_evidence(
                item
            )

            ai_structured.append(
                normalized
            )

            structured_evidence.append(
                normalized
            )

        # AI contradictions
        for contradiction in (
            ai_analysis.get(
                "contradictions",
                [],
            )
            or []
        ):

            text = (
                contradiction.get(
                    "explanation",
                    contradiction,
                )
                if isinstance(
                    contradiction,
                    dict,
                )
                else str(
                    contradiction
                )
            )

            evidence["behavioral"].append(
                f"AI Conflict: {text}"
            )

            structured_evidence.append({
                "type": "CONFLICTING_EVIDENCE",
                "severity": "MEDIUM",
                "direction": "NEUTRAL",
                "source": "LocalAI",
                "explanation": text,
                "confidence": ai_confidence,
            })

        # Homoglyph
        for item in (
            ai_analysis.get(
                "homoglyph",
                [],
            )
            or []
        ):

            if isinstance(item, dict):
                text = item.get(
                    "evidence",
                    "Homoglyph detected",
                )
            else:
                text = str(item)

            score += 20

            evidence["network"].append(
                text
            )

            structured_evidence.append({
                "type": "HOMOGRAPH_DOMAIN",
                "severity": "HIGH",
                "direction": "NEGATIVE",
                "source": "BrandIntelligence",
                "explanation": text,
                "confidence": 0.90,
            })

        # Brand intelligence
        for item in (
            ai_analysis.get(
                "brand_intelligence",
                [],
            )
            or []
        ):

            if not isinstance(item, dict):
                continue

            if item.get(
                "impersonation_risk"
            ):
                score += 40

                explanation = item.get(
                    "explanation",
                    "Brand impersonation detected.",
                )

                evidence["behavioral"].append(
                    explanation
                )

                structured_evidence.append({
                    "type": "BRAND_IMPERSONATION",
                    "severity": "CRITICAL",
                    "direction": "NEGATIVE",
                    "source": "BrandIntelligence",
                    "explanation": explanation,
                    "confidence": self._safe_number(
                        item.get(
                            "confidence",
                            0.95,
                        ),
                        0.95,
                    ),
                })

            elif (
                item.get("brand_mentioned")
                and not item.get(
                    "domain_claimed"
                )
            ):
                evidence["behavioral"].append(
                    item.get(
                        "explanation",
                        "Brand mentioned without "
                        "domain alignment.",
                    )
                )

        # Adversarial analysis
        for item in (
            ai_analysis.get(
                "adversarial",
                [],
            )
            or []
        ):

            if not isinstance(item, dict):
                continue

            explanation = item.get(
                "explanation",
                "",
            )

            evidence["behavioral"].append(
                explanation
            )

            severity = self._normalize_severity(
                item.get(
                    "severity",
                    "MEDIUM",
                )
            )

            if item.get(
                "direction",
                "NEGATIVE",
            ).upper() == "NEGATIVE":

                score += {
                    "CRITICAL": 30,
                    "HIGH": 25,
                    "MEDIUM": 15,
                    "LOW": 5,
                }.get(
                    severity,
                    10,
                )

                structured_evidence.append({
                    "type": "ADVERSARIAL_INDICATOR",
                    "severity": severity,
                    "direction": "NEGATIVE",
                    "source": "AdversarialAnalyzer",
                    "explanation": explanation,
                    "confidence": self._safe_number(
                        item.get(
                            "confidence",
                            0,
                        ),
                        0,
                    ),
                })

        # Contradiction engine
        contradiction_engine = (
            ai_analysis.get(
                "contradictions_engine",
                {},
            )
            or {}
        )

        if contradiction_engine.get(
            "contradiction_detected"
        ):

            contradiction_state = str(
                contradiction_engine.get(
                    "state",
                    "",
                )
            ).upper()

            explanation = contradiction_engine.get(
                "explanation",
                "Conflicting evidence detected.",
            )

            evidence["behavioral"].append(
                explanation
            )

            structured_evidence.append({
                "type": (
                    "TRUST_HISTORY_CONFLICT"
                    if contradiction_state
                    == "TRUST_HISTORY_CONFLICT"
                    else "CONFLICTING_EVIDENCE"
                ),
                "severity": "HIGH",
                "direction": "NEUTRAL",
                "source": "ContradictionEngine",
                "explanation": explanation,
                "confidence": self._safe_number(
                    contradiction_engine.get(
                        "confidence",
                        0,
                    ),
                    0,
                ),
            })

            if contradiction_state == "TRUST_HISTORY_CONFLICT":
                ai_state = (
                    "TRUST_HISTORY_CONFLICT"
                )

            elif contradiction_state == "CONFLICTING_EVIDENCE":
                ai_state = (
                    "CONFLICTING_EVIDENCE"
                )

            elif contradiction_state == "INSUFFICIENT_EVIDENCE":
                ai_state = (
                    "INSUFFICIENT_EVIDENCE"
                )

        # Behavioral intelligence
        for item in (
            ai_analysis.get(
                "behavioral",
                [],
            )
            or []
        ):

            normalized = self._structured_evidence(
                item
            )

            evidence["behavioral"].append(
                normalized["explanation"]
            )

            structured_evidence.append(
                normalized
            )

            if normalized["direction"] == "NEGATIVE":

                score += {
                    "CRITICAL": 30,
                    "HIGH": 20,
                    "MEDIUM": 15,
                    "LOW": 5,
                }.get(
                    normalized["severity"],
                    10,
                )

        # Campaign intelligence
        for item in (
            ai_analysis.get(
                "campaign",
                [],
            )
            or []
        ):

            normalized = self._structured_evidence(
                item
            )

            evidence["behavioral"].append(
                normalized["explanation"]
            )

            structured_evidence.append(
                normalized
            )

            if (
                normalized["direction"]
                == "NEGATIVE"
            ):
                score += {
                    "CRITICAL": 30,
                    "HIGH": 25,
                    "MEDIUM": 15,
                    "LOW": 5,
                }.get(
                    normalized["severity"],
                    10,
                )

        # Temporal intelligence
        for item in (
            ai_analysis.get(
                "temporal",
                [],
            )
            or []
        ):

            normalized = self._structured_evidence(
                item
            )

            evidence["behavioral"].append(
                normalized["explanation"]
            )

            structured_evidence.append(
                normalized
            )

            if (
                normalized["direction"]
                == "NEGATIVE"
            ):
                score += {
                    "CRITICAL": 25,
                    "HIGH": 20,
                    "MEDIUM": 15,
                    "LOW": 5,
                }.get(
                    normalized["severity"],
                    10,
                )

        # Sender reputation
        reputation = (
            ai_analysis.get(
                "sender_reputation",
                {},
            )
            or {}
        )

        reputation_status = str(
            reputation.get(
                "reputation",
                "UNKNOWN",
            )
        ).upper()

        messages_seen = int(
            self._safe_number(
                reputation.get(
                    "messages_seen",
                    0,
                ),
                0,
            )
        )

        if (
            reputation_status == "UNKNOWN"
            and messages_seen == 0
        ):
            ai_state = "NEW_SENDER"

        elif reputation_status in {
            "SUSPICIOUS",
            "HIGH_RISK",
        }:
            ai_state = "SUSPICIOUS_HISTORY"

        # Adaptive intelligence
        adaptive = (
            ai_analysis.get(
                "adaptive",
                {},
            )
            or {}
        )

        for anomaly in (
            adaptive.get(
                "behavioral_anomalies",
                [],
            )
            or []
        ):

            if not isinstance(
                anomaly,
                dict,
            ):
                continue

            explanation = anomaly.get(
                "explanation",
                "",
            )

            evidence["behavioral"].append(
                explanation
            )

            severity = self._normalize_severity(
                anomaly.get(
                    "severity",
                    "MEDIUM",
                )
            )

            if anomaly.get(
                "direction",
                "NEGATIVE",
            ).upper() == "NEGATIVE":

                score += {
                    "CRITICAL": 30,
                    "HIGH": 20,
                    "MEDIUM": 10,
                    "LOW": 5,
                }.get(
                    severity,
                    10,
                )

            anomaly_type = self._normalize_type(
                anomaly.get(
                    "type",
                    "",
                )
            )

            if anomaly_type in {
                "DOMAIN_DRIFT",
                "AUTHENTICATION_DRIFT",
                "URL_BEHAVIOR_DRIFT",
            }:
                ai_state = anomaly_type

            structured_evidence.append({
                "type": anomaly_type
                or "BEHAVIORAL_ANOMALY",
                "severity": severity,
                "direction": self._normalize_direction(
                    anomaly.get(
                        "direction",
                        "NEGATIVE",
                    )
                ),
                "source": "AdaptiveIntelligence",
                "explanation": explanation,
                "confidence": self._safe_number(
                    anomaly.get(
                        "confidence",
                        0,
                    ),
                    0,
                ),
            })

        trend = (
            adaptive.get(
                "risk_trend",
                {},
            )
            or {}
        ).get("trend")

        if trend == "DEGRADING":
            score += 15
            evidence["behavioral"].append(
                "Risk trend is degrading over time."
            )

        elif trend == "IMPROVING":
            score -= 5

        history_confidence = (
            adaptive.get(
                "history_confidence",
                {},
            )
            or {}
        ).get("level")

        if history_confidence in {
            "VERY_LOW",
            "LOW",
        }:
            evidence["behavioral"].append(
                "Insufficient historical baseline "
                "for this sender."
            )

        # =====================================================
        # 9. HISTORICAL EVIDENCE
        # =====================================================

        historical_status = (
            historical_evidence.get(
                "status"
            )
            if historical_evidence
            else None
        )

        if (
            historical_status
            == "VALID_HISTORICAL_EVIDENCE"
        ):

            record = historical_evidence.get(
                "record",
                {},
            ) or {}

            historical = record.get(
                "historical",
                {},
            ) or {}

            historical_verdict = historical.get(
                "verdict"
            )

            freshness = self._safe_number(
                record.get(
                    "history_state",
                    {},
                ).get(
                    "freshness",
                    0,
                ),
                0,
            )

            # Historical evidence must never be used
            # as an override if meaningful current
            # negative evidence exists.
            current_negative = (
                self._has_current_negative_evidence(
                    structured_evidence
                )
            )

            if historical_verdict in {
                "VERIFIED LEGITIMATE",
                "LIKELY LEGITIMATE",
            }:

                if current_negative:

                    evidence["behavioral"].append(
                        "Historical evidence supports "
                        "legitimacy, but current negative "
                        "evidence takes precedence."
                    )

                    structured_evidence.append({
                        "type": "HISTORICAL_CURRENT_CONFLICT",
                        "severity": "MEDIUM",
                        "direction": "NEUTRAL",
                        "source": "VerdictStore",
                        "explanation": (
                            "Historical positive evidence "
                            "conflicts with current security "
                            "evidence."
                        ),
                        "confidence": freshness,
                    })

                else:

                    evidence["positive"].append(
                        "Historical evidence supports "
                        "legitimate sender behavior."
                    )

                    structured_evidence.append({
                        "type": "VALID_HISTORICAL_EVIDENCE",
                        "severity": "LOW",
                        "direction": "POSITIVE",
                        "source": "VerdictStore",
                        "explanation": (
                            "Historical positive evidence "
                            "supports legitimacy."
                        ),
                        "confidence": freshness,
                    })

        elif (
            historical_status
            == "STALE_HISTORICAL_EVIDENCE"
        ):

            evidence["behavioral"].append(
                "Stale historical evidence is present "
                "but ignored because the current message "
                "fingerprint changed."
            )

        # =====================================================
        # 10. FINAL SCORE AFTER ALL EVIDENCE
        # =====================================================

        score = self._clamp_score(
            score
        )

        # =====================================================
        # 11. DETERMINE CURRENT EVIDENCE STATE
        # =====================================================

        has_critical = (
            self._has_current_critical_evidence(
                structured_evidence
            )
        )

        has_strong = (
            self._has_current_strong_evidence(
                structured_evidence
            )
        )

        has_negative = (
            self._has_current_negative_evidence(
                structured_evidence
            )
        )

        has_supporting_malicious = (
            self._has_supporting_malicious_evidence(
                structured_evidence
            )
        )

        unresolved_contradiction = (
            self._has_unresolved_contradiction(
                ai_analysis,
                structured_evidence,
                historical_evidence,
            )
        )

        # =====================================================
        # 12. CONFIDENCE
        # =====================================================

        independent_negative_sources = len({
            item.get("source")
            for item in structured_evidence
            if item.get("direction")
            == "NEGATIVE"
        })

        independent_positive_sources = len({
            item.get("source")
            for item in structured_evidence
            if item.get("direction")
            == "POSITIVE"
        })

        if (
            has_critical
            and independent_negative_sources >= 2
        ):
            confidence = 90

        elif (
            has_critical
            or independent_negative_sources >= 2
        ):
            confidence = 80

        elif (
            has_strong
            and independent_negative_sources >= 1
        ):
            confidence = 70

        elif (
            independent_positive_sources >= 3
            and not has_negative
        ):
            confidence = 90

        elif (
            independent_positive_sources >= 2
            and not has_negative
        ):
            confidence = 80

        elif not has_negative:
            confidence = 55

        else:
            confidence = 50

        # AI confidence can inform but cannot exceed
        # deterministic evidence confidence.
        if ai_confidence > 0:
            confidence = min(
                confidence,
                max(
                    40,
                    int(ai_confidence),
                ),
            )

        # =====================================================
        # 13. LIMITED CONTEXT
        # =====================================================

        if limited_context:

            confidence = max(
                10,
                confidence - 30,
            )

            if not has_negative:
                ai_state = (
                    "LIMITED_CONTEXT"
                )

        # =====================================================
        # 14. FINAL VERDICT
        # =====================================================

        if has_critical:
            verdict = "PHISHING"

        elif score >= 80:
            verdict = "PHISHING"

        elif score >= 60:
            verdict = "HIGH RISK"

        elif score >= 40:
            verdict = "SUSPICIOUS"

        elif (
            unresolved_contradiction
            and not has_critical
        ):
            verdict = "UNKNOWN"

        elif (
            limited_context
            and not has_negative
        ):
            verdict = "UNKNOWN"

        elif score < 20:
            if (
                independent_positive_sources >= 3
                and not has_negative
                and not unresolved_contradiction
            ):
                verdict = (
                    "VERIFIED LEGITIMATE"
                )

            elif (
                independent_positive_sources >= 2
                and not has_negative
                and not unresolved_contradiction
            ):
                verdict = (
                    "LIKELY LEGITIMATE"
                )

            else:
                verdict = "UNKNOWN"

        else:
            verdict = "UNKNOWN"

        # =====================================================
        # 15. AI RECOMMENDATION — EVIDENCE ONLY
        # =====================================================

        recommended = self._normalize_type(
            ai_analysis.get(
                "recommended_classification",
                "",
            )
        )

        # AI cannot override strong deterministic evidence.
        if (
            recommended
            in {
                "SAFE",
                "LEGITIMATE",
                "LIKELY_LEGITIMATE",
                "VERIFIED_LEGITIMATE",
            }
            and has_critical
        ):

            structured_evidence.append({
                "type": "AI_IGNORED_DUE_TO_MALICE",
                "severity": "HIGH",
                "direction": "NEUTRAL",
                "source": "SanityValidator",
                "explanation": (
                    "AI recommendation was ignored "
                    "because current deterministic "
                    "malicious evidence takes precedence."
                ),
                "confidence": ai_confidence,
            })

            ai_state = (
                "CONFLICTING_EVIDENCE"
            )

            verdict = "PHISHING"

        elif (
            recommended == "PHISHING"
            and not has_negative
            and score < 30
        ):

            ai_state = (
                "INSUFFICIENT_EVIDENCE"
            )

            verdict = "UNKNOWN"

            confidence = min(
                confidence,
                45,
            )

            evidence["behavioral"].append(
                "AI phishing recommendation lacked "
                "sufficient independent malicious evidence."
            )

        elif (
            recommended == "SUSPICIOUS"
            and independent_positive_sources >= 3
            and not has_negative
            and not unresolved_contradiction
        ):

            ai_state = (
                "AI_LEGITIMACY_CONFLICT"
            )

            verdict = (
                "LIKELY LEGITIMATE"
            )

            confidence = min(
                confidence,
                70,
            )

        # =====================================================
        # 16. TRUST HISTORY CONFLICT
        # =====================================================

        reputation_status = reputation_status

        if (
            reputation_status
            == "TRUSTED"
            and verdict
            in {
                "PHISHING",
                "HIGH RISK",
                "SUSPICIOUS",
            }
        ):

            ai_state = (
                "POSSIBLE_COMPROMISED_SENDER"
            )

            structured_evidence.append({
                "type": "TRUST_HISTORY_CONFLICT",
                "severity": "HIGH",
                "direction": "NEUTRAL",
                "source": "BehavioralIntelligence",
                "explanation": (
                    "Sender has historically behaved "
                    "legitimately, but the current message "
                    "contains suspicious or malicious evidence."
                ),
                "confidence": 0.90,
            })

            evidence["behavioral"].append(
                "Trusted sender history conflicts "
                "with current security evidence."
            )

        # =====================================================
        # 17. FINAL CONFIDENCE ADJUSTMENTS
        # =====================================================

        if unresolved_contradiction:
            confidence = min(
                confidence,
                50,
            )

        if (
            verdict
            in {
                "VERIFIED LEGITIMATE",
                "LIKELY LEGITIMATE",
            }
            and has_negative
        ):
            verdict = "UNKNOWN"
            confidence = min(
                confidence,
                50,
            )

            ai_state = (
                "CONFLICTING_EVIDENCE"
            )

        confidence = self._clamp_confidence(
            confidence
        )

        score = self._clamp_score(
            score
        )

        # =====================================================
        # 18. FINAL EXPLANATION
        # =====================================================

        explanation = self.generate_explanation(
            verdict,
            evidence,
        )

        # =====================================================
        # 19. FINAL RESULT
        # =====================================================

        return {
            "risk_score": score,
            "confidence": confidence,
            "verdict": verdict,
            "detail_verdict": (
                ai_state
                or None
            ),
            "explanation": explanation,
            "evidence": evidence,
            "adaptive_info": adaptive,
            "structured_evidence": structured_evidence,
            "is_trusted_sender": (
                auth_fully_passed
                and trust_score >= 40
            ),
        }

    # =========================================================
    # EXPLANATION
    # =========================================================

    def generate_explanation(
        self,
        verdict,
        evidence,
    ):
        lines = [
            f"Overall Verdict: {verdict}",
            "",
        ]

        sections = [
            (
                "Positive Evidence",
                evidence.get(
                    "positive",
                    [],
                ),
            ),
            (
                "Technical",
                evidence.get(
                    "technical",
                    [],
                ),
            ),
            (
                "Behavioral",
                evidence.get(
                    "behavioral",
                    [],
                ),
            ),
            (
                "Network",
                evidence.get(
                    "network",
                    [],
                ),
            ),
            (
                "Negative Evidence",
                evidence.get(
                    "negative",
                    [],
                ),
            ),
        ]

        has_content = False

        for title, values in sections:

            if not values:
                continue

            has_content = True

            lines.append(
                f"{title}:"
            )

            seen = set()

            for item in values:

                text = str(item)

                if text in seen:
                    continue

                seen.add(text)

                lines.append(
                    f"- {text}"
                )

            lines.append("")

        if not has_content:
            lines.append(
                "No sufficient evidence was "
                "generated for this analysis."
            )

        return "\n".join(lines)