# pyrefly: ignore [missing-import]

from asyncio import selector_events
from src.config.scoring import SCORING


class AnalyticalReasoningEngine:
    """
    Evidence-first Analytical Reasoning Engine.

    Design principles:
    - Collect all available evidence before calculating the final verdict.
    - Risk score and confidence remain separate.
    - Historical evidence never overrides current evidence.
    - Authentication failure is distinct from authentication unavailability.
    - Structured evidence is preferred over string parsing.
    - Local AI contributes evidence but does not independently control the verdict.
    - Strong deterministic malicious evidence takes precedence over trust history.
    - Authentication success is a positive signal, not proof of legitimacy.
    - Limited context reduces confidence rather than automatically declaring safety.
    """

    TRUSTED_DOMAINS = {
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
    }

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
        "PRIVATE_IP_DESTINATION",
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
        "CREDENTIAL_FORM",
    }

    POSITIVE_TYPES = {
        "AUTHENTICATION_PASS",
        "VALID_HISTORICAL_EVIDENCE",
        "TRUSTED_SENDER",
        "ALIGNED_DOMAIN",
        "VALID_TLS",
        "SAFE_URL",
    }

    def __init__(self):
        self.rules = SCORING

    # =========================================================
    # DOMAIN HELPERS
    # =========================================================

    @staticmethod
    def _clean_domain(domain):
        domain = str(domain or "").strip().lower()

        if "://" in domain:
            domain = domain.split("://", 1)[1]

        domain = domain.split("/", 1)[0]
        domain = domain.split("?", 1)[0]
        domain = domain.split("#", 1)[0]
        domain = domain.split(":", 1)[0]

        return domain.strip(".")

    def _is_trusted_domain(self, domain):
        domain = self._clean_domain(domain)

        if not domain:
            return False

        for trusted in self.TRUSTED_DOMAINS:
            if (
                domain == trusted
                or domain.endswith("." + trusted)
            ):
                return True

        return False

    def _is_trusted_url_domain(self, url_item):
        if not isinstance(url_item, dict):
            return False

        domain = url_item.get("domain", "")

        return self._is_trusted_domain(domain)

    # =========================================================
    # NORMALIZATION HELPERS
    # =========================================================

    @staticmethod
    def _safe_number(value, default=0):
        try:
            number = float(value)

            if number != number:
                return float(default)

            return number

        except (TypeError, ValueError):
            return float(default)

    @staticmethod
    def _normalize_direction(value):
        value = str(value or "NEUTRAL").upper().strip()

        if value not in {
            "POSITIVE",
            "NEGATIVE",
            "NEUTRAL",
        }:
            return "NEUTRAL"

        return value

    @staticmethod
    def _normalize_severity(value):
        value = str(value or "INFO").upper().strip()

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
        Normalize dictionaries and object-based evidence
        into a consistent internal structure.
        """

        if isinstance(item, dict):

            confidence = self._safe_number(
                item.get("confidence", 0),
                0,
            )

            confidence = max(
                0,
                min(1, confidence),
            )

            return {
                "type": self._normalize_type(
                    item.get("type")
                ),
                "severity": self._normalize_severity(
                    item.get("severity")
                ),
                "direction": self._normalize_direction(
                    item.get("direction")
                ),
                "source": str(
                    item.get(
                        "source",
                        "UNKNOWN",
                    )
                    or "UNKNOWN"
                ),
                "explanation": str(
                    item.get(
                        "explanation",
                        "",
                    )
                    or ""
                ),
                "confidence": confidence,
            }

        confidence = self._safe_number(
            getattr(
                item,
                "confidence",
                0,
            ),
            0,
        )

        confidence = max(
            0,
            min(1, confidence),
        )

        return {
            "type": self._normalize_type(
                getattr(
                    item,
                    "type",
                    None,
                )
            ),
            "severity": self._normalize_severity(
                getattr(
                    item,
                    "severity",
                    None,
                )
            ),
            "direction": self._normalize_direction(
                getattr(
                    item,
                    "direction",
                    None,
                )
            ),
            "source": str(
                getattr(
                    item,
                    "source",
                    "UNKNOWN",
                )
                or "UNKNOWN"
            ),
            "explanation": str(
                getattr(
                    item,
                    "explanation",
                    "",
                )
                or ""
            ),
            "confidence": confidence,
        }

    def _collect_structured_items(
        self,
        target,
        items,
        default_category="behavioral",
    ):
        for item in items or []:

            normalized = self._structured_evidence(
                item
            )

            explanation = (
                normalized["explanation"]
                or normalized["type"]
            )

            target[default_category].append(
                explanation
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
            or "AVAILABLE"
        ).upper()

        if status == "UNAVAILABLE":
            return "UNAVAILABLE"

        spf = str(
            authentication.get(
                "spf",
                "",
            )
            or ""
        ).lower().strip()

        dkim = str(
            authentication.get(
                "dkim",
                "",
            )
            or ""
        ).lower().strip()

        dmarc = str(
            authentication.get(
                "dmarc",
                "",
            )
            or ""
        ).lower().strip()

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
            spf in {
                "",
                "unknown",
                "none",
            }
            and dkim in {
                "",
                "unknown",
                "none",
            }
            and dmarc in {
                "",
                "unknown",
                "none",
            }
        ):
            return "UNAVAILABLE"

        return "PARTIAL"

    # =========================================================
    # EVIDENCE STATE HELPERS
    # =========================================================

    def _has_current_negative_evidence(
        self,
        structured_items,
    ):
        for item in structured_items:

            if not isinstance(item, dict):
                continue

            if (
                item.get("direction")
                == "NEGATIVE"
                and (
                    item.get("type")
                    in (
                        self.CRITICAL_NEGATIVE_TYPES
                        | self.STRONG_NEGATIVE_TYPES
                    )
                    or item.get("severity")
                    in {
                        "HIGH",
                        "CRITICAL",
                    }
                )
            ):
                return True

        return False

    def _has_current_critical_evidence(
        self,
        structured_items,
    ):
        for item in structured_items:

            if not isinstance(item, dict):
                continue

            if (
                item.get("direction")
                == "NEGATIVE"
                and (
                    item.get("severity")
                    == "CRITICAL"
                    or item.get("type")
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

            if not isinstance(item, dict):
                continue

            if (
                item.get("direction")
                == "NEGATIVE"
                and (
                    item.get("severity")
                    in {
                        "HIGH",
                        "CRITICAL",
                    }
                    or item.get("type")
                    in (
                        self.CRITICAL_NEGATIVE_TYPES
                        | self.STRONG_NEGATIVE_TYPES
                    )
                )
            ):
                return True

        return False

    def _has_supporting_malicious_evidence(
        self,
        structured_items,
    ):
        return any(
            item.get("direction") == "NEGATIVE"
            and item.get("severity")
            in {
                "MEDIUM",
                "HIGH",
                "CRITICAL",
            }
            for item in structured_items
            if isinstance(item, dict)
        )

    def _has_unresolved_contradiction(
        self,
        ai_analysis,
        structured_items,
        historical_evidence,
    ):
        ai_analysis = ai_analysis or {}

        ai_state = str(
            ai_analysis.get(
                "reasoning_state",
                "",
            )
            or ""
        ).upper()

        if ai_state in {
            "CONFLICTING_EVIDENCE",
            "TRUST_HISTORY_CONFLICT",
            "AI_LEGITIMACY_CONFLICT",
        }:
            return True

        contradiction_engine = (
            ai_analysis.get(
                "contradictions_engine",
                {},
            )
            or {}
        )

        contradiction_state = str(
            contradiction_engine.get(
                "state",
                "",
            )
            or ""
        ).upper()

        if contradiction_state in {
            "CONFLICTING_EVIDENCE",
            "TRUST_HISTORY_CONFLICT",
        }:
            return True

        if historical_evidence:

            status = str(
                historical_evidence.get(
                    "status",
                    "",
                )
                or ""
            ).upper()

            if status == "CONFLICTING_EVIDENCE":
                return True

        return any(
            item.get("type")
            in {
                "CONFLICTING_EVIDENCE",
                "HISTORICAL_CURRENT_CONFLICT",
            }
            for item in structured_items
            if isinstance(item, dict)
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

    @staticmethod
    def _score_by_severity(
        severity,
        critical=30,
        high=20,
        medium=15,
        low=5,
        default=10,
    ):
        return {
            "CRITICAL": critical,
            "HIGH": high,
            "MEDIUM": medium,
            "LOW": low,
        }.get(
            severity,
            default,
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
        authentication = (
            authentication
            if isinstance(authentication, dict)
            else {}
        )

        url_analysis = (
            url_analysis
            if isinstance(url_analysis, dict)
            else {}
        )

        whois_analysis = (
            whois_analysis
            if isinstance(whois_analysis, list)
            else []
        )

        content_analysis = (
            content_analysis
            if isinstance(content_analysis, dict)
            else {}
        )

        attachment_analysis = (
            attachment_analysis
            if isinstance(attachment_analysis, dict)
            else {}
        )

        trust_analysis = (
            trust_analysis
            if isinstance(trust_analysis, dict)
            else {}
        )

        ai_analysis = (
            ai_analysis
            if isinstance(ai_analysis, dict)
            else {}
        )

        url_page_intelligence = (
            url_page_intelligence
            if isinstance(
                url_page_intelligence,
                dict,
            )
            else {}
        )

        historical_evidence = (
            historical_evidence
            if isinstance(
                historical_evidence,
                dict,
            )
            else None
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

        auth_rules = self.rules.get(
            "authentication",
            {},
        )

        url_rules = self.rules.get(
            "url",
            {},
        )

        content_rules = self.rules.get(
            "content",
            {},
        )

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
                authentication.get(
                    "spf",
                    "",
                )
                or ""
            ).lower()

            dkim = str(
                authentication.get(
                    "dkim",
                    "",
                )
                or ""
            ).lower()

            dmarc = str(
                authentication.get(
                    "dmarc",
                    "",
                )
                or ""
            ).lower()

            if spf == "fail":

                score += self._safe_number(
                    auth_rules.get(
                        "spf_fail",
                        15,
                    ),
                    15,
                )

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

            if dkim == "fail":

                score += self._safe_number(
                    auth_rules.get(
                        "dkim_fail",
                        15,
                    ),
                    15,
                )

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

            if dmarc == "fail":

                score += self._safe_number(
                    auth_rules.get(
                        "dmarc_fail",
                        20,
                    ),
                    20,
                )

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

            structured_evidence.append({
                "type": "AUTHENTICATION_PARTIAL",
                "severity": "INFO",
                "direction": "NEUTRAL",
                "source": "AuthenticationAnalyzer",
                "explanation": (
                    "Authentication evidence is incomplete; "
                    "missing authentication results are not "
                    "treated as authentication failure."
                ),
                "confidence": 0.80,
            })

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

        trust_score = max(
            0,
            min(
                100,
                trust_score,
            ),
        )

        auth_fully_passed = (
            auth_state == "PASSED"
        )

        aligned_url_count = sum(
            1
            for item in (
                url_analysis.get(
                    "analysis",
                    [],
                )
                or []
            )
            if isinstance(item, dict)
            and item.get(
                "email_alignment"
            ) == "aligned"
        )

        misaligned_url_count = sum(
            1
            for item in (
                url_analysis.get(
                    "analysis",
                    [],
                )
                or []
            )
            if isinstance(item, dict)
            and item.get(
                "email_alignment"
            ) == "misaligned"
        )

        strong_authenticated_context = (
            auth_fully_passed
            and aligned_url_count > 0
            and misaligned_url_count == 0
        )

        trusted_sender_context = (
            auth_fully_passed
            and (
                trust_score >= 40
                or strong_authenticated_context
            )
        )

        if trusted_sender_context:

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

            structured_evidence.append({
                "type": "TRUSTED_SENDER",
                "severity": "LOW",
                "direction": "POSITIVE",
                "source": "TrustAnalyzer",
                "explanation": (
                    "Sender has full authentication "
                    "and established trust context."
                ),
                "confidence": 0.90,
            })

        # =====================================================
        # 3. URL ANALYSIS
        # =====================================================

        for url in (
            url_analysis.get(
                "analysis",
                [],
            )
            or []
        ):

            if not isinstance(url, dict):
                continue

            # -------------------------------------------------
            # URL structured evidence
            # -------------------------------------------------

            for item in (
                url.get(
                    "structured_evidence",
                    [],
                )
                or []
            ):

                if not isinstance(item, dict):
                    continue

                evidence_type = str(
                    item.get(
                        "type",
                        "",
                    )
                    or ""
                ).upper()

                if evidence_type == "OFFICIAL_BRAND":

                    evidence["positive"].append(
                        "URL exactly matches a recognized "
                        "official domain."
                    )

                    structured_evidence.append({
                        "type": "OFFICIAL_BRAND",
                        "severity": "LOW",
                        "direction": "POSITIVE",
                        "source": "URLAnalyzer",
                        "explanation": (
                            "URL exactly matches a recognized "
                            "official domain."
                        ),
                        "confidence": self._safe_number(
                            item.get(
                                "confidence",
                                0.95,
                            ),
                            0.95,
                        ),
                    })

            # -------------------------------------------------
            # IP-based URL
            # -------------------------------------------------

            if url.get("ip_based"):

                score += self._safe_number(
                    url_rules.get(
                        "ip_url",
                        20,
                    ),
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

            # -------------------------------------------------
            # URL shortener
            # -------------------------------------------------

            if url.get("shortener"):

                score += self._safe_number(
                    url_rules.get(
                        "shortener",
                        10,
                    ),
                    10,
                )

                evidence["network"].append(
                    f"Shortened URL: {url.get('url', '')}"
                )

                structured_evidence.append({
                    "type": "SUSPICIOUS_URL",
                    "severity": "MEDIUM",
                    "direction": "NEGATIVE",
                    "source": "URLAnalyzer",
                    "explanation": (
                        "URL uses a URL-shortening service."
                    ),
                    "confidence": 0.75,
                })

            # -------------------------------------------------
            # Suspicious keywords
            # -------------------------------------------------

            keywords = url.get(
                "keywords",
                [],
            )

            if isinstance(
                keywords,
                str,
            ):
                keywords = [keywords]

            if keywords:

                keyword_score = (
                    len(keywords)
                    * self._safe_number(
                        url_rules.get(
                            "keyword",
                            5,
                        ),
                        5,
                    )
                )

                score += keyword_score

                evidence["network"].append(
                    "Suspicious URL keywords: "
                    + ", ".join(
                        str(k)
                        for k in keywords
                    )
                )

                structured_evidence.append({
                    "type": "SUSPICIOUS_URL",
                    "severity": "MEDIUM",
                    "direction": "NEGATIVE",
                    "source": "URLAnalyzer",
                    "explanation": (
                        "URL contains suspicious "
                        "security-sensitive keywords."
                    ),
                    "confidence": 0.75,
                })

            # -------------------------------------------------
            # Obfuscation
            # -------------------------------------------------

            if url.get("obfuscated"):

                score += self._safe_number(
                    url_rules.get(
                        "obfuscated",
                        15,
                    ),
                    15,
                )

                evidence["network"].append(
                    f"Obfuscated URL detected: "
                    f"{url.get('url', '')}"
                )

                structured_evidence.append({
                    "type": "SUSPICIOUS_URL",
                    "severity": "HIGH",
                    "direction": "NEGATIVE",
                    "source": "URLAnalyzer",
                    "explanation": (
                        "URL contains obfuscation indicators."
                    ),
                    "confidence": 0.90,
                })

            # -------------------------------------------------
            # Punycode
            # -------------------------------------------------

            if url.get("punycode"):

                score += self._safe_number(
                    url_rules.get(
                        "punycode",
                        20,
                    ),
                    20,
                )

                evidence["network"].append(
                    "Punycode domain detected: "
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

            # -------------------------------------------------
            # Suspicious port
            # -------------------------------------------------

            if url.get("suspicious_port"):

                score += self._safe_number(
                    url_rules.get(
                        "suspicious_port",
                        10,
                    ),
                    10,
                )

                evidence["network"].append(
                    "Suspicious URL port detected: "
                    f"{url.get('url', '')}"
                )

                structured_evidence.append({
                    "type": "SUSPICIOUS_URL",
                    "severity": "MEDIUM",
                    "direction": "NEGATIVE",
                    "source": "URLAnalyzer",
                    "explanation": (
                        "URL uses a suspicious network port."
                    ),
                    "confidence": 0.80,
                })

            # -------------------------------------------------
            # Excessive subdomains
            # -------------------------------------------------

            if (
                self._safe_number(
                    url.get(
                        "subdomain_count",
                        0,
                    ),
                    0,
                )
                > 3
            ):

                score += self._safe_number(
                    url_rules.get(
                        "excessive_subdomains",
                        10,
                    ),
                    10,
                )

                evidence["network"].append(
                    "Excessive subdomains detected: "
                    f"{url.get('domain', '')}"
                )

                structured_evidence.append({
                    "type": "SUSPICIOUS_URL",
                    "severity": "MEDIUM",
                    "direction": "NEGATIVE",
                    "source": "URLAnalyzer",
                    "explanation": (
                        "Domain contains an unusually "
                        "large number of subdomains."
                    ),
                    "confidence": 0.70,
                })

            # -------------------------------------------------
            # Brand intelligence
            # -------------------------------------------------

            if url.get(
                "brand_impersonation"
            ):

                score += 40

                domain = url.get(
                    "domain",
                    "",
                )

                evidence["network"].append(
                    "Brand impersonation detected: "
                    f"{domain}"
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

            # -------------------------------------------------
            # Email alignment
            # -------------------------------------------------

            alignment = str(
                url.get(
                    "email_alignment",
                    "",
                )
                or ""
            ).lower()

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

                structured_evidence.append({
                    "type": "ALIGNED_DOMAIN",
                    "severity": "LOW",
                    "direction": "POSITIVE",
                    "source": "URLAnalyzer",
                    "explanation": (
                        "URL domain aligns with "
                        "the sender domain."
                    ),
                    "confidence": 0.90,
                })

            # -------------------------------------------------
            # DNS
            # -------------------------------------------------

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

            # -------------------------------------------------
            # Redirects
            # -------------------------------------------------

            redirects = url.get(
                "redirects",
                {},
            ) or {}

            if (
                redirects.get(
                    "external_domain_change"
                )
                and not self._is_trusted_url_domain(
                    url
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

            # -------------------------------------------------
            # TLS
            # -------------------------------------------------

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

                structured_evidence.append({
                    "type": "VALID_TLS",
                    "severity": "LOW",
                    "direction": "POSITIVE",
                    "source": "TLSInspector",
                    "explanation": (
                        "TLS certificate validation "
                        "completed successfully."
                    ),
                    "confidence": 0.90,
                })

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
                    "TLS Policy Violation "
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

                structured_evidence.append({
                    "type": "TLS_POLICY_VIOLATION",
                    "severity": "LOW",
                    "direction": "NEGATIVE",
                    "source": "TLSInspector",
                    "explanation": (
                        "URL uses insecure HTTP transport."
                    ),
                    "confidence": 0.85,
                })

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

            if not isinstance(whois, dict):
                continue

            domain = whois.get(
                "domain",
                "Unknown",
            )

            age_category = str(
                whois.get(
                    "age_category",
                    "",
                )
                or ""
            ).lower()

            error = whois.get(
                "error"
            )

            if error:

                evidence["network"].append(
                    "WHOIS lookup unavailable for: "
                    f"{domain}"
                )

            elif age_category == "new":

                score += self._safe_number(
                    whois_rules.get(
                        "new_domain",
                        15,
                    ),
                    15,
                )

                evidence["network"].append(
                    "Newly registered domain detected: "
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

                score += self._safe_number(
                    whois_rules.get(
                        "recent_domain",
                        5,
                    ),
                    5,
                )

                evidence["network"].append(
                    "Recently registered domain: "
                    f"{domain}"
                )

                structured_evidence.append({
                    "type": "NEW_DOMAIN",
                    "severity": "LOW",
                    "direction": "NEGATIVE",
                    "source": "WhoisAnalyzer",
                    "explanation": (
                        f"Recently registered domain: "
                        f"{domain}"
                    ),
                    "confidence": 0.70,
                })

        # =====================================================
        # 5. CONTENT ANALYSIS
        # =====================================================

        content_status = str(
            content_analysis.get(
                "analysis_status",
                "AVAILABLE",
            )
            or "AVAILABLE"
        ).upper()

        if content_status == "UNAVAILABLE":

            evidence["behavioral"].append(
                "Content analysis unavailable"
            )

        else:

            # -------------------------------------------------
            # Urgency
            # -------------------------------------------------

            if content_analysis.get(
                "urgency"
            ):

                score += self._safe_number(
                    content_rules.get(
                        "urgency",
                        20,
                    ),
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

            # -------------------------------------------------
            # Credential request
            # -------------------------------------------------

            if content_analysis.get(
                "credential_request"
            ):

                score += self._safe_number(
                    content_rules.get(
                        "credential_request",
                        25,
                    ),
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

            # -------------------------------------------------
            # Financial request
            # -------------------------------------------------

            if content_analysis.get(
                "financial_request"
            ):

                score += self._safe_number(
                    content_rules.get(
                        "financial_request",
                        25,
                    ),
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

            # -------------------------------------------------
            # Impersonation
            # -------------------------------------------------

            if content_analysis.get(
                "impersonation"
            ):

                score += self._safe_number(
                    content_rules.get(
                        "impersonation",
                        10,
                    ),
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

            # -------------------------------------------------
            # Threat language
            # -------------------------------------------------

            if content_analysis.get(
                "threat_language"
            ):

                score += self._safe_number(
                    content_rules.get(
                        "threat_language",
                        20,
                    ),
                    20,
                )

                evidence["behavioral"].append(
                    "Threat language detected"
                )

                structured_evidence.append({
                    "type": "THREAT_LANGUAGE",
                    "severity": "MEDIUM",
                    "direction": "NEGATIVE",
                    "source": "ContentAnalyzer",
                    "explanation": (
                        "Threat or coercive language "
                        "was detected."
                    ),
                    "confidence": 0.80,
                })

        # =====================================================
        # 6. ATTACHMENTS
        # =====================================================

        attachment_status = str(
            attachment_analysis.get(
                "analysis_status",
                "AVAILABLE",
            )
            or "AVAILABLE"
        ).upper()

        if attachment_status == "UNAVAILABLE":

            evidence["technical"].append(
                "Attachment analysis unavailable"
            )

        else:

            attachment_config = (
                self.rules.get(
                    "attachment",
                    {},
                )
            )

            attachment_risk = self._safe_number(
                attachment_analysis.get(
                    "risk_score",
                    0,
                ),
                0,
            )

            risk_multiplier = self._safe_number(
                attachment_config.get(
                    "risk_multiplier",
                    1,
                ),
                1,
            )

            score += (
                attachment_risk
                * risk_multiplier
            )

            for item in (
                attachment_analysis.get(
                    "evidence",
                    [],
                )
                or []
            ):

                text = str(
                    item
                    or ""
                )

                if not text:
                    continue

                evidence["technical"].append(
                    text
                )

                lowered = text.lower()

                if (
                    "executable attachment"
                    in lowered
                ):

                    structured_evidence.append({
                        "type": "EXECUTABLE_ATTACHMENT",
                        "severity": "CRITICAL",
                        "direction": "NEGATIVE",
                        "source": "AttachmentAnalyzer",
                        "explanation": text,
                        "confidence": 0.98,
                    })

                elif (
                    "script attachment"
                    in lowered
                ):

                    structured_evidence.append({
                        "type": "SCRIPT_ATTACHMENT",
                        "severity": "CRITICAL",
                        "direction": "NEGATIVE",
                        "source": "AttachmentAnalyzer",
                        "explanation": text,
                        "confidence": 0.97,
                    })

                elif (
                    "macro-enabled"
                    in lowered
                    or "macro enabled"
                    in lowered
                ):

                    structured_evidence.append({
                        "type": "MACRO_ATTACHMENT",
                        "severity": "HIGH",
                        "direction": "NEGATIVE",
                        "source": "AttachmentAnalyzer",
                        "explanation": text,
                        "confidence": 0.95,
                    })

                elif (
                    "malicious attachment"
                    in lowered
                ):

                    structured_evidence.append({
                        "type": "MALICIOUS_ATTACHMENT",
                        "severity": "CRITICAL",
                        "direction": "NEGATIVE",
                        "source": "AttachmentAnalyzer",
                        "explanation": text,
                        "confidence": 0.98,
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
            # -----------------------------------------
            # URL Threat Intelligence
            # -----------------------------------------

            for url_item in (
                url_analysis.get(
                    "analysis",
                    [],
                )
                or []
            ):

                if not isinstance(
                    url_item,
                    dict,
                ):
                    continue

                threat_intelligence = (
                    url_item.get(
                        "threat_intelligence",
                        {},
                    )
                    or {}
                )

                if not isinstance(
                    threat_intelligence,
                    dict,
                ):
                    continue

                if not threat_intelligence.get(
                    "available"
                ):
                    continue

                status = str(
                    threat_intelligence.get(
                        "status",
                        "",
                    )
                    or ""
                ).lower()

                detections = self._safe_number(
                    threat_intelligence.get(
                        "detections",
                        0,
                    ),
                    0,
                )

                if (
                    status
                    in {
                        "malicious",
                        "phishing",
                        "unsafe",
                        "dangerous",
                    }
                    or detections > 0
                ):

                    score += 50

                    evidence["network"].append(
                        "URL threat intelligence "
                        "detected malicious activity"
                    )

                    structured_evidence.append({
                        "type": (
                            "THREAT_INTELLIGENCE_DETECTION"
                        ),
                        "severity": "CRITICAL",
                        "direction": "NEGATIVE",
                        "source": "ThreatIntelligence",
                        "explanation": (
                            "Threat intelligence detected "
                            f"the URL as {status or 'malicious'} "
                            f"with {detections} detection(s)."
                        ),
                        "confidence": 0.99,
                    })
            if url_page_intelligence:

                page_risk_found = False

                for url, page_data in (
                    url_page_intelligence.items()
                ):

                    page_data = (
                        page_data
                        if isinstance(
                            page_data,
                            dict,
                        )
                        else {}
                    )

                    security = (
                        page_data.get(
                            "security",
                            {},
                        )
                        or {}
                    )

                    if security.get(
                        "error"
                    ):

                        evidence["network"].append(
                            f"Page fetch failed/blocked "
                            f"for {url}"
                        )

                    forms = (
                        page_data.get(
                            "forms",
                            {},
                        )
                        or {}
                    )

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

                    # -----------------------------------------
                    # Password field
                    # -----------------------------------------

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

                    # -----------------------------------------
                    # Email/login field
                    # -----------------------------------------

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

                    # -----------------------------------------
                    # Page AI
                    # -----------------------------------------

                    page_ai = (
                        page_data.get(
                            "ai",
                            {},
                        )
                        or {}
                    )

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

                        page_confidence = (
                            self._safe_number(
                                page_ai.get(
                                    "confidence",
                                    0,
                                ),
                                0,
                            )
                        )

                        if page_confidence > 1:
                            page_confidence /= 100

                        page_confidence = max(
                            0,
                            min(
                                1,
                                page_confidence,
                            ),
                        )

                        structured_evidence.append({
                            "type": page_intent,
                            "severity": "CRITICAL",
                            "direction": "NEGATIVE",
                            "source": "LocalAI",
                            "explanation": (
                                "Local page-intent analysis "
                                f"identified {page_intent}."
                            ),
                            "confidence": page_confidence,
                        })

                if not page_risk_found:

                    evidence["positive"].append(
                        "Deep URL inspection found no "
                        "immediate page-level risk."
                    )

                    structured_evidence.append({
                        "type": "SAFE_URL",
                        "severity": "LOW",
                        "direction": "POSITIVE",
                        "source": "URLPageInspection",
                        "explanation": (
                            "Deep URL inspection found no "
                            "immediate page-level risk."
                        ),
                        "confidence": 0.70,
                    })

        # =====================================================
        # 8. LOCAL AI / STAGE 6-10 EVIDENCE
        # =====================================================

        ai_state = str(
            ai_analysis.get(
                "reasoning_state",
                "",
            )
            or ""
        ).upper()

        ai_confidence = self._safe_number(
            ai_analysis.get(
                "confidence",
                0,
            ),
            0,
        )

        if ai_confidence > 1:
            ai_confidence /= 100

        ai_confidence = max(
            0,
            min(
                1,
                ai_confidence,
            ),
        )

        original_ai_state = ai_state

        ai_structured = []

        # -----------------------------------------------------
        # Structured Local AI evidence
        # -----------------------------------------------------

        for item in (
            ai_analysis.get(
                "structured_evidence",
                [],
            )
            or []
        ):

            normalized = (
                self._structured_evidence(
                    item
                )
            )

            ai_structured.append(
                normalized
            )

            structured_evidence.append(
                normalized
            )

        # -----------------------------------------------------
        # AI contradictions
        # -----------------------------------------------------

        for contradiction in (
            ai_analysis.get(
                "contradictions",
                [],
            )
            or []
        ):

            if isinstance(
                contradiction,
                dict,
            ):

                text = str(
                    contradiction.get(
                        "explanation",
                        "Conflicting evidence detected.",
                    )
                    or "Conflicting evidence detected."
                )

            else:

                text = str(
                    contradiction
                    or "Conflicting evidence detected."
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

            ai_state = (
                "CONFLICTING_EVIDENCE"
            )

        # -----------------------------------------------------
        # Homoglyph
        # -----------------------------------------------------

        for item in (
            ai_analysis.get(
                "homoglyph",
                [],
            )
            or []
        ):

            if isinstance(
                item,
                dict,
            ):

                text = str(
                    item.get(
                        "evidence",
                        "Homoglyph detected",
                    )
                    or "Homoglyph detected"
                )

                item_confidence = (
                    self._safe_number(
                        item.get(
                            "confidence",
                            0.90,
                        ),
                        0.90,
                    )
                )

                if item_confidence > 1:
                    item_confidence /= 100

            else:

                text = str(
                    item
                    or "Homoglyph detected"
                )

                item_confidence = 0.90

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
                "confidence": max(
                    0,
                    min(
                        1,
                        item_confidence,
                    ),
                ),
            })

        # -----------------------------------------------------
        # Brand intelligence
        # -----------------------------------------------------

        for item in (
            ai_analysis.get(
                "brand_intelligence",
                [],
            )
            or []
        ):

            if not isinstance(
                item,
                dict,
            ):
                continue

            if item.get(
                "impersonation_risk"
            ):

                score += 40

                explanation = str(
                    item.get(
                        "explanation",
                        "Brand impersonation detected.",
                    )
                    or "Brand impersonation detected."
                )

                confidence = self._safe_number(
                    item.get(
                        "confidence",
                        0.95,
                    ),
                    0.95,
                )

                if confidence > 1:
                    confidence /= 100

                evidence["behavioral"].append(
                    explanation
                )

                structured_evidence.append({
                    "type": "BRAND_IMPERSONATION",
                    "severity": "CRITICAL",
                    "direction": "NEGATIVE",
                    "source": "BrandIntelligence",
                    "explanation": explanation,
                    "confidence": max(
                        0,
                        min(
                            1,
                            confidence,
                        ),
                    ),
                })

            elif (
                item.get("brand_mentioned")
                and not item.get(
                    "domain_claimed"
                )
            ):

                explanation = str(
                    item.get(
                        "explanation",
                        "Brand mentioned without "
                        "domain alignment.",
                    )
                    or "Brand mentioned without "
                    "domain alignment."
                )

                evidence["behavioral"].append(
                    explanation
                )

        # -----------------------------------------------------
        # Adversarial analysis
        # -----------------------------------------------------

        for item in (
            ai_analysis.get(
                "adversarial",
                [],
            )
            or []
        ):

            if not isinstance(
                item,
                dict,
            ):
                continue

            explanation = str(
                item.get(
                    "explanation",
                    "",
                )
                or ""
            )

            if explanation:
                evidence["behavioral"].append(
                    explanation
                )

            severity = self._normalize_severity(
                item.get(
                    "severity",
                    "MEDIUM",
                )
            )

            direction = self._normalize_direction(
                item.get(
                    "direction",
                    "NEGATIVE",
                )
            )

            confidence = self._safe_number(
                item.get(
                    "confidence",
                    0,
                ),
                0,
            )

            if confidence > 1:
                confidence /= 100

            if direction == "NEGATIVE":

                score += self._score_by_severity(
                    severity,
                    critical=30,
                    high=25,
                    medium=15,
                    low=5,
                    default=10,
                )

            structured_evidence.append({
                "type": "ADVERSARIAL_INDICATOR",
                "severity": severity,
                "direction": direction,
                "source": "AdversarialAnalyzer",
                "explanation": explanation,
                "confidence": max(
                    0,
                    min(
                        1,
                        confidence,
                    ),
                ),
            })

        # -----------------------------------------------------
        # Contradiction engine
        # -----------------------------------------------------

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
                or ""
            ).upper()

            explanation = str(
                contradiction_engine.get(
                    "explanation",
                    "Conflicting evidence detected.",
                )
                or "Conflicting evidence detected."
            )

            contradiction_confidence = (
                self._safe_number(
                    contradiction_engine.get(
                        "confidence",
                        0,
                    ),
                    0,
                )
            )

            if contradiction_confidence > 1:
                contradiction_confidence /= 100

            evidence["behavioral"].append(
                explanation
            )

            contradiction_type = (
                "TRUST_HISTORY_CONFLICT"
                if contradiction_state
                == "TRUST_HISTORY_CONFLICT"
                else "CONFLICTING_EVIDENCE"
            )

            structured_evidence.append({
                "type": contradiction_type,
                "severity": "HIGH",
                "direction": "NEUTRAL",
                "source": "ContradictionEngine",
                "explanation": explanation,
                "confidence": max(
                    0,
                    min(
                        1,
                        contradiction_confidence,
                    ),
                ),
            })

            if contradiction_state == (
                "TRUST_HISTORY_CONFLICT"
            ):

                ai_state = (
                    "TRUST_HISTORY_CONFLICT"
                )

            elif contradiction_state == (
                "CONFLICTING_EVIDENCE"
            ):

                ai_state = (
                    "CONFLICTING_EVIDENCE"
                )

            elif contradiction_state == (
                "INSUFFICIENT_EVIDENCE"
            ):

                ai_state = (
                    "INSUFFICIENT_EVIDENCE"
                )

        # -----------------------------------------------------
        # Behavioral intelligence
        # -----------------------------------------------------

        for item in (
            ai_analysis.get(
                "behavioral",
                [],
            )
            or []
        ):

            normalized = (
                self._structured_evidence(
                    item
                )
            )

            evidence["behavioral"].append(
                normalized["explanation"]
                or normalized["type"]
            )

            structured_evidence.append(
                normalized
            )

            if (
                normalized["direction"]
                == "NEGATIVE"
            ):

                score += self._score_by_severity(
                    normalized["severity"],
                    critical=30,
                    high=20,
                    medium=15,
                    low=5,
                    default=10,
                )

        # -----------------------------------------------------
        # Campaign intelligence
        # -----------------------------------------------------

        for item in (
            ai_analysis.get(
                "campaign",
                [],
            )
            or []
        ):

            normalized = (
                self._structured_evidence(
                    item
                )
            )

            evidence["behavioral"].append(
                normalized["explanation"]
                or normalized["type"]
            )

            structured_evidence.append(
                normalized
            )

            if (
                normalized["direction"]
                == "NEGATIVE"
            ):

                score += self._score_by_severity(
                    normalized["severity"],
                    critical=30,
                    high=25,
                    medium=15,
                    low=5,
                    default=10,
                )

        # -----------------------------------------------------
        # Temporal intelligence
        # -----------------------------------------------------

        for item in (
            ai_analysis.get(
                "temporal",
                [],
            )
            or []
        ):

            normalized = (
                self._structured_evidence(
                    item
                )
            )

            evidence["behavioral"].append(
                normalized["explanation"]
                or normalized["type"]
            )

            structured_evidence.append(
                normalized
            )

            if (
                normalized["direction"]
                == "NEGATIVE"
            ):

                score += self._score_by_severity(
                    normalized["severity"],
                    critical=25,
                    high=20,
                    medium=15,
                    low=5,
                    default=10,
                )

        # =====================================================
        # 8A. SENDER REPUTATION
        # =====================================================

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
            or "UNKNOWN"
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

            if not ai_state:
                ai_state = "NEW_SENDER"

        elif reputation_status in {
            "SUSPICIOUS",
            "HIGH_RISK",
        }:

            ai_state = "SUSPICIOUS_HISTORY"

            structured_evidence.append({
                "type": "SUSPICIOUS_HISTORY",
                "severity": "HIGH",
                "direction": "NEGATIVE",
                "source": "SenderReputation",
                "explanation": (
                    "Sender reputation indicates "
                    "suspicious or high-risk history."
                ),
                "confidence": 0.80,
            })

            score += 15

        # =====================================================
        # 8B. ADAPTIVE INTELLIGENCE
        # =====================================================

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

            explanation = str(
                anomaly.get(
                    "explanation",
                    "",
                )
                or ""
            )

            if explanation:
                evidence["behavioral"].append(
                    explanation
                )

            severity = self._normalize_severity(
                anomaly.get(
                    "severity",
                    "MEDIUM",
                )
            )

            direction = self._normalize_direction(
                anomaly.get(
                    "direction",
                    "NEGATIVE",
                )
            )

            confidence = self._safe_number(
                anomaly.get(
                    "confidence",
                    0,
                ),
                0,
            )

            if confidence > 1:
                confidence /= 100

            if direction == "NEGATIVE":

                score += self._score_by_severity(
                    severity,
                    critical=30,
                    high=20,
                    medium=10,
                    low=5,
                    default=10,
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
                "type": (
                    anomaly_type
                    or "BEHAVIORAL_ANOMALY"
                ),
                "severity": severity,
                "direction": direction,
                "source": "AdaptiveIntelligence",
                "explanation": explanation,
                "confidence": max(
                    0,
                    min(
                        1,
                        confidence,
                    ),
                ),
            })

        trend = (
            adaptive.get(
                "risk_trend",
                {},
            )
            or {}
        ).get(
            "trend"
        )

        trend = str(
            trend or ""
        ).upper()

        if trend == "DEGRADING":

            score += 15

            evidence["behavioral"].append(
                "Risk trend is degrading over time."
            )

            structured_evidence.append({
                "type": "CAMPAIGN_ANOMALY",
                "severity": "MEDIUM",
                "direction": "NEGATIVE",
                "source": "AdaptiveIntelligence",
                "explanation": (
                    "Risk trend is degrading over time."
                ),
                "confidence": 0.75,
            })

        elif trend == "IMPROVING":

            score -= 5

            evidence["positive"].append(
                "Historical risk trend is improving."
            )

        history_confidence = (
            adaptive.get(
                "history_confidence",
                {},
            )
            or {}
        ).get(
            "level"
        )

        history_confidence = str(
            history_confidence or ""
        ).upper()

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

        historical_status = str(
            historical_status or ""
        ).upper()

        if (
            historical_status
            == "VALID_HISTORICAL_EVIDENCE"
        ):

            record = (
                historical_evidence.get(
                    "record",
                    {},
                )
                or {}
            )

            historical = (
                record.get(
                    "historical",
                    {},
                )
                or {}
            )

            historical_verdict = str(
                historical.get(
                    "verdict",
                    "",
                )
                or ""
            ).upper()

            history_state = (
                record.get(
                    "history_state",
                    {},
                )
                or {}
            )

            freshness = self._safe_number(
                history_state.get(
                    "freshness",
                    0,
                ),
                0,
            )

            if freshness > 1:
                freshness /= 100

            freshness = max(
                0,
                min(
                    1,
                    freshness,
                ),
            )

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
                        "type": (
                            "HISTORICAL_CURRENT_CONFLICT"
                        ),
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
                        "type": (
                            "VALID_HISTORICAL_EVIDENCE"
                        ),
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

            structured_evidence.append({
                "type": "STALE_HISTORICAL_EVIDENCE",
                "severity": "INFO",
                "direction": "NEUTRAL",
                "source": "VerdictStore",
                "explanation": (
                    "Historical evidence was ignored "
                    "because it is stale."
                ),
                "confidence": 0.50,
            })

        # =====================================================
        # 10. FINAL SCORE
        # =====================================================

        raw_score = score

        # Critical malicious evidence must contribute to
        # the numeric risk score as well as the verdict.
        if self._has_current_critical_evidence(
            structured_evidence
        ):
            score = max(
                score,
                80,
            )

        score = self._clamp_score(
            score
        )

        # =====================================================
        # 11. CURRENT EVIDENCE STATE
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

        negative_sources = {
            item.get("source")
            for item in structured_evidence
            if (
                isinstance(item, dict)
                and item.get("direction")
                == "NEGATIVE"
                and item.get("source")
            )
        }

        positive_sources = {
            item.get("source")
            for item in structured_evidence
            if (
                isinstance(item, dict)
                and item.get("direction")
                == "POSITIVE"
                and item.get("source")
            )
        }

        independent_negative_sources = len(
            negative_sources
        )

        independent_positive_sources = len(
            positive_sources
        )

        # Confidence is evidence quality,
        # not simply risk score.

        if (
            has_critical
            and independent_negative_sources >= 2
        ):

            confidence = 95

        elif has_critical:

            confidence = 90

        elif (
            has_strong
            and independent_negative_sources >= 2
        ):

            confidence = 85

        elif (
            has_strong
            and independent_negative_sources >= 1
        ):

            confidence = 75

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

        # AI confidence can reduce confidence,
        # but AI cannot manufacture confidence.

        if ai_confidence > 0:

            ai_confidence_percent = (
                ai_confidence * 100
            )

            confidence = min(
                confidence,
                int(
                    round(
                        max(
                            40,
                            ai_confidence_percent,
                        )
                    )
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

        elif raw_score >= 80:

            verdict = "PHISHING"

        elif raw_score >= 60:

            verdict = "HIGH RISK"

        elif raw_score >= 40:

            verdict = "SUSPICIOUS"

        elif has_strong:

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

        elif raw_score < 20:

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

        # -----------------------------------------------------
        # AI says safe but deterministic evidence says malicious
        # -----------------------------------------------------

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

            confidence = max(
                confidence,
                90,
            )

        # -----------------------------------------------------
        # AI says phishing without deterministic evidence
        # -----------------------------------------------------

        elif (
            recommended == "PHISHING"
            and not has_negative
            and raw_score < 30
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

            structured_evidence.append({
                "type": "AI_INSUFFICIENT_EVIDENCE",
                "severity": "MEDIUM",
                "direction": "NEUTRAL",
                "source": "SanityValidator",
                "explanation": (
                    "AI recommended phishing, but "
                    "independent malicious evidence "
                    "was insufficient."
                ),
                "confidence": ai_confidence,
            })

        # -----------------------------------------------------
        # AI suspicious vs strong legitimacy
        # -----------------------------------------------------

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
        # 17. FINAL SAFETY VALIDATION
        # =====================================================

        # Recalculate current evidence after all AI,
        # historical and adaptive evidence has been added.

        final_has_critical = (
            self._has_current_critical_evidence(
                structured_evidence
            )
        )

        final_has_negative = (
            self._has_current_negative_evidence(
                structured_evidence
            )
        )

        final_has_strong = (
            self._has_current_strong_evidence(
                structured_evidence
            )
        )

        final_contradiction = (
            self._has_unresolved_contradiction(
                ai_analysis,
                structured_evidence,
                historical_evidence,
            )
        )

        # Absolute deterministic safety rule:
        # critical malicious evidence cannot result in
        # a legitimate verdict.

        if final_has_critical:

            verdict = "PHISHING"

            confidence = max(
                confidence,
                90,
            )

            ai_state = "MALICIOUS_EVIDENCE"

        # A legitimate verdict with meaningful negative
        # evidence is never allowed.

        if (
            verdict
            in {
                "VERIFIED LEGITIMATE",
                "LIKELY LEGITIMATE",
            }
            and final_has_negative
        ):

            verdict = "UNKNOWN"

            confidence = min(
                confidence,
                50,
            )

            ai_state = (
                "CONFLICTING_EVIDENCE"
            )

        # Strong negative evidence should prevent
        # an unsupported legitimate verdict.

        if (
            final_has_strong
            and verdict
            in {
                "VERIFIED LEGITIMATE",
                "LIKELY LEGITIMATE",
            }
        ):

            verdict = "SUSPICIOUS"

            confidence = min(
                confidence,
                65,
            )

        # Contradictions reduce confidence.
        # Strong current negative evidence takes precedence
        # over contradiction handling.

        if final_contradiction:

            confidence = min(
                confidence,
                50,
            )

            if (
                not final_has_critical
                and not final_has_strong
                and verdict != "PHISHING"
            ):

                verdict = "UNKNOWN"

                if not ai_state:
                    ai_state = (
                        "CONFLICTING_EVIDENCE"
                    )

        # Limited context prevents high-confidence
        # legitimacy.

        if (
            limited_context
            and not final_has_critical
        ):

            if (
                final_has_strong
                or final_has_negative
            ):

                if verdict in {
                    "VERIFIED LEGITIMATE",
                    "LIKELY LEGITIMATE",
                }:

                    verdict = "UNKNOWN"

                confidence = min(
                    confidence,
                    50,
                )

            elif (
                independent_positive_sources >= 3
                and not final_contradiction
            ):

                verdict = "LIKELY LEGITIMATE"

                confidence = min(
                    confidence,
                    75,
                )

                ai_state = "LIMITED_CONTEXT"

            else:

                verdict = "UNKNOWN"

                confidence = min(
                    confidence,
                    50,
                )

        # =====================================================
        # 18. FINAL EXPLANATION
        # =====================================================

        explanation = self.generate_explanation(
            verdict,
            evidence,
        )

        if (
            trusted_sender_context
            and not final_has_negative
            and not final_has_critical
            and not final_has_strong
        ):
            score -= 30

        if final_has_critical:
            score = max(
                score,
                80,
            )

        score = self._clamp_score(
            score
        )

        confidence = self._clamp_confidence(
            confidence
        )

        # =====================================================
        # 19. TRUSTED SENDER RESULT
        # =====================================================

        is_trusted_sender = bool(
            auth_fully_passed
            and trust_score >= 40
            and not final_has_critical
            and not final_has_strong
        )

        # =====================================================
        # 20. FINAL RESULT
        # =====================================================

        return {
            "risk_score": score,
            "confidence": confidence,
            "verdict": verdict,
            "detail_verdict": (
                ai_state
                or original_ai_state
                or None
            ),
            "explanation": explanation,
            "evidence": evidence,
            "adaptive_info": adaptive,
            "structured_evidence": structured_evidence,
            "is_trusted_sender": (
                is_trusted_sender
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

                text = str(
                    item
                    or ""
                ).strip()

                if not text:
                    continue

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