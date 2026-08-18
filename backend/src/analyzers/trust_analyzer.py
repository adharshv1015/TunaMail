# ============================================================
# backend/src/analyzers/trust_analyzer.py
# ============================================================

from __future__ import annotations

from email.utils import parseaddr
from typing import Any, Dict, List, Set


class TrustAnalyzer:
    """
    Deterministic sender/domain trust analyzer.

    Important:
    - Trust is supporting evidence, never a final SAFE decision.
    - A trusted sender can still be compromised.
    - A trusted URL does not automatically make the email safe.
    - Exact domain/subdomain matching is used to avoid lookalike
      domain mistakes.
    """

    def __init__(self):
        self.known_organizations = {
            "google": {
                "sender_domains": {
                    "google.com",
                    "gmail.com",
                    "googlemail.com",
                },
                "url_domains": {
                    "google.com",
                    "gmail.com",
                    "googleusercontent.com",
                    "gstatic.com",
                    "googleapis.com",
                    "accounts.google.com",
                    "myaccount.google.com",
                    "mail.google.com",
                },
            },
            "microsoft": {
                "sender_domains": {
                    "microsoft.com",
                    "outlook.com",
                    "office.com",
                    "account.microsoft.com",
                    "accountprotection.microsoft.com",
                },
                "url_domains": {
                    "microsoft.com",
                    "microsoftonline.com",
                    "office.com",
                    "live.com",
                    "outlook.com",
                    "account.microsoft.com",
                    "accountprotection.microsoft.com",
                },
            },
            "apple": {
                "sender_domains": {
                    "apple.com",
                    "icloud.com",
                    "id.apple.com",
                },
                "url_domains": {
                    "apple.com",
                    "icloud.com",
                    "appleid.apple.com",
                    "id.apple.com",
                },
            },
            "amazon": {
                "sender_domains": {
                    "amazon.com",
                    "amazon.in",
                },
                "url_domains": {
                    "amazon.com",
                    "amazon.in",
                    "amazonaws.com",
                },
            },
            "paypal": {
                "sender_domains": {
                    "paypal.com",
                },
                "url_domains": {
                    "paypal.com",
                },
            },
            "github": {
                "sender_domains": {
                    "github.com",
                },
                "url_domains": {
                    "github.com",
                    "githubusercontent.com",
                },
            },
            "linkedin": {
                "sender_domains": {
                    "linkedin.com",
                    "e.linkedin.com",
                },
                "url_domains": {
                    "linkedin.com",
                    "lnkd.in",
                },
            },
            "meta": {
                "sender_domains": {
                    "meta.com",
                    "facebook.com",
                    "instagram.com",
                },
                "url_domains": {
                    "meta.com",
                    "facebook.com",
                    "instagram.com",
                },
            },
            "x": {
                "sender_domains": {
                    "x.com",
                    "twitter.com",
                },
                "url_domains": {
                    "x.com",
                    "twitter.com",
                },
            },
            "dropbox": {
                "sender_domains": {
                    "dropbox.com",
                },
                "url_domains": {
                    "dropbox.com",
                },
            },
            "cloudflare": {
                "sender_domains": {
                    "cloudflare.com",
                },
                "url_domains": {
                    "cloudflare.com",
                },
            },
        }

    # ========================================================
    # Main API
    # ========================================================

    def analyze(
        self,
        parsed_email: Dict[str, Any] | None,
        url_analysis: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:

        parsed_email = (
            parsed_email
            if isinstance(parsed_email, dict)
            else {}
        )

        url_analysis = (
            url_analysis
            if isinstance(url_analysis, dict)
            else {}
        )

        return self.evaluate(
            parsed_email,
            url_analysis,
        )

    def evaluate(
        self,
        parsed_email: Dict[str, Any] | None,
        url_analysis: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:

        parsed_email = (
            parsed_email
            if isinstance(parsed_email, dict)
            else {}
        )

        url_analysis = (
            url_analysis
            if isinstance(url_analysis, dict)
            else {}
        )

        score = 0

        evidence: List[str] = []
        structured_evidence: List[
            Dict[str, Any]
        ] = []

        # ----------------------------------------------------
        # Sender
        # ----------------------------------------------------

        sender_raw = (
            parsed_email.get(
                "from",
                "",
            )
            or parsed_email.get(
                "sender",
                "",
            )
            or ""
        )

        sender_name, email_address = parseaddr(
            str(sender_raw)
        )

        email_address = (
            email_address
            or ""
        ).strip().lower()

        sender_domain = self._extract_domain(
            email_address
        )

        sender_org = (
            self.get_organization(
                sender_domain
            )
            if sender_domain
            else None
        )

        # ----------------------------------------------------
        # Authentication state
        # ----------------------------------------------------

        authentication = (
            parsed_email.get(
                "authentication",
                parsed_email.get(
                    "auth",
                    {},
                ),
            )
            or {}
        )

        auth_state = self._authentication_state(
            authentication
        )

        auth_fully_passed = (
            auth_state == "PASSED"
        )

        # ----------------------------------------------------
        # URL records
        # ----------------------------------------------------

        url_items = (
            url_analysis.get(
                "analysis",
                [],
            )
            or []
        )

        trusted_organizations: Set[
            str
        ] = set()

        suspicious_url_count = 0
        critical_url_count = 0
        aligned_url_count = 0
        mismatched_url_count = 0

        # ----------------------------------------------------
        # Sender organization trust
        #
        # This is only supporting evidence.
        # Authentication can strengthen it but does not
        # make it an unconditional safe state.
        # ----------------------------------------------------

        if sender_org:

            score += 10

            message = (
                f"Recognized sender organization: "
                f"{sender_org.capitalize()}"
            )

            evidence.append(
                message
            )

            structured_evidence.append(
                self._evidence(
                    type_="TRUSTED_SENDER",
                    severity="LOW",
                    direction="POSITIVE",
                    source="TrustAnalyzer",
                    explanation=message,
                    confidence=0.85,
                )
            )

        # ----------------------------------------------------
        # Analyze URLs
        # ----------------------------------------------------

        for item in url_items:

            if not isinstance(
                item,
                dict,
            ):
                continue

            domain = self._extract_domain(
                item.get(
                    "domain",
                    item.get(
                        "url",
                        "",
                    ),
                )
            )

            if not domain:
                continue

            url_org = self.get_organization(
                domain
            )

            if url_org:

                trusted_organizations.add(
                    url_org
                )

            # ------------------------------------------------
            # Current security evidence must never be hidden
            # by trust scoring.
            # ------------------------------------------------

            if item.get(
                "brand_impersonation"
            ):

                critical_url_count += 1

                structured_evidence.append(
                    self._evidence(
                        type_="BRAND_IMPERSONATION",
                        severity="CRITICAL",
                        direction="NEGATIVE",
                        source="TrustAnalyzer",
                        explanation=(
                            f"URL {domain} is associated with "
                            "brand impersonation."
                        ),
                        confidence=0.95,
                    )
                )

            if item.get(
                "tls_policy_violation"
            ):

                suspicious_url_count += 1

                structured_evidence.append(
                    self._evidence(
                        type_="TLS_POLICY_VIOLATION",
                        severity=self._tls_severity(
                            item
                        ),
                        direction="NEGATIVE",
                        source="TrustAnalyzer",
                        explanation=(
                            f"TLS policy violation detected "
                            f"for {domain}."
                        ),
                        confidence=0.90,
                    )
                )

            if item.get(
                "ip_based"
            ):

                suspicious_url_count += 1

                structured_evidence.append(
                    self._evidence(
                        type_="SUSPICIOUS_URL",
                        severity="HIGH",
                        direction="NEGATIVE",
                        source="TrustAnalyzer",
                        explanation=(
                            f"URL {domain} uses an IP-based destination."
                        ),
                        confidence=0.90,
                    )
                )

            if item.get(
                "punycode"
            ):

                suspicious_url_count += 1

                structured_evidence.append(
                    self._evidence(
                        type_="PUNYCODE_DOMAIN",
                        severity="HIGH",
                        direction="NEGATIVE",
                        source="TrustAnalyzer",
                        explanation=(
                            f"URL {domain} uses Punycode."
                        ),
                        confidence=0.90,
                    )
                )

            if item.get(
                "shortener"
            ):

                suspicious_url_count += 1

                structured_evidence.append(
                    self._evidence(
                        type_="SUSPICIOUS_URL",
                        severity="MEDIUM",
                        direction="NEGATIVE",
                        source="TrustAnalyzer",
                        explanation=(
                            f"URL {domain} uses a URL shortener."
                        ),
                        confidence=0.80,
                    )
                )

            # ------------------------------------------------
            # Email/URL alignment
            # ------------------------------------------------

            alignment = str(
                item.get(
                    "email_alignment",
                    item.get(
                        "alignment",
                        "unknown",
                    ),
                )
                or "unknown"
            ).lower()

            if alignment == "aligned":

                aligned_url_count += 1

                score += 10

                structured_evidence.append(
                    self._evidence(
                        type_="URL_ALIGNMENT",
                        severity="LOW",
                        direction="POSITIVE",
                        source="TrustAnalyzer",
                        explanation=(
                            f"URL {domain} is aligned with the sender."
                        ),
                        confidence=0.90,
                    )
                )

            elif alignment == "misaligned":

                mismatched_url_count += 1

                score -= 10

                structured_evidence.append(
                    self._evidence(
                        type_="DOMAIN_MISMATCH",
                        severity="HIGH",
                        direction="NEGATIVE",
                        source="TrustAnalyzer",
                        explanation=(
                            f"URL {domain} is misaligned with the sender."
                        ),
                        confidence=0.90,
                    )
                )

        # ----------------------------------------------------
        # Trusted URL organizations
        # ----------------------------------------------------

        if trusted_organizations:

            trusted_url_score = min(
                len(
                    trusted_organizations
                )
                * 5,
                15,
            )

            score += trusted_url_score

            message = (
                f"{len(trusted_organizations)} recognized "
                "organization URL(s)"
            )

            evidence.append(
                message
            )

            structured_evidence.append(
                self._evidence(
                    type_="TRUSTED_DOMAIN",
                    severity="LOW",
                    direction="POSITIVE",
                    source="TrustAnalyzer",
                    explanation=message,
                    confidence=0.85,
                )
            )

        # ----------------------------------------------------
        # Sender organization ↔ URL organization
        # ----------------------------------------------------

        same_org_found = False

        if sender_org:

            for item in url_items:

                if not isinstance(
                    item,
                    dict,
                ):
                    continue

                domain = self._extract_domain(
                    item.get(
                        "domain",
                        item.get(
                            "url",
                            "",
                        ),
                    )
                )

                url_org = self.get_organization(
                    domain
                )

                if (
                    url_org
                    and url_org == sender_org
                ):

                    same_org_found = True

                    score += 10

                    message = (
                        "Sender and URL belong to the "
                        f"same recognized organization "
                        f"({sender_org.capitalize()})"
                    )

                    evidence.append(
                        message
                    )

                    structured_evidence.append(
                        self._evidence(
                            type_="DOMAIN_ALIGNMENT",
                            severity="LOW",
                            direction="POSITIVE",
                            source="TrustAnalyzer",
                            explanation=message,
                            confidence=0.93,
                        )
                    )

                    break

        # ----------------------------------------------------
        # Cross-organization mismatch
        #
        # Important:
        # Google sender + PayPal URL does not automatically mean
        # phishing. It creates a mismatch signal. Other evidence
        # must determine risk.
        # ----------------------------------------------------

        has_real_urls = bool(url_items)
        if (
            sender_org
            and trusted_organizations
            and not same_org_found
            and has_real_urls
        ):

            foreign_orgs = (
                trusted_organizations
                - {sender_org}
            )

            if foreign_orgs:

                mismatch_message = (
                    "Recognized sender organization "
                    f"({sender_org}) differs from URL "
                    f"organization(s): "
                    f"{', '.join(sorted(foreign_orgs))}"
                )

                evidence.append(
                    mismatch_message
                )

                score -= 10

                structured_evidence.append(
                    self._evidence(
                        type_="ORGANIZATION_MISMATCH",
                        severity="MEDIUM",
                        direction="NEGATIVE",
                        source="TrustAnalyzer",
                        explanation=mismatch_message,
                        confidence=0.75,
                    )
                )

        # ----------------------------------------------------
        # Authentication + trust
        # ----------------------------------------------------

        if auth_fully_passed:
            score += 10

            message = (
                "SPF, DKIM and DMARC all passed."
            )

            evidence.append(
                message
            )

            structured_evidence.append(
                self._evidence(
                    type_="AUTHENTICATION_PASS",
                    severity="LOW",
                    direction="POSITIVE",
                    source="TrustAnalyzer",
                    explanation=message,
                    confidence=0.96,
                )
            )

        elif auth_state == "FAILED":

            score -= 25

            structured_evidence.append(
                self._evidence(
                    type_="AUTHENTICATION_FAILURE",
                    severity="HIGH",
                    direction="NEGATIVE",
                    source="TrustAnalyzer",
                    explanation=(
                        "One or more sender authentication "
                        "checks failed."
                    ),
                    confidence=0.95,
                )
            )

        # ----------------------------------------------------
        # Current malicious indicators override trust scoring
        # in the trust result itself.
        #
        # The final verdict remains the responsibility of ARE /
        # DecisionFusion.
        # ----------------------------------------------------

        if critical_url_count:
            score = min(
                score,
                20,
            )

        elif suspicious_url_count:
            score = min(
                score,
                60,
            )

        # Trust score is intentionally not allowed to reach 100
        # merely because a sender is a recognized organization.
        score = max(
            0,
            min(
                100,
                int(score),
            ),
        )

        # ----------------------------------------------------
        # Trust confidence
        # ----------------------------------------------------

        positive_sources = 0

        if sender_org:
            positive_sources += 1

        if trusted_organizations:
            positive_sources += 1

        if same_org_found:
            positive_sources += 1

        if auth_fully_passed:
            positive_sources += 1

        if aligned_url_count:
            positive_sources += 1

        negative_sources = 0

        if mismatched_url_count:
            negative_sources += 1

        if suspicious_url_count:
            negative_sources += 1

        if critical_url_count:
            negative_sources += 1

        if auth_state == "FAILED":
            negative_sources += 1

        if critical_url_count:
            confidence = 90

        elif negative_sources:
            confidence = 65

        elif positive_sources >= 3:
            confidence = 90

        elif positive_sources >= 2:
            confidence = 80

        elif positive_sources == 1:
            confidence = 65

        else:
            confidence = 40

        # A recognized sender is not enough to claim full trust.
        if (
            sender_org
            and not auth_fully_passed
            and not same_org_found
        ):
            confidence = min(
                confidence,
                70,
            )

        return {
            "analysis_status": "AVAILABLE",

            "trust_score": score,
            "confidence": confidence,

            "sender": email_address,
            "sender_name": sender_name,
            "sender_domain": sender_domain,

            "sender_organization": sender_org,

            "trusted_organizations": sorted(
                trusted_organizations
            ),

            "sender_url_same_organization": (
                same_org_found
            ),

            "aligned_url_count": (
                aligned_url_count
            ),

            "misaligned_url_count": (
                mismatched_url_count
            ),

            "suspicious_url_count": (
                suspicious_url_count
            ),

            "critical_url_count": (
                critical_url_count
            ),

            "authentication_state": (
                auth_state
            ),

            "is_trusted_sender": (
                bool(sender_org)
                and auth_fully_passed
                and same_org_found
            ),

            "trust_is_supporting_evidence": True,

            "trust_cannot_override_negative_evidence": True,

            "negative_security_indicators_present": (
                bool(
                    critical_url_count
                    or suspicious_url_count
                    or mismatched_url_count
                    or auth_state == "FAILED"
                )
            ),

            "evidence": evidence,

            "structured_evidence": (
                structured_evidence
            ),
        }

    @staticmethod
    def _extract_domain(
        value: Any,
    ) -> str:

        if not value:
            return ""

        try:
            value = str(value).strip().lower()
        except Exception:
            return ""

        if "://" in value:
            value = value.split("://", 1)[1]

        if "@" in value:
            value = value.rsplit("@", 1)[1]
            value = value.split("/", 1)[0]
            value = value.split("?", 1)[0]
            value = value.split("#", 1)[0]
            value = value.split(":", 1)[0]

        return TrustAnalyzer._normalize_domain(value)

    # ========================================================
    # Domain helpers
    # ========================================================

    def get_organization(
        self,
        domain: str,
    ) -> str | None:

        domain = self._normalize_domain(
            domain
        )

        if not domain:
            return None

        for (
            organization,
            config,
        ) in self.known_organizations.items():

            for trusted_domain in (
                config.get(
                    "sender_domains",
                    set(),
                )
                | config.get(
                    "url_domains",
                    set(),
                )
            ):

                if self.domain_matches(
                    domain,
                    trusted_domain,
                ):
                    return organization

        return None

    def domain_matches(
        self,
        domain: str,
        trusted: str,
    ) -> bool:

        domain = self._normalize_domain(
            domain
        )

        trusted = self._normalize_domain(
            trusted
        )

        if not domain or not trusted:
            return False

        return (
            domain == trusted
            or domain.endswith(
                "."
                + trusted
            )
        )

    @staticmethod
    def _normalize_domain(
        domain: Any,
    ) -> str:

        if not domain:
            return ""

        try:
            domain = str(
                domain
            ).strip().lower()
        except Exception:
            return ""

        domain = domain.rstrip(
            "."
        )

        return domain

    # ========================================================
    # Authentication helpers
    # ========================================================

    def _authentication_state(
        self,
        authentication: Dict[str, Any],
    ) -> str:

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

        spf = self._auth_value(
            authentication,
            "spf",
            "spf_result",
        )

        dkim = self._auth_value(
            authentication,
            "dkim",
            "dkim_result",
        )

        dmarc = self._auth_value(
            authentication,
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
    def _auth_value(
        authentication: Dict[str, Any],
        primary: str,
        fallback: str,
    ) -> str:

        return str(
            authentication.get(
                primary,
                authentication.get(
                    fallback,
                    "",
                ),
            )
            or ""
        ).strip().lower()

    # ========================================================
    # TLS helper
    # ========================================================

    @staticmethod
    def _tls_severity(
        item: Dict[str, Any],
    ) -> str:

        tls = (
            item.get(
                "tls",
                {},
            )
            or {}
        )

        severity = str(
            tls.get(
                "severity",
                "MEDIUM",
            )
        ).upper()

        if severity not in {
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }:
            return "MEDIUM"

        return severity

    # ========================================================
    # Evidence helper
    # ========================================================

    @staticmethod
    def _evidence(
        type_: str,
        severity: str,
        direction: str,
        source: str,
        explanation: str,
        confidence: float,
    ) -> Dict[str, Any]:

        try:
            confidence = float(
                confidence
            )
        except (
            TypeError,
            ValueError,
        ):
            confidence = 0.0

        return {
            "type": (
                str(
                    type_
                )
                .strip()
                .upper()
                .replace(
                    "-",
                    "_",
                )
                .replace(
                    " ",
                    "_",
                )
            ),
            "severity": str(
                severity
            ).upper(),
            "direction": str(
                direction
            ).upper(),
            "source": source,
            "explanation": explanation,
            "confidence": max(
                0.0,
                min(
                    1.0,
                    confidence,
                ),
            ),
        } 