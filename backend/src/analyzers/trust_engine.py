# ============================================================
# backend/src/engines/trust_engine.py
# ============================================================

from __future__ import annotations

from email.utils import parseaddr
from typing import Any, Dict, List, Set


class TrustEngine:
    """
    Deterministic trust-evidence engine.

    Important:
    - Trust is supporting evidence only.
    - A recognized sender is NOT automatically safe.
    - A recognized URL is NOT automatically safe.
    - Current malicious indicators always remain visible.
    - SPF/DKIM/DMARC authentication is handled as supporting evidence.
    - A trusted sender can still be compromised.
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
        # Authentication
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

        authentication_state = (
            self._authentication_state(
                authentication
            )
        )

        auth_fully_passed = (
            authentication_state == "PASSED"
        )

        auth_failed = (
            authentication_state == "FAILED"
        )

        # ----------------------------------------------------
        # URLs
        # ----------------------------------------------------

        url_items = (
            url_analysis.get(
                "analysis",
                [],
            )
            or []
        )

        trusted_organizations: Set[str] = set()

        aligned_url_count = 0
        misaligned_url_count = 0
        suspicious_url_count = 0
        critical_url_count = 0

        has_malicious_url = False
        has_brand_impersonation = False
        has_page_credential_harvesting = False
        has_malicious_page = False

        # ----------------------------------------------------
        # Sender organization
        # ----------------------------------------------------

        if sender_org:

            score += 20

            message = (
                "Recognized sender organization: "
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
                    source="TrustEngine",
                    explanation=message,
                    confidence=0.85,
                )
            )

        # ----------------------------------------------------
        # Analyze each URL
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
            # Brand impersonation
            # ------------------------------------------------

            if item.get(
                "brand_impersonation"
            ):

                has_brand_impersonation = True
                critical_url_count += 1

                structured_evidence.append(
                    self._evidence(
                        type_="BRAND_IMPERSONATION",
                        severity="CRITICAL",
                        direction="NEGATIVE",
                        source="TrustEngine",
                        explanation=(
                            f"Brand impersonation detected for URL domain "
                            f"{domain}."
                        ),
                        confidence=0.95,
                    )
                )

            # ------------------------------------------------
            # Threat intelligence
            # ------------------------------------------------

            threat_intel = (
                item.get(
                    "threat_intelligence",
                    {},
                )
                or {}
            )

            detections = self._safe_int(
                threat_intel.get(
                    "detections",
                    0,
                )
            )

            if detections > 0:

                has_malicious_url = True
                critical_url_count += 1

                structured_evidence.append(
                    self._evidence(
                        type_="KNOWN_MALICIOUS_URL",
                        severity="CRITICAL",
                        direction="NEGATIVE",
                        source="TrustEngine",
                        explanation=(
                            f"Threat intelligence reported "
                            f"{detections} detection(s) for {domain}."
                        ),
                        confidence=0.99,
                    )
                )

            # ------------------------------------------------
            # Suspicious URL indicators
            # ------------------------------------------------

            if item.get(
                "ip_based"
            ):

                suspicious_url_count += 1

                structured_evidence.append(
                    self._evidence(
                        type_="SUSPICIOUS_URL",
                        severity="HIGH",
                        direction="NEGATIVE",
                        source="TrustEngine",
                        explanation=(
                            f"URL uses an IP-based destination: {domain}."
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
                        source="TrustEngine",
                        explanation=(
                            f"Punycode domain detected: {domain}."
                        ),
                        confidence=0.90,
                    )
                )

            if item.get(
                "obfuscated"
            ):

                suspicious_url_count += 1

                structured_evidence.append(
                    self._evidence(
                        type_="SUSPICIOUS_URL",
                        severity="HIGH",
                        direction="NEGATIVE",
                        source="TrustEngine",
                        explanation=(
                            f"URL obfuscation detected for {domain}."
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
                        source="TrustEngine",
                        explanation=(
                            f"URL shortening service detected for {domain}."
                        ),
                        confidence=0.80,
                    )
                )

            # ------------------------------------------------
            # Redirects
            # ------------------------------------------------

            redirects = (
                item.get(
                    "redirects",
                    {},
                )
                or {}
            )

            if redirects.get(
                "external_domain_change"
            ):

                suspicious_url_count += 1

                structured_evidence.append(
                    self._evidence(
                        type_="SUSPICIOUS_REDIRECT",
                        severity="HIGH",
                        direction="NEGATIVE",
                        source="TrustEngine",
                        explanation=(
                            f"URL redirects to another external domain."
                        ),
                        confidence=0.90,
                    )
                )

            # ------------------------------------------------
            # TLS
            # ------------------------------------------------

            if item.get(
                "tls_policy_violation"
            ):

                suspicious_url_count += 1

                tls = (
                    item.get(
                        "tls",
                        {},
                    )
                    or {}
                )

                severity = self._normalize_severity(
                    tls.get(
                        "severity",
                        "MEDIUM",
                    )
                )

                structured_evidence.append(
                    self._evidence(
                        type_="TLS_POLICY_VIOLATION",
                        severity=severity,
                        direction="NEGATIVE",
                        source="TrustEngine",
                        explanation=(
                            f"TLS policy violation detected for {domain}: "
                            f"{tls.get('violation', 'UNKNOWN')}."
                        ),
                        confidence=0.90,
                    )
                )

            # ------------------------------------------------
            # Page intelligence
            # ------------------------------------------------

            page_intelligence = (
                item.get(
                    "page_intelligence",
                    {},
                )
                or {}
            )

            if page_intelligence.get(
                "has_credential_form"
            ):
                has_page_credential_harvesting = True
                critical_url_count += 1

                structured_evidence.append(
                    self._evidence(
                        type_="CREDENTIAL_HARVESTING",
                        severity="CRITICAL",
                        direction="NEGATIVE",
                        source="TrustEngine",
                        explanation=(
                            f"Destination page for {domain} "
                            "contains a credential form."
                        ),
                        confidence=0.95,
                    )
                )

            if page_intelligence.get(
                "has_malicious_intent"
            ):
                has_malicious_page = True
                critical_url_count += 1

                structured_evidence.append(
                    self._evidence(
                        type_="MALICIOUS_PAGE",
                        severity="CRITICAL",
                        direction="NEGATIVE",
                        source="TrustEngine",
                        explanation=(
                            f"Destination page for {domain} "
                            "contains malicious intent indicators."
                        ),
                        confidence=0.95,
                    )
                )

            # ------------------------------------------------
            # Sender / URL alignment
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
                        source="TrustEngine",
                        explanation=(
                            f"URL {domain} aligns with the sender."
                        ),
                        confidence=0.90,
                    )
                )

            elif alignment == "misaligned":

                misaligned_url_count += 1

                structured_evidence.append(
                    self._evidence(
                        type_="DOMAIN_MISMATCH",
                        severity="HIGH",
                        direction="NEGATIVE",
                        source="TrustEngine",
                        explanation=(
                            f"URL {domain} is misaligned with the sender."
                        ),
                        confidence=0.90,
                    )
                )

        # ----------------------------------------------------
        # Recognized URL organizations
        # ----------------------------------------------------

        if trusted_organizations:

            url_bonus = min(
                30,
                len(
                    trusted_organizations
                )
                * 10,
            )

            score += url_bonus

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
                    source="TrustEngine",
                    explanation=message,
                    confidence=0.85,
                )
            )

        # ----------------------------------------------------
        # Same sender organization and URL organization
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

                if not domain:
                    continue

                url_org = self.get_organization(
                    domain
                )

                if (
                    url_org
                    and url_org == sender_org
                ):

                    same_org_found = True
                    score += 20

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
                            source="TrustEngine",
                            explanation=message,
                            confidence=0.93,
                        )
                    )

                    break

        # ----------------------------------------------------
        # Cross-organization relationship
        #
        # This is a contextual warning, not automatic phishing.
        # ----------------------------------------------------

        if (
            sender_org
            and trusted_organizations
            and not same_org_found
        ):

            foreign_orgs = (
                trusted_organizations
                - {sender_org}
            )

            if foreign_orgs:

                message = (
                    f"Sender organization ({sender_org}) "
                    "differs from recognized URL organization(s): "
                    + ", ".join(
                        sorted(
                            foreign_orgs
                        )
                    )
                )

                evidence.append(
                    message
                )

                structured_evidence.append(
                    self._evidence(
                        type_="ORGANIZATION_MISMATCH",
                        severity="MEDIUM",
                        direction="NEGATIVE",
                        source="TrustEngine",
                        explanation=message,
                        confidence=0.75,
                    )
                )

        # ----------------------------------------------------
        # Authentication support
        # ----------------------------------------------------

        if auth_fully_passed:

            score += 15

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
                    source="TrustEngine",
                    explanation=message,
                    confidence=0.96,
                )
            )

        elif auth_failed:

            structured_evidence.append(
                self._evidence(
                    type_="AUTHENTICATION_FAILURE",
                    severity="HIGH",
                    direction="NEGATIVE",
                    source="TrustEngine",
                    explanation=(
                        "One or more sender authentication "
                        "checks failed."
                    ),
                    confidence=0.95,
                )
            )

        # ----------------------------------------------------
        # Compromised sender signal
        # ----------------------------------------------------

        possible_compromise = (
            auth_fully_passed
            and (
                has_brand_impersonation
                or has_malicious_url
                or has_page_credential_harvesting
                or has_malicious_page
            )
        )

        if possible_compromise:

            structured_evidence.append(
                self._evidence(
                    type_="TRUST_HISTORY_CONFLICT",
                    severity="HIGH",
                    direction="NEUTRAL",
                    source="TrustEngine",
                    explanation=(
                        "Strong sender authentication or organizational "
                        "trust conflicts with current malicious URL/page evidence. "
                        "Possible sender or account compromise."
                    ),
                    confidence=0.95,
                )
            )

        # ----------------------------------------------------
        # Never let trust score itself prove safety.
        # ----------------------------------------------------

        score = max(
            0,
            min(
                100,
                int(score),
            ),
        )

        # ----------------------------------------------------
        # Confidence
        # ----------------------------------------------------

        positive_sources = set()

        if sender_org:
            positive_sources.add(
                "sender"
            )

        if trusted_organizations:
            positive_sources.add(
                "url"
            )

        if auth_fully_passed:
            positive_sources.add(
                "authentication"
            )

        if aligned_url_count:
            positive_sources.add(
                "alignment"
            )

        if same_org_found:
            positive_sources.add(
                "same_organization"
            )

        negative_sources = set()

        if misaligned_url_count:
            negative_sources.add(
                "alignment"
            )

        if suspicious_url_count:
            negative_sources.add(
                "url"
            )

        if critical_url_count:
            negative_sources.add(
                "critical"
            )

        if auth_failed:
            negative_sources.add(
                "authentication"
            )

        if critical_url_count:
            confidence = 90

        elif negative_sources:
            confidence = 65

        elif len(
            positive_sources
        ) >= 4:
            confidence = 90

        elif len(
            positive_sources
        ) >= 3:
            confidence = 85

        elif len(
            positive_sources
        ) >= 2:
            confidence = 75

        elif len(
            positive_sources
        ) == 1:
            confidence = 60

        else:
            confidence = 35

        # A recognized sender without full authentication
        # should never receive extremely high confidence.
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
                misaligned_url_count
            ),

            "suspicious_url_count": (
                suspicious_url_count
            ),

            "critical_url_count": (
                critical_url_count
            ),

            "has_malicious_url": (
                has_malicious_url
            ),

            "has_page_credential_harvesting": (
                has_page_credential_harvesting
            ),

            "has_malicious_page": (
                has_malicious_page
            ),

            "possible_compromised_sender": (
                possible_compromise
            ),

            "authentication_state": (
                authentication_state
            ),

            "is_trusted_sender": (
                sender_org is not None
                and auth_fully_passed
                and same_org_found
                and not (
                    has_malicious_url
                    or has_brand_impersonation
                    or has_page_credential_harvesting
                    or has_malicious_page
                )
            ),

            "evidence": evidence,

            "structured_evidence": (
                structured_evidence
            ),
        }

    # ========================================================
    # Organization helpers
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

            trusted_domains = (
                config.get(
                    "sender_domains",
                    set(),
                )
                | config.get(
                    "url_domains",
                    set(),
                )
            )

            for trusted_domain in trusted_domains:

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
    # Domain normalization
    # ========================================================

    @staticmethod
    def _extract_domain(
        value: Any,
    ) -> str:

        if not value:
            return ""

        try:
            value = str(
                value
            ).strip().lower()
        except Exception:
            return ""

        if "@" in value:
            value = value.rsplit(
                "@",
                1,
            )[1]

        value = value.rstrip(
            "."
        )

        return value

    @staticmethod
    def _normalize_domain(
        value: Any,
    ) -> str:

        return (
            str(
                value
                or ""
            )
            .strip()
            .lower()
            .rstrip(".")
        )

    # ========================================================
    # TLS helpers
    # ========================================================

    @staticmethod
    def _normalize_severity(
        value: Any,
    ) -> str:

        severity = str(
            value
            or "MEDIUM"
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
    # Generic helpers
    # ========================================================

    @staticmethod
    def _safe_int(
        value: Any,
    ) -> int:

        try:
            return int(
                float(
                    value
                    or 0
                )
            )
        except (
            TypeError,
            ValueError,
        ):
            return 0

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