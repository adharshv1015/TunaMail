# ============================================================
# backend/src/analyzers/content_analyzer.py
# ============================================================

from __future__ import annotations

import logging
import re
from typing import Any, Dict, Iterable, List


logger = logging.getLogger(__name__)


class ContentAnalyzer:
    """
    Defensive email-content analyzer.

    Responsibilities:
    - Detect urgency / credential / financial / threat language.
    - Detect genuine organization/domain impersonation patterns.
    - Detect LINK_ONLY / LIMITED_CONTEXT messages.
    - Produce deterministic risk evidence.
    - Produce structured evidence for ARE / DecisionFusion.
    - Never treat a brand mention alone as impersonation.
    - Never treat authentication failure alone as impersonation.
    """

    TRUSTED_ORGANIZATIONS = {
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
            },
            "url_domains": {
                "apple.com",
                "icloud.com",
                "appleid.apple.com",
                "id.apple.com",
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
    }

    KEYWORDS = {
        "urgency": [
            "urgent",
            "immediately",
            "expire",
            "expires",
            "within 24 hours",
            "action required",
            "act now",
            "limited time",
            "final notice",
            "last warning",
            "respond immediately",
        ],
        "credential_request": [
            "password",
            "login",
            "log in",
            "verify account",
            "verify your account",
            "confirm account",
            "confirm your account",
            "sign in",
            "username",
            "otp",
            "one-time password",
            "one time password",
            "mfa",
            "verification code",
            "security code",
            "passcode",
        ],
        "financial_request": [
            "payment",
            "bank",
            "credit card",
            "debit card",
            "wire transfer",
            "invoice",
            "refund",
            "billing",
            "payment failed",
            "transaction",
            "account balance",
        ],
        "threat_language": [
            "suspended",
            "locked",
            "disabled",
            "terminated",
            "blocked",
            "hacked",
            "compromised",
            "security breach",
            "unauthorized access",
        ],
    }

    URL_PATTERN = re.compile(
        r"https?://[^\s<>'\"\]\[()]+",
        re.IGNORECASE,
    )

    # Used to strip common punctuation around URLs.
    URL_TRAILING_CHARS = ".,;:!?)]}>\"'"

    def analyze(
        self,
        body: str,
        sender: str = "",
        auth_results: dict | None = None,
        urls: Iterable[Any] | None = None,
    ) -> Dict[str, Any]:
        """
        Analyze email content.

        `urls` may contain:
        - URL strings
        - dictionaries containing url/domain information

        Returns a backward-compatible result plus structured evidence.
        """

        auth_results = (
            auth_results
            if isinstance(
                auth_results,
                dict,
            )
            else {}
        )

        body = (
            body
            if isinstance(
                body,
                str,
            )
            else str(
                body or ""
            )
        )

        sender = (
            sender
            if isinstance(
                sender,
                str,
            )
            else str(
                sender or ""
            )
        )

        urls = list(
            urls or []
        )

        text = body.lower().strip()

        sender_domain = self._extract_domain(
            sender
        )

        normalized_urls = [
            self._normalize_url_item(item)
            for item in urls
        ]

        normalized_urls = [
            item
            for item in normalized_urls
            if item.get("url")
            or item.get("domain")
        ]

        # ----------------------------------------------------
        # Link-only / limited-context detection
        # ----------------------------------------------------

        body_without_urls = self._remove_urls(
            text
        )

        clean_context = self._normalize_whitespace(
            body_without_urls
        )

        non_url_words = (
            clean_context.split()
            if clean_context
            else []
        )

        explicit_link_only = bool(
            len(normalized_urls) > 0
            and len(non_url_words) <= 5
        )

        # Existing parser/analyzer hints can be supplied
        # through auth_results only for compatibility, but
        # this analyzer owns its own deterministic detection.
        is_link_only = explicit_link_only

        # Empty body and no URL is insufficient context.
        is_empty = (
            len(
                non_url_words
            ) == 0
            and not normalized_urls
        )

        # ----------------------------------------------------
        # Keyword detection
        # ----------------------------------------------------

        urgency = self.contains_any(
            text,
            self.KEYWORDS["urgency"],
        )

        credential_request = self.contains_any(
            text,
            self.KEYWORDS["credential_request"],
        )

        financial_request = self.contains_any(
            text,
            self.KEYWORDS["financial_request"],
        )

        threat_language = self.contains_any(
            text,
            self.KEYWORDS["threat_language"],
        )

        # ----------------------------------------------------
        # Organization / impersonation analysis
        # ----------------------------------------------------

        impersonation_result = (
            self._detect_impersonation(
                body=body,
                sender=sender,
                urls=normalized_urls,
                authentication=auth_results,
            )
        )

        impersonation = bool(
            impersonation_result.get(
                "impersonation",
                False,
            )
        )

        brand_mentions = impersonation_result.get(
            "brand_mentions",
            [],
        )

        organization_relationships = (
            impersonation_result.get(
                "relationships",
                [],
            )
        )

        # ----------------------------------------------------
        # Risk scoring
        # ----------------------------------------------------

        score = 0
        structured_evidence: List[
            Dict[str, Any]
        ] = []
        evidence: List[str] = []

        if urgency:
            score += 20

            evidence.append(
                "Urgency language detected"
            )

            structured_evidence.append(
                self._evidence(
                    type_="URGENCY_LANGUAGE",
                    severity="MEDIUM",
                    explanation=(
                        "Urgency or time-pressure language "
                        "was detected."
                    ),
                    confidence=0.80,
                )
            )

        if credential_request:
            score += 25

            evidence.append(
                "Credential request language detected"
            )

            structured_evidence.append(
                self._evidence(
                    type_="CREDENTIAL_REQUEST",
                    severity="HIGH",
                    explanation=(
                        "The message contains language "
                        "requesting credentials or account verification."
                    ),
                    confidence=0.85,
                )
            )

        if financial_request:
            score += 25

            evidence.append(
                "Financial request language detected"
            )

            structured_evidence.append(
                self._evidence(
                    type_="FINANCIAL_REQUEST",
                    severity="HIGH",
                    explanation=(
                        "The message contains financial or payment "
                        "request language."
                    ),
                    confidence=0.85,
                )
            )

        if threat_language:
            score += 20

            evidence.append(
                "Threat or account-consequence language detected"
            )

            structured_evidence.append(
                self._evidence(
                    type_="THREAT_LANGUAGE",
                    severity="MEDIUM",
                    explanation=(
                        "Threat, suspension, lockout, or "
                        "security-consequence language was detected."
                    ),
                    confidence=0.80,
                )
            )

        if impersonation:
            score += 40

            evidence.append(
                "Potential brand/domain impersonation detected"
            )

            structured_evidence.append(
                self._evidence(
                    type_="BRAND_IMPERSONATION",
                    severity="CRITICAL",
                    explanation=(
                        impersonation_result.get(
                            "explanation",
                            "Potential brand impersonation detected.",
                        )
                    ),
                    confidence=self._safe_float(
                        impersonation_result.get(
                            "confidence",
                            0.90,
                        ),
                        0.90,
                    ),
                )
            )

        # ----------------------------------------------------
        # Positive contextual evidence
        # ----------------------------------------------------

        for relationship in organization_relationships:

            if not isinstance(
                relationship,
                dict,
            ):
                continue

            if relationship.get(
                "legitimate"
            ):

                structured_evidence.append(
                    {
                        "type": "DOMAIN_ALIGNMENT",
                        "severity": "LOW",
                        "direction": "POSITIVE",
                        "source": "ContentAnalyzer",
                        "explanation": (
                            "Sender and destination domain "
                            "belong to the same recognized organization."
                        ),
                        "confidence": 0.90,
                    }
                )

        # ----------------------------------------------------
        # Content quality state
        # ----------------------------------------------------

        if is_empty:
            content_state = (
                "INSUFFICIENT_EVIDENCE"
            )

            evidence.append(
                "Email contains no meaningful body text or URL."
            )

        elif is_link_only:
            content_state = (
                "LIMITED_CONTEXT"
            )

            evidence.append(
                "Email contains mostly a URL with minimal surrounding text."
            )

        else:
            content_state = (
                "SUFFICIENT_CONTEXT"
            )

        # ----------------------------------------------------
        # Context quality
        # ----------------------------------------------------

        meaningful_words = len(
            non_url_words
        )

        context_quality = {
            "state": content_state,
            "word_count": meaningful_words,
            "url_count": len(
                normalized_urls
            ),
        }

        # ----------------------------------------------------
        # Final score
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

        confidence = 50

        signal_count = sum(
            [
                int(urgency),
                int(credential_request),
                int(financial_request),
                int(threat_language),
                int(impersonation),
            ]
        )

        if content_state == "INSUFFICIENT_EVIDENCE":
            confidence = 20

        elif content_state == "LIMITED_CONTEXT":
            confidence = 35

        elif signal_count == 0:
            confidence = 65

        elif signal_count == 1:
            confidence = 60

        else:
            confidence = 75

        if impersonation:
            confidence = max(
                confidence,
                85,
            )

        # Content keyword evidence should NOT create a
        # high-confidence phishing result by itself.
        if (
            signal_count > 0
            and not impersonation
        ):
            confidence = min(
                confidence,
                75,
            )

        # ----------------------------------------------------
        # Analysis status
        # ----------------------------------------------------

        result = {
            "analysis_status": "AVAILABLE",

            # Existing frontend/API compatibility
            "link_only": is_link_only,
            "limited_context": (
                content_state
                == "LIMITED_CONTEXT"
            ),
            "context_state": content_state,

            "urgency": urgency,
            "credential_request": credential_request,
            "financial_request": financial_request,
            "impersonation": impersonation,
            "threat_language": threat_language,

            "risk_score": score,
            "confidence": confidence,

            "sender_domain": sender_domain,

            "brand_mentions": brand_mentions,
            "organization_relationships": (
                organization_relationships
            ),

            "context_quality": context_quality,

            "evidence": evidence,

            "structured_evidence": (
                structured_evidence
            ),
        }

        return result

    # ========================================================
    # Keyword helpers
    # ========================================================

    @classmethod
    def contains_any(
        cls,
        text: str,
        keywords: Iterable[str],
    ) -> bool:
        """
        Match meaningful keyword/phrase occurrences.

        Longer phrases are checked before shorter phrases.
        """

        if not text:
            return False

        for keyword in sorted(
            keywords,
            key=len,
            reverse=True,
        ):

            keyword = str(
                keyword or ""
            ).strip().lower()

            if not keyword:
                continue

            # Phrase matching can safely use normalized
            # substring matching. Single-word keywords use
            # word boundaries to avoid cases such as:
            # "login" matching unrelated longer words.
            if " " in keyword:

                if keyword in text:
                    return True

            else:

                pattern = (
                    r"(?<![\w])"
                    + re.escape(
                        keyword
                    )
                    + r"(?![\w])"
                )

                if re.search(
                    pattern,
                    text,
                    flags=re.IGNORECASE,
                ):
                    return True

        return False

    @staticmethod
    def contains(
        text: str,
        keywords: Iterable[str],
    ) -> bool:
        return ContentAnalyzer.contains_any(
            text,
            keywords,
        )

    # ========================================================
    # URL helpers
    # ========================================================

    def _normalize_url_item(
        self,
        item: Any,
    ) -> Dict[str, Any]:

        if isinstance(
            item,
            dict,
        ):

            url = (
                item.get(
                    "url"
                )
                or item.get(
                    "normalized_url"
                )
                or ""
            )

            domain = (
                item.get(
                    "domain"
                )
                or self._extract_domain(
                    str(
                        url
                    )
                )
            )

            normalized = dict(
                item
            )

            normalized["url"] = self._normalize_url(
                url
            )

            normalized["domain"] = (
                self._extract_domain(
                    domain
                )
            )

            return normalized

        url = self._normalize_url(
            str(
                item
                or ""
            )
        )

        return {
            "url": url,
            "domain": self._extract_domain(
                url
            ),
        }

    def _normalize_url(
        self,
        value: Any,
    ) -> str:

        value = str(
            value or ""
        ).strip()

        value = value.strip(
            self.URL_TRAILING_CHARS
        )

        return value

    def _remove_urls(
        self,
        text: str,
    ) -> str:

        if not text:
            return ""

        return self.URL_PATTERN.sub(
            " ",
            text,
        )

    @staticmethod
    def _normalize_whitespace(
        value: str,
    ) -> str:

        return re.sub(
            r"\s+",
            " ",
            value or "",
        ).strip()

    # ========================================================
    # Domain helpers
    # ========================================================

    def _extract_domain(
        self,
        value: Any,
    ) -> str:
        """
        Extract a normalized domain from:

        Display Name <email@example.com>
        email@example.com
        https://example.com/path
        example.com/path
        """

        if not value:
            return ""

        try:
            value = str(
                value
            ).strip()
        except Exception:
            return ""

        # Display Name <email@example.com>
        match = re.search(
            r"<\s*([^<>@\s]+@[^<>@\s]+)\s*>",
            value,
            flags=re.IGNORECASE,
        )

        if match:
            value = match.group(
                1
            )

        value = value.lower().strip()

        # Extract the email domain.
        if "@" in value:
            value = value.rsplit(
                "@",
                1,
            )[1]

        # Remove scheme.
        value = re.sub(
            r"^[a-z][a-z0-9+\-.]*://",
            "",
            value,
            flags=re.IGNORECASE,
        )

        # Remove path/query/fragment.
        value = re.split(
            r"[/?#]",
            value,
            maxsplit=1,
        )[0]

        # Remove standard port notation.
        if value.count(":") == 1:
            value = value.split(
                ":",
                1,
            )[0]

        # Remove surrounding punctuation.
        value = value.strip(
            " .<>[](){}\"'"
        )

        return value

    def _is_same_or_subdomain(
        self,
        domain: str,
        trusted_domain: str,
    ) -> bool:

        domain = self._extract_domain(
            domain
        )

        trusted_domain = self._extract_domain(
            trusted_domain
        )

        if not domain or not trusted_domain:
            return False

        return (
            domain == trusted_domain
            or domain.endswith(
                "."
                + trusted_domain
            )
        )

    def _organization_for_domain(
        self,
        domain: str,
    ) -> str | None:

        domain = self._extract_domain(
            domain
        )

        if not domain:
            return None

        for (
            organization,
            config,
        ) in self.TRUSTED_ORGANIZATIONS.items():

            for trusted_domain in (
                config.get(
                    "url_domains",
                    set(),
                )
            ):

                if self._is_same_or_subdomain(
                    domain,
                    trusted_domain,
                ):
                    return organization

        return None

    def _is_legitimate_organization_relationship(
        self,
        sender_domain: str,
        url_domain: str,
        organization: str,
    ) -> bool:

        config = (
            self.TRUSTED_ORGANIZATIONS.get(
                organization
            )
        )

        if not config:
            return False

        sender_domain = self._extract_domain(
            sender_domain
        )

        url_domain = self._extract_domain(
            url_domain
        )

        sender_matches = any(
            self._is_same_or_subdomain(
                sender_domain,
                trusted_domain,
            )
            for trusted_domain in (
                config.get(
                    "sender_domains",
                    set(),
                )
            )
        )

        url_matches = any(
            self._is_same_or_subdomain(
                url_domain,
                trusted_domain,
            )
            for trusted_domain in (
                config.get(
                    "url_domains",
                    set(),
                )
            )
        )

        return (
            sender_matches
            and url_matches
        )

    # ========================================================
    # Impersonation detection
    # ========================================================

    def _detect_impersonation(
        self,
        body: str,
        sender: str,
        urls: Iterable[Dict[str, Any]] | None = None,
        authentication: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """
        Detect brand/domain impersonation.

        Important rules:
        - Authentication failure alone is NOT impersonation.
        - Mentioning "Microsoft" alone is NOT impersonation.
        - Official URLs alone are NOT impersonation.
        - A brand + unrelated sender/domain relationship can be
          suspicious.
        """

        body_lower = (
            body or ""
        ).lower()

        sender_domain = self._extract_domain(
            sender
        )

        urls = list(
            urls or []
        )

        brand_mentions = []
        relationships = []

        # ----------------------------------------------------
        # Authentication failures are NOT impersonation.
        # ----------------------------------------------------
        # They remain authentication evidence for the rest of
        # the pipeline. Do not return True here.

        # ----------------------------------------------------
        # Examine each organization
        # ----------------------------------------------------

        for (
            organization,
            config,
        ) in self.TRUSTED_ORGANIZATIONS.items():

            brand_mentioned = self._contains_brand_reference(
                body_lower,
                organization,
            )

            organization_url_domains = []

            for url_item in urls:

                url_domain = self._extract_domain(
                    url_item.get(
                        "domain",
                        url_item.get(
                            "url",
                            "",
                        ),
                    )
                )

                if not url_domain:
                    continue

                url_organization = (
                    self._organization_for_domain(
                        url_domain
                    )
                )

                if (
                    url_organization
                    == organization
                ):
                    organization_url_domains.append(
                        url_domain
                    )

            # ------------------------------------------------
            # Brand mention tracking
            # ------------------------------------------------

            if brand_mentioned:

                brand_mentions.append(
                    organization
                )

            # ------------------------------------------------
            # Brand mention without official URL
            #
            # This alone is NOT impersonation.
            # It may simply be a discussion or notification.
            # ------------------------------------------------

            if (
                brand_mentioned
                and not organization_url_domains
            ):
                continue

            # ------------------------------------------------
            # Organization URL relationships
            # ------------------------------------------------

            for url_domain in (
                organization_url_domains
            ):

                legitimate = (
                    self._is_legitimate_organization_relationship(
                        sender_domain,
                        url_domain,
                        organization,
                    )
                )

                relationships.append(
                    {
                        "organization": organization,
                        "sender_domain": sender_domain,
                        "url_domain": url_domain,
                        "legitimate": legitimate,
                        "brand_mentioned": brand_mentioned,
                    }
                )

                # A valid sender + official organization URL
                # is positive context.
                if legitimate:
                    continue

                # An unrelated sender using an organization's
                # official-looking infrastructure can be
                # suspicious, especially when the body claims
                # the organization is contacting the user.
                if (
                    brand_mentioned
                    and not legitimate
                ):

                    return {
                        "impersonation": True,
                        "brand_mentions": brand_mentions,
                        "relationships": relationships,
                        "confidence": 0.95,
                        "explanation": (
                            f"The message references {organization} "
                            "but the sender/domain relationship does "
                            "not match a recognized legitimate organization relationship."
                        ),
                    }

        # ----------------------------------------------------
        # Domain-level brand mismatch
        #
        # Example:
        # "Microsoft Security"
        # sent from unrelated domain
        # linking to an unrelated domain.
        # ----------------------------------------------------

        if brand_mentions:

            body_claims = set(
                brand_mentions
            )

            unrelated_url_count = 0

            for url_item in urls:

                url_domain = self._extract_domain(
                    url_item.get(
                        "domain",
                        url_item.get(
                            "url",
                            "",
                        ),
                    )
                )

                if not url_domain:
                    continue

                url_org = (
                    self._organization_for_domain(
                        url_domain
                    )
                )

                if (
                    url_org is None
                    and self._looks_like_brand_domain(
                        url_domain,
                        body_claims,
                    )
                ):

                    unrelated_url_count += 1

            if unrelated_url_count:
                return {
                    "impersonation": True,
                    "brand_mentions": brand_mentions,
                    "relationships": relationships,
                    "confidence": 0.90,
                    "explanation": (
                        "Brand references were detected alongside "
                        "a domain that does not match the referenced organization."
                    ),
                }

        return {
            "impersonation": False,
            "brand_mentions": brand_mentions,
            "relationships": relationships,
            "confidence": 0.0,
            "explanation": "",
        }

    # ========================================================
    # Brand matching
    # ========================================================

    def _contains_brand_reference(
        self,
        text: str,
        organization: str,
    ) -> bool:

        organization = (
            organization
            or ""
        ).strip().lower()

        if not organization:
            return False

        # Organization names are matched as word/phrase
        # boundaries to avoid false matches such as:
        # "amazon" in "amazonite".
        pattern = (
            r"(?<![\w])"
            + re.escape(
                organization
            )
            + r"(?![\w])"
        )

        if re.search(
            pattern,
            text or "",
            flags=re.IGNORECASE,
        ):
            return True

        # Brand aliases commonly used in email content.
        aliases = {
            "google": [
                "google",
                "gmail",
            ],
            "microsoft": [
                "microsoft",
                "outlook",
                "office 365",
                "office365",
            ],
            "apple": [
                "apple",
                "icloud",
                "apple id",
                "appleid",
            ],
            "paypal": [
                "paypal",
            ],
            "amazon": [
                "amazon",
            ],
            "linkedin": [
                "linkedin",
            ],
        }

        for alias in aliases.get(
            organization,
            [],
        ):

            if " " in alias:
                if alias in (
                    text or ""
                ):
                    return True
                continue

            alias_pattern = (
                r"(?<![\w])"
                + re.escape(
                    alias
                )
                + r"(?![\w])"
            )

            if re.search(
                alias_pattern,
                text or "",
                flags=re.IGNORECASE,
            ):
                return True

        return False

    def _looks_like_brand_domain(
        self,
        domain: str,
        brands: Iterable[str],
    ) -> bool:

        domain = (
            self._extract_domain(
                domain
            )
        )

        if not domain:
            return False

        labels = domain.split(
            "."
        )

        for brand in brands:

            brand = (
                brand
                or ""
            ).lower()

            if not brand:
                continue

            if any(
                brand in label
                for label in labels
                if label
            ):
                return True

        return False

    # ========================================================
    # Generic helpers
    # ========================================================

    @staticmethod
    def _safe_float(
        value: Any,
        fallback: float,
    ) -> float:

        try:
            return max(
                0.0,
                min(
                    1.0,
                    float(value),
                ),
            )
        except (
            TypeError,
            ValueError,
        ):
            return fallback

    @staticmethod
    def _evidence(
        type_: str,
        severity: str,
        explanation: str,
        confidence: float,
    ) -> Dict[str, Any]:

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
            "severity": (
                str(
                    severity
                )
                .strip()
                .upper()
            ),
            "direction": "NEGATIVE",
            "source": "ContentAnalyzer",
            "explanation": explanation,
            "confidence": max(
                0.0,
                min(
                    1.0,
                    float(confidence),
                ),
            ),
        }