# ============================================================
# backend/src/analyzers/email_categorizer.py
# ============================================================

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Set


class EmailCategorizer:
    """
    Deterministic email categorizer.

    Categories describe the likely functional/content type of an email.
    They are NOT security verdicts.

    Security verdicts such as PHISHING, SUSPICIOUS, SAFE, etc. are taken
    from the final decision and normalized safely.

    The categorizer never converts the absence of evidence into SAFE.
    """

    OTP_PATTERNS = [
        r"\botp\b",
        r"\bverification code\b",
        r"\bone[- ]time password\b",
        r"\bsecurity code\b",
        r"\blogin code\b",
        r"\b\d{6}[- ]digit code\b",
        r"\bauthentication code\b",
        r"\bpasscode\b",
    ]

    SECURITY_KEYWORDS = [
        "security alert",
        "password",
        "sign in",
        "sign-in",
        "login",
        "log in",
        "account",
        "device",
        "recovery",
        "verification",
        "verify your account",
        "2fa",
        "two-factor",
        "multi-factor",
        "mfa",
    ]

    BANKING_KEYWORDS = [
        "bank",
        "transaction",
        "upi",
        "debit",
        "credit",
        "payment",
        "account balance",
        "statement",
        "wire transfer",
        "beneficiary",
        "ifsc",
    ]

    INVOICE_KEYWORDS = [
        "invoice",
        "receipt",
        "bill",
        "tax invoice",
        "payment received",
        "purchase order",
        "po number",
        "billing statement",
    ]

    SHOPPING_KEYWORDS = [
        "order",
        "shipping",
        "delivered",
        "amazon",
        "flipkart",
        "purchase",
        "shopping",
        "order confirmation",
    ]

    DELIVERY_KEYWORDS = [
        "tracking",
        "shipment",
        "courier",
        "parcel",
        "out for delivery",
        "delivery attempt",
        "tracking number",
    ]

    SOCIAL_KEYWORDS = [
        "friend request",
        "liked your",
        "commented",
        "mentioned you",
        "follow",
        "followers",
        "connection request",
    ]

    NEWSLETTER_KEYWORDS = [
        "unsubscribe",
        "weekly",
        "newsletter",
        "digest",
        "mailing list",
    ]

    PROMOTION_KEYWORDS = [
        "offer",
        "discount",
        "sale",
        "coupon",
        "deal",
        "% off",
        "limited offer",
        "promo",
        "promotional",
    ]

    EXECUTABLE_ATTACHMENT_TYPES = {
        "EXECUTABLE_ATTACHMENT",
        "SCRIPT_ATTACHMENT",
        "MALICIOUS_ATTACHMENT",
        "MACRO_ATTACHMENT",
    }

    LEGITIMATE_VERDICTS = {
        "SAFE",
        "LOW RISK",
        "LIKELY LEGITIMATE",
        "VERIFIED LEGITIMATE",
    }

    RISK_VERDICTS = {
        "SUSPICIOUS",
        "HIGH RISK",
        "PHISHING",
    }

    VALID_VERDICTS = LEGITIMATE_VERDICTS | RISK_VERDICTS | {
        "UNKNOWN",
    }

    URL_PATTERN = re.compile(
        r"https?://[^\s<>'\"\]\[()]+",
        re.IGNORECASE,
    )

    # ========================================================
    # Main categorization
    # ========================================================

    def categorize(
        self,
        parsed_email: Dict[str, Any] | None,
        content_analysis: Dict[str, Any] | None,
        url_analysis: Dict[str, Any] | None,
        attachment_analysis: Dict[str, Any] | None,
        decision: Dict[str, Any] | None,
    ) -> List[str]:

        parsed_email = (
            parsed_email
            if isinstance(parsed_email, dict)
            else {}
        )

        content_analysis = (
            content_analysis
            if isinstance(content_analysis, dict)
            else {}
        )

        url_analysis = (
            url_analysis
            if isinstance(url_analysis, dict)
            else {}
        )

        attachment_analysis = (
            attachment_analysis
            if isinstance(attachment_analysis, dict)
            else {}
        )

        decision = (
            decision
            if isinstance(decision, dict)
            else {}
        )

        categories: Set[str] = set()

        subject = self._safe_text(
            parsed_email.get("subject")
        )

        body = self._safe_text(
            parsed_email.get("body")
        )

        sender = self._safe_text(
            parsed_email.get("from")
            or parsed_email.get("sender")
        )

        text = self._normalize_text(
            f"{subject} {body}"
        )

        # ----------------------------------------------------
        # OTP
        # ----------------------------------------------------

        if self._matches_any_pattern(
            text,
            self.OTP_PATTERNS,
        ):
            categories.add("OTP")

        # ----------------------------------------------------
        # Security
        # ----------------------------------------------------

        if self._contains_any(
            text,
            self.SECURITY_KEYWORDS,
        ):
            categories.add("Security")

        # ----------------------------------------------------
        # Banking
        # ----------------------------------------------------

        if self._contains_any(
            text,
            self.BANKING_KEYWORDS,
        ):
            categories.add("Banking")

        # ----------------------------------------------------
        # Invoice
        # ----------------------------------------------------

        if self._contains_any(
            text,
            self.INVOICE_KEYWORDS,
        ):
            categories.add("Invoice")

        # ----------------------------------------------------
        # Shopping
        # ----------------------------------------------------

        if self._contains_any(
            text,
            self.SHOPPING_KEYWORDS,
        ):
            categories.add("Shopping")

        # ----------------------------------------------------
        # Delivery
        # ----------------------------------------------------

        if self._contains_any(
            text,
            self.DELIVERY_KEYWORDS,
        ):
            categories.add("Delivery")

        # ----------------------------------------------------
        # Social
        # ----------------------------------------------------

        if self._contains_any(
            text,
            self.SOCIAL_KEYWORDS,
        ):
            categories.add("Social")

        # ----------------------------------------------------
        # Newsletter
        # ----------------------------------------------------

        if self._contains_any(
            text,
            self.NEWSLETTER_KEYWORDS,
        ):
            categories.add("Newsletter")

        # ----------------------------------------------------
        # Promotion
        # ----------------------------------------------------

        if self._contains_any(
            text,
            self.PROMOTION_KEYWORDS,
        ):
            categories.add("Promotion")

        # ----------------------------------------------------
        # Attachment
        # ----------------------------------------------------

        attachment_count = self._safe_int(
            attachment_analysis.get(
                "attachment_count",
                0,
            )
        )

        analyzed_attachment_count = self._safe_int(
            attachment_analysis.get(
                "analyzed_attachment_count",
                attachment_count,
            )
        )

        if attachment_count > 0:
            categories.add("Attachment")

        # ----------------------------------------------------
        # Link-only / Limited Context
        # ----------------------------------------------------

        link_only = bool(
            content_analysis.get(
                "link_only"
            )
            or content_analysis.get(
                "limited_context"
            )
            or url_analysis.get(
                "link_only"
            )
            or url_analysis.get(
                "limited_context"
            )
        )

        if link_only:
            categories.add("Link Only")

        # ----------------------------------------------------
        # Empty / insufficient context
        # ----------------------------------------------------

        body_word_count = len(
            body.split()
        )

        url_count = self._count_urls(
            body,
            url_analysis,
        )

        if (
            body_word_count == 0
            and url_count == 0
            and not attachment_count
        ):
            categories.add("Insufficient Context")

        # ----------------------------------------------------
        # Final security verdict
        # ----------------------------------------------------

        verdict = self._normalize_verdict(
            decision.get(
                "verdict"
            )
        )

        risk_score = self._safe_int(
            decision.get(
                "risk_score",
                0,
            )
        )

        confidence = self._safe_int(
            decision.get(
                "confidence",
                0,
            )
        )

        # ----------------------------------------------------
        # Phishing
        # ----------------------------------------------------

        if verdict == "PHISHING":
            categories.add("Phishing")

        # ----------------------------------------------------
        # High Risk
        # ----------------------------------------------------

        if (
            verdict == "HIGH RISK"
            or risk_score >= 70
        ):
            categories.add("High Risk")

        # ----------------------------------------------------
        # Suspicious
        # ----------------------------------------------------

        if verdict == "SUSPICIOUS":
            categories.add("Suspicious")

        # ----------------------------------------------------
        # Unknown
        # ----------------------------------------------------

        if verdict == "UNKNOWN":
            categories.add("Unknown")

        # ----------------------------------------------------
        # Unanalyzed
        # ----------------------------------------------------

        analysis_status = str(
            decision.get(
                "analysis_status",
                "",
            )
            or ""
        ).upper()

        if (
            analysis_status == "UNANALYZED"
            or decision.get(
                "verdict"
            ) is None
        ):
            categories.add("Unanalyzed")

        # ----------------------------------------------------
        # Trusted / legitimate
        #
        # Do NOT use "no threat detected" as proof.
        # Require a legitimate final verdict and meaningful
        # confidence.
        # ----------------------------------------------------

        if (
            verdict in self.LEGITIMATE_VERDICTS
            and confidence >= 70
        ):
            categories.add("Trusted")

        # ----------------------------------------------------
        # Deep URL intelligence categories
        # ----------------------------------------------------

        structured_evidence = (
            decision.get(
                "structured_evidence",
                [],
            )
            or []
        )

        self._categorize_structured_evidence(
            categories,
            structured_evidence,
        )

        self._categorize_url_analysis(
            categories,
            url_analysis,
        )

        self._categorize_attachment_analysis(
            categories,
            attachment_analysis,
        )

        # ----------------------------------------------------
        # Sender metadata
        # ----------------------------------------------------

        sender_domain = self._extract_domain(
            sender
        )

        if sender_domain:
            suspicious_sender_terms = (
                "mailinator",
                "tempmail",
                "10minutemail",
                "guerrillamail",
            )

            if any(
                term in sender_domain
                for term in suspicious_sender_terms
            ):
                categories.add(
                    "Disposable Sender"
                )

        # ----------------------------------------------------
        # Fallback
        # ----------------------------------------------------

        if not categories:
            categories.add("General")

        return sorted(
            categories
        )

    # ========================================================
    # Structured evidence categorization
    # ========================================================

    def _categorize_structured_evidence(
        self,
        categories: Set[str],
        evidence: Iterable[Any],
    ) -> None:

        for item in evidence:

            if not isinstance(
                item,
                dict,
            ):
                continue

            evidence_type = self._normalize_type(
                item.get(
                    "type"
                )
            )

            severity = str(
                item.get(
                    "severity",
                    "",
                )
            ).upper()

            if evidence_type in {
                "CREDENTIAL_HARVESTING",
                "CREDENTIAL_FORM",
            }:
                categories.add(
                    "Credential Risk"
                )

            if evidence_type in {
                "BRAND_IMPERSONATION",
                "HOMOGRAPH_DOMAIN",
                "PUNYCODE_DOMAIN",
            }:
                categories.add(
                    "Impersonation Risk"
                )

            if evidence_type in {
                "TLS_POLICY_VIOLATION",
                "HOSTNAME_MISMATCH",
            }:
                categories.add(
                    "TLS Risk"
                )

            if evidence_type in {
                "SUSPICIOUS_URL",
                "MALICIOUS_URL",
                "KNOWN_MALICIOUS_URL",
                "SUSPICIOUS_REDIRECT",
                "MALICIOUS_REDIRECT",
            }:
                categories.add(
                    "URL Risk"
                )

            if evidence_type in {
                "EXECUTABLE_ATTACHMENT",
                "SCRIPT_ATTACHMENT",
                "MALICIOUS_ATTACHMENT",
                "MACRO_ATTACHMENT",
            }:
                categories.add(
                    "Malicious Attachment"
                )

            if evidence_type in {
                "CONFLICTING_EVIDENCE",
                "TRUST_HISTORY_CONFLICT",
                "HISTORICAL_CURRENT_CONFLICT",
            }:
                categories.add(
                    "Conflicting Evidence"
                )

            if evidence_type in {
                "VALID_HISTORICAL_EVIDENCE",
            }:
                categories.add(
                    "Historical Trust"
                )

            if severity == "CRITICAL":
                categories.add(
                    "Critical Indicator"
                )

    # ========================================================
    # URL analysis categorization
    # ========================================================

    def _categorize_url_analysis(
        self,
        categories: Set[str],
        url_analysis: Dict[str, Any],
    ) -> None:

        items = (
            url_analysis.get(
                "analysis",
                [],
            )
            or []
        )

        for item in items:

            if not isinstance(
                item,
                dict,
            ):
                continue

            if item.get(
                "brand_impersonation"
            ):
                categories.add(
                    "Impersonation Risk"
                )

            if item.get(
                "tls_policy_violation"
            ):
                categories.add(
                    "TLS Risk"
                )

            if item.get(
                "http_policy_warning"
            ):
                categories.add(
                    "Insecure Transport"
                )

            if item.get(
                "ip_based"
            ):
                categories.add(
                    "IP URL"
                )

            if item.get(
                "shortener"
            ):
                categories.add(
                    "Shortened URL"
                )

            if item.get(
                "punycode"
            ):
                categories.add(
                    "Punycode URL"
                )

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
                categories.add(
                    "External Redirect"
                )

    # ========================================================
    # Attachment categorization
    # ========================================================

    def _categorize_attachment_analysis(
        self,
        categories: Set[str],
        attachment_analysis: Dict[str, Any],
    ) -> None:

        evidence = (
            attachment_analysis.get(
                "structured_evidence",
                [],
            )
            or []
        )

        for item in evidence:

            if not isinstance(
                item,
                dict,
            ):
                continue

            evidence_type = self._normalize_type(
                item.get(
                    "type"
                )
            )

            if evidence_type in (
                "EXECUTABLE_ATTACHMENT",
                "SCRIPT_ATTACHMENT",
                "MALICIOUS_ATTACHMENT",
            ):
                categories.add(
                    "Malicious Attachment"
                )

            elif evidence_type == (
                "MACRO_ATTACHMENT"
            ):
                categories.add(
                    "Macro Attachment"
                )

            elif evidence_type == (
                "ARCHIVE_ATTACHMENT"
            ):
                categories.add(
                    "Archive Attachment"
                )

    # ========================================================
    # Text helpers
    # ========================================================

    @staticmethod
    def _safe_text(
        value: Any,
    ) -> str:

        if value is None:
            return ""

        if isinstance(
            value,
            str,
        ):
            return value.strip()

        try:
            return str(
                value
            ).strip()
        except Exception:
            return ""

    @staticmethod
    def _normalize_text(
        value: str,
    ) -> str:

        return re.sub(
            r"\s+",
            " ",
            value or "",
        ).strip().lower()

    @classmethod
    def _contains_any(
        cls,
        text: str,
        keywords: Iterable[str],
    ) -> bool:

        text = cls._normalize_text(
            text
        )

        for keyword in sorted(
            keywords,
            key=len,
            reverse=True,
        ):

            keyword = cls._normalize_text(
                keyword
            )

            if not keyword:
                continue

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

    @classmethod
    def _matches_any_pattern(
        cls,
        text: str,
        patterns: Iterable[str],
    ) -> bool:

        text = text or ""

        for pattern in patterns:

            try:
                if re.search(
                    pattern,
                    text,
                    flags=re.IGNORECASE,
                ):
                    return True
            except re.error:
                continue

        return False

    # ========================================================
    # URL helpers
    # ========================================================

    @classmethod
    def _count_urls(
        cls,
        body: str,
        url_analysis: Dict[str, Any],
    ) -> int:

        items = (
            url_analysis.get(
                "analysis",
                [],
            )
            or []
        )

        if items:
            return len(
                [
                    item
                    for item in items
                    if isinstance(
                        item,
                        dict,
                    )
                ]
            )

        if not body:
            return 0

        return len(
            cls.URL_PATTERN.findall(
                body
            )
        )

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

        match = re.search(
            r"<\s*[^<>@\s]+@([^<>\s]+)\s*>",
            value,
            flags=re.IGNORECASE,
        )

        if match:
            value = match.group(
                1
            )

        if "@" in value:
            value = value.rsplit(
                "@",
                1,
            )[1]

        value = re.sub(
            r"^[a-z][a-z0-9+\-.]*://",
            "",
            value,
            flags=re.IGNORECASE,
        )

        value = re.split(
            r"[/?#]",
            value,
            maxsplit=1,
        )[0]

        if value.count(":") == 1:
            value = value.split(
                ":",
                1,
            )[0]

        return value.strip(
            " .<>[](){}\"'"
        )

    # ========================================================
    # Verdict helpers
    # ========================================================

    @staticmethod
    def _normalize_verdict(
        value: Any,
    ) -> str:

        if value is None:
            return "UNKNOWN"

        value = str(
            value
        ).strip().upper()

        aliases = {
            "PHISHING EMAIL": "PHISHING",
            "MALICIOUS": "PHISHING",
            "LIKELY LEGITIMATE": "LIKELY LEGITIMATE",
            "VERIFIED LEGITIMATE": "VERIFIED LEGITIMATE",
            "LEGITIMATE": "LIKELY LEGITIMATE",
            "SAFE": "SAFE",
            "LOW_RISK": "LOW RISK",
            "HIGH_RISK": "HIGH RISK",
        }

        return aliases.get(
            value,
            value,
        )

    @staticmethod
    def _normalize_type(
        value: Any,
    ) -> str:

        return (
            str(
                value
                or ""
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
        )

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