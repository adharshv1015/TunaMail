# ============================================================
# backend/src/analyzers/page_phishing_analyzer.py
# ============================================================

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List
from urllib.parse import urlsplit


logger = logging.getLogger(__name__)


class PagePhishingAnalyzer:
    """
    Analyzes sanitized webpage evidence produced by the URL worker.

    Important design rules:
    - A login page is NOT automatically phishing.
    - A valid HTTPS/TLS page is NOT automatically safe.
    - Individual keywords are contextual indicators only.
    - Credential harvesting/page-intent evidence carries substantially
      more weight than generic words such as "security" or "login".
    - Fetch failures are represented as unavailable evidence, not as
      phishing verdicts.
    - Produces structured evidence for ARE / DecisionFusion.
    """

    FAKE_ERROR_PATTERNS = [
        "your computer has been",
        "your computer is infected",
        "call microsoft",
        "call apple",
        "call support",
        "virus detected",
        "your device is at risk",
        "windows defender alert",
        "security alert",
        "your ip has been flagged",
        "your ip address has been blocked",
        "your account has been suspended",
        "your account has been compromised",
        "your information was compromised",
        "your session has expired",
        "unusual activity detected",
        "suspicious activity detected",
        "unauthorized access detected",
        "your system is at risk",
        "click here to restore",
        "click here to fix",
        "scan detected",
        "access blocked",
        "warning! your",
        "alert! your",
        "hacked by",
        "your browser has been locked",
        "do not ignore this message",
        "do not close this window",
    ]

    URGENCY_PATTERNS = [
        "act now",
        "immediate action required",
        "expires in",
        "expires today",
        "last chance",
        "final warning",
        "within 24 hours",
        "within 48 hours",
        "limited time",
        "before it's too late",
        "failure to comply",
        "account will be terminated",
        "account will be closed",
        "account will be deleted",
        "respond immediately",
        "time is running out",
    ]

    CREDENTIAL_TEXT_PATTERNS = [
        "enter your password",
        "confirm your password",
        "type your password",
        "social security number",
        "social security no",
        "credit card number",
        "card number",
        "cvv",
        "date of birth",
        "mother's maiden name",
        "security question",
        "pin number",
        "bank account number",
        "routing number",
        "account verification",
        "identity verification",
        "verify your identity",
        "verify your account",
        "confirm your identity",
    ]

    SPOOFED_TITLE_PATTERNS = [
        "login",
        "sign in",
        "signin",
        "log in",
        "account verification",
        "verify account",
        "security check",
        "authentication required",
        "identity verification",
    ]

    HIGH_RISK_PAGE_INTENTS = {
        "CREDENTIAL_HARVESTING",
        "PAYMENT_SCAM",
        "MALWARE_DISTRIBUTION",
        "TECH_SUPPORT_SCAM",
        "FAKE_SECURITY_ALERT",
    }

    CRITICAL_INDICATOR_TYPES = {
        "CREDENTIAL_HARVESTING",
        "FAKE_ERROR_PAGE",
        "MALWARE_LANDING_PAGE",
        "PAYMENT_SCAM",
    }

    URL_TRAILING_CHARS = ".,;:!?)]}>\"'"

    def analyze(
        self,
        page_data: Dict[str, Any] | None,
        url: str = "",
    ) -> Dict[str, Any]:
        """
        Analyze fetched/sanitized page data.

        Expected page_data shape may contain:
            title
            visible_text
            word_count
            forms
            redirects
            security
            ai
            brand
            tls

        Returns a normalized result suitable for URL analysis
        and the evidence-fusion pipeline.
        """

        page_data = (
            page_data
            if isinstance(page_data, dict)
            else {}
        )

        security = (
            page_data.get(
                "security",
                {},
            )
            or {}
        )

        # ----------------------------------------------------
        # Fetch unavailable / blocked
        # ----------------------------------------------------

        if (
            not page_data
            or security.get("error")
        ):
            error = (
                security.get(
                    "error"
                )
                or "Page could not be fetched"
            )

            return {
                "available": False,
                "analysis_status": "UNAVAILABLE",
                "error": str(error),
                "url": url,
                "indicators": [],
                "structured_evidence": [],
                "page_risk_score": 0,
                "page_confidence": 0,
                "has_credential_form": False,
                "has_fake_error": False,
                "has_urgency": False,
                "has_malicious_intent": False,
                "page_intent": "UNAVAILABLE",
            }

        # ----------------------------------------------------
        # Normalize basic content
        # ----------------------------------------------------

        raw_visible_text = self._safe_text(
            page_data.get(
                "visible_text",
                "",
            )
        )

        raw_title = self._safe_text(
            page_data.get(
                "title",
                "",
            )
        )

        visible_text = self._normalize_text(
            raw_visible_text
        )

        title = self._normalize_text(
            raw_title
        )

        forms = (
            page_data.get(
                "forms",
                {},
            )
            or {}
        )

        word_count = self._safe_int(
            page_data.get(
                "word_count",
                len(
                    visible_text.split()
                ),
            )
        )

        indicators: List[
            Dict[str, Any]
        ] = []

        structured_evidence: List[
            Dict[str, Any]
        ] = []

        risk_score = 0

        # ====================================================
        # 1. Existing AI/page intent
        # ====================================================

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

        ai_confidence = self._confidence(
            page_ai.get(
                "confidence",
                0,
            )
        )

        # AI intent is evidence, not automatic authority.
        if page_intent in self.HIGH_RISK_PAGE_INTENTS:

            severity = "CRITICAL"

            detail = (
                f"Page intent analysis identified "
                f"{page_intent}."
            )

            self._add_indicator(
                indicators,
                structured_evidence,
                type_=page_intent,
                severity=severity,
                detail=detail,
                confidence=max(
                    ai_confidence,
                    0.80,
                ),
                score=40,
            )

            risk_score += 40

        # ====================================================
        # 2. Fake error / scareware page
        # ====================================================

        fake_error_matches = self._find_matches(
            visible_text,
            title,
            self.FAKE_ERROR_PATTERNS,
        )

        has_fake_error = bool(
            fake_error_matches
        )

        if has_fake_error:

            detail = (
                "Page contains deceptive error/warning "
                "language designed to pressure or scare "
                "the visitor: "
                + ", ".join(
                    fake_error_matches[:5]
                )
            )

            self._add_indicator(
                indicators,
                structured_evidence,
                type_="FAKE_ERROR_PAGE",
                severity="HIGH",
                detail=detail,
                confidence=0.92,
                score=35,
            )

            risk_score += 35

        # ====================================================
        # 3. Form normalization
        # ====================================================

        form_count = self._safe_int(
            forms.get(
                "count",
                0,
            )
        )

        password_fields = self._safe_int(
            forms.get(
                "password_fields",
                0,
            )
        )

        email_fields = self._safe_int(
            forms.get(
                "email_fields",
                0,
            )
        )

        text_inputs = self._safe_int(
            forms.get(
                "text_fields",
                forms.get(
                    "text_inputs",
                    0,
                ),
            )
        )

        submit_buttons = self._safe_int(
            forms.get(
                "submit_buttons",
                0,
            )
        )

        has_credential_form = (
            password_fields > 0
        )

        has_email_form = (
            email_fields > 0
        )

        # ====================================================
        # 4. Credential form analysis
        # ====================================================

        if has_credential_form:

            if word_count < 80:

                detail = (
                    "Password input detected on a very sparse "
                    f"page ({word_count} words)."
                )

                self._add_indicator(
                    indicators,
                    structured_evidence,
                    type_="SPARSE_CREDENTIAL_FORM",
                    severity="CRITICAL",
                    detail=detail,
                    confidence=0.96,
                    score=55,
                )

                risk_score += 55

            else:

                detail = (
                    "Page contains a password input field."
                )

                self._add_indicator(
                    indicators,
                    structured_evidence,
                    type_="CREDENTIAL_FORM",
                    severity="HIGH",
                    detail=detail,
                    confidence=0.85,
                    score=25,
                )

                risk_score += 25

        elif (
            has_email_form
            and word_count < 100
        ):

            detail = (
                "Email/username input detected on a sparse "
                f"page ({word_count} words)."
            )

            self._add_indicator(
                indicators,
                structured_evidence,
                type_="SPARSE_EMAIL_FORM",
                severity="MEDIUM",
                detail=detail,
                confidence=0.80,
                score=20,
            )

            risk_score += 20

        # ====================================================
        # 5. Sparse generic forms
        # ====================================================

        if (
            form_count > 0
            and word_count < 40
            and not has_credential_form
            and not has_email_form
        ):

            detail = (
                "A form was detected on a very sparse page "
                f"({word_count} words)."
            )

            self._add_indicator(
                indicators,
                structured_evidence,
                type_="SPARSE_FORM_PAGE",
                severity="MEDIUM",
                detail=detail,
                confidence=0.72,
                score=15,
            )

            risk_score += 15

        # ====================================================
        # 6. Urgency / pressure language
        # ====================================================

        urgency_matches = self._find_matches(
            visible_text,
            title,
            self.URGENCY_PATTERNS,
        )

        has_urgency = bool(
            urgency_matches
        )

        if has_urgency:

            detail = (
                "Page uses urgency/pressure tactics: "
                + ", ".join(
                    urgency_matches[:5]
                )
            )

            self._add_indicator(
                indicators,
                structured_evidence,
                type_="URGENCY_LANGUAGE",
                severity="MEDIUM",
                detail=detail,
                confidence=0.80,
                score=15,
            )

            risk_score += 15

        # ====================================================
        # 7. Credential / sensitive-information language
        # ====================================================

        credential_text_matches = (
            self._find_matches_single_text(
                visible_text,
                self.CREDENTIAL_TEXT_PATTERNS,
            )
        )

        has_credential_solicitation = bool(
            credential_text_matches
        )

        if has_credential_solicitation:

            detail = (
                "Page explicitly requests sensitive information: "
                + ", ".join(
                    credential_text_matches[:5]
                )
            )

            self._add_indicator(
                indicators,
                structured_evidence,
                type_="CREDENTIAL_SOLICITATION",
                severity="HIGH",
                detail=detail,
                confidence=0.90,
                score=25,
            )

            risk_score += 25

        # ====================================================
        # 8. Login/verification title
        #
        # A login title alone is NOT malicious.
        # It becomes stronger only when combined with sparse
        # content/forms/credential solicitation.
        # ====================================================

        spoofed_title_matches = (
            self._find_matches_single_text(
                title,
                self.SPOOFED_TITLE_PATTERNS,
            )
        )

        has_suspicious_title = bool(
            spoofed_title_matches
        )

        if (
            has_suspicious_title
            and (
                word_count < 200
                or has_credential_form
                or has_credential_solicitation
            )
        ):

            detail = (
                "Page title suggests a login or verification "
                f"workflow: \"{raw_title}\"."
            )

            self._add_indicator(
                indicators,
                structured_evidence,
                type_="SUSPICIOUS_TITLE",
                severity="LOW",
                detail=detail,
                confidence=0.65,
                score=5,
            )

            risk_score += 5

        # ====================================================
        # 9. Redirect chain
        # ====================================================

        redirects = (
            page_data.get(
                "redirects",
                [],
            )
            or []
        )

        redirect_analysis = (
            self._analyze_redirects(
                redirects
            )
        )

        if redirect_analysis[
            "multiple_domains"
        ]:

            detail = (
                "URL passed through "
                f"{redirect_analysis['hop_count']} "
                "redirect hop(s) across "
                f"{redirect_analysis['domain_count']} "
                "different domains."
            )

            self._add_indicator(
                indicators,
                structured_evidence,
                type_="MULTI_DOMAIN_REDIRECT",
                severity="MEDIUM",
                detail=detail,
                confidence=0.82,
                score=15,
            )

            risk_score += 15

        # ====================================================
        # 10. Page/brand relationship
        # ====================================================

        brand_data = (
            page_data.get(
                "brand",
                {},
            )
            or {}
        )

        domain_match = brand_data.get(
            "domain_match"
        )

        if domain_match is False:

            detail = (
                "The page's claimed brand does not match "
                "the destination domain."
            )

            self._add_indicator(
                indicators,
                structured_evidence,
                type_="PAGE_BRAND_MISMATCH",
                severity="HIGH",
                detail=detail,
                confidence=0.90,
                score=30,
            )

            risk_score += 30

        # ====================================================
        # 11. TLS information is contextual only
        # ====================================================

        tls = (
            page_data.get(
                "tls",
                {},
            )
            or {}
        )

        if tls.get(
            "policy_violation"
        ) or tls.get(
            "violation"
        ):

            violation = (
                tls.get(
                    "violation"
                )
                or "TLS_POLICY_VIOLATION"
            )

            detail = (
                f"TLS policy issue detected: {violation}."
            )

            self._add_indicator(
                indicators,
                structured_evidence,
                type_="TLS_POLICY_VIOLATION",
                severity=self._severity_from_tls(
                    tls
                ),
                detail=detail,
                confidence=0.90,
                score=self._tls_score(
                    tls
                ),
            )

            risk_score += self._tls_score(
                tls
            )

        # ====================================================
        # 12. Final page intent
        # ====================================================

        has_malicious_page_evidence = (
            page_intent
            in self.HIGH_RISK_PAGE_INTENTS
            or has_credential_form
            or has_credential_solicitation
            or (
                domain_match is False
                and (
                    has_credential_form
                    or has_fake_error
                )
            )
        )

        if has_malicious_page_evidence:

            if page_intent in self.HIGH_RISK_PAGE_INTENTS:
                final_page_intent = page_intent

            elif has_credential_form:
                final_page_intent = (
                    "CREDENTIAL_HARVESTING"
                )

            elif has_fake_error:
                final_page_intent = (
                    "FAKE_SECURITY_ALERT"
                )

            else:
                final_page_intent = (
                    "SUSPICIOUS_PAGE"
                )

        elif (
            has_suspicious_title
            or has_urgency
            or has_email_form
        ):

            final_page_intent = (
                "POTENTIALLY_SENSITIVE"
            )

        else:

            final_page_intent = (
                "INFORMATIONAL"
            )

        # ====================================================
        # 13. Score normalization
        # ====================================================

        risk_score = max(
            0,
            min(
                100,
                int(risk_score),
            ),
        )

        # ====================================================
        # 14. Confidence calibration
        # ====================================================

        confidence = self._calculate_confidence(
            indicators=indicators,
            risk_score=risk_score,
            word_count=word_count,
            form_count=form_count,
        )

        # ====================================================
        # 15. Return normalized result
        # ====================================================

        return {
            "available": True,
            "analysis_status": "AVAILABLE",
            "url": url,

            "title": raw_title,
            "word_count": word_count,

            "forms": forms,

            "indicators": indicators,

            "structured_evidence": (
                structured_evidence
            ),

            "page_risk_score": risk_score,
            "page_confidence": confidence,

            "page_intent": final_page_intent,

            "has_credential_form": (
                has_credential_form
            ),
            "has_email_form": (
                has_email_form
            ),
            "has_fake_error": (
                has_fake_error
            ),
            "has_urgency": (
                has_urgency
            ),
            "has_credential_solicitation": (
                has_credential_solicitation
            ),
            "has_malicious_intent": (
                has_malicious_page_evidence
            ),

            "redirects": redirects,

            "redirect_analysis": (
                redirect_analysis
            ),

            "tls": tls,
        }

    # ========================================================
    # Helpers
    # ========================================================

    @staticmethod
    def _safe_text(
        value: Any,
    ) -> str:

        if value is None:
            return ""

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

    @staticmethod
    def _normalize_type(
        value: Any,
    ) -> str:

        return (
            str(
                value or ""
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
            return max(
                0,
                int(
                    float(
                        value or 0
                    )
                ),
            )
        except (
            TypeError,
            ValueError,
        ):
            return 0

    @staticmethod
    def _confidence(
        value: Any,
    ) -> float:

        try:
            value = float(
                value or 0
            )
        except (
            TypeError,
            ValueError,
        ):
            return 0.0

        # Accept both 0-1 and 0-100 confidence formats.
        if value > 1:
            value /= 100

        return max(
            0.0,
            min(
                1.0,
                value,
            ),
        )

    @staticmethod
    def _find_matches(
        text: str,
        title: str,
        patterns: List[str],
    ) -> List[str]:

        haystacks = (
            text or "",
            title or "",
        )

        matches = []

        for pattern in patterns:

            pattern = str(
                pattern or ""
            ).strip().lower()

            if not pattern:
                continue

            if any(
                pattern in haystack
                for haystack in haystacks
            ):
                matches.append(
                    pattern
                )

        return matches

    @staticmethod
    def _find_matches_single_text(
        text: str,
        patterns: List[str],
    ) -> List[str]:

        matches = []

        for pattern in patterns:

            pattern = str(
                pattern or ""
            ).strip().lower()

            if (
                pattern
                and pattern in (
                    text or ""
                )
            ):
                matches.append(
                    pattern
                )

        return matches

    @staticmethod
    def _add_indicator(
        indicators: List[Dict[str, Any]],
        structured_evidence: List[Dict[str, Any]],
        type_: str,
        severity: str,
        detail: str,
        confidence: float,
        score: int,
    ) -> None:

        normalized_type = (
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
        )

        normalized_severity = (
            str(
                severity
            )
            .strip()
            .upper()
        )

        indicator = {
            "type": normalized_type,
            "severity": normalized_severity,
            "detail": detail,
            "score": int(
                max(
                    0,
                    score,
                )
            ),
        }

        indicators.append(
            indicator
        )

        structured_evidence.append(
            {
                "type": normalized_type,
                "severity": normalized_severity,
                "direction": "NEGATIVE",
                "source": "PagePhishingAnalyzer",
                "explanation": detail,
                "confidence": max(
                    0.0,
                    min(
                        1.0,
                        float(
                            confidence
                        ),
                    ),
                ),
            }
        )

    @staticmethod
    def _analyze_redirects(
        redirects: Any,
    ) -> Dict[str, Any]:

        if not isinstance(
            redirects,
            list,
        ):
            return {
                "hop_count": 0,
                "domain_count": 0,
                "domains": [],
                "multiple_domains": False,
            }

        domains = set()

        for hop in redirects:

            if not isinstance(
                hop,
                dict,
            ):
                continue

            for field in (
                "from",
                "to",
                "url",
                "location",
            ):

                hop_url = str(
                    hop.get(
                        field,
                        "",
                    )
                    or ""
                ).strip()

                if not hop_url:
                    continue

                try:
                    hostname = (
                        urlsplit(
                            hop_url
                        ).hostname
                        or ""
                    )

                    hostname = (
                        hostname.lower()
                        .lstrip("www.")
                        .strip(".")
                    )

                    if hostname:
                        domains.add(
                            hostname
                        )

                except (
                    ValueError,
                    TypeError,
                ):
                    continue

        return {
            "hop_count": len(
                redirects
            ),
            "domain_count": len(
                domains
            ),
            "domains": sorted(
                domains
            ),
            "multiple_domains": (
                len(domains) > 1
            ),
        }

    @staticmethod
    def _severity_from_tls(
        tls: Dict[str, Any],
    ) -> str:

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

    @staticmethod
    def _tls_score(
        tls: Dict[str, Any],
    ) -> int:

        severity = PagePhishingAnalyzer._severity_from_tls(
            tls
        )

        return {
            "LOW": 5,
            "MEDIUM": 10,
            "HIGH": 20,
            "CRITICAL": 30,
        }.get(
            severity,
            10,
        )

    @staticmethod
    def _calculate_confidence(
        indicators: List[Dict[str, Any]],
        risk_score: int,
        word_count: int,
        form_count: int,
    ) -> int:

        if not indicators:
            return 60

        critical_count = sum(
            1
            for item in indicators
            if str(
                item.get(
                    "severity",
                    "",
                )
            ).upper()
            == "CRITICAL"
        )

        high_count = sum(
            1
            for item in indicators
            if str(
                item.get(
                    "severity",
                    "",
                )
            ).upper()
            == "HIGH"
        )

        if critical_count:
            confidence = 90

        elif high_count >= 2:
            confidence = 82

        elif high_count == 1:
            confidence = 75

        elif risk_score >= 40:
            confidence = 68

        else:
            confidence = 60

        # Very sparse pages have less contextual certainty.
        if word_count < 20:
            confidence = min(
                confidence,
                75,
            )

        # A form strengthens the evidence quality.
        if form_count > 0:
            confidence = min(
                95,
                confidence + 5,
            )

        return max(
            0,
            min(
                100,
                confidence,
            ),
        )