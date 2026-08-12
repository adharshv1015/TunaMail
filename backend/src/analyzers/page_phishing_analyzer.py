"""
Page Phishing Analyzer

Analyzes fetched page content for phishing and social engineering indicators.
Called after the URL worker fetches the page, adding a new layer of evidence
to the URL analysis pipeline.
"""

import re
from typing import Dict, Any, List


class PagePhishingAnalyzer:
    """
    Detects phishing indicators from a fetched web page's content.
    Works on the output of ContentExtractor (title, visible_text, forms, word_count).
    """

    # Fake error / warning pages designed to scare and trick users
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

    # Urgency / pressure language
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

    # Credential / sensitive data solicitation in page text
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

    # Title patterns that indicate a spoofed/phishing page
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

    def analyze(self, page_data: Dict[str, Any], url: str = "") -> Dict[str, Any]:
        """
        Analyze fetched page content and return a structured phishing assessment.

        Args:
            page_data: Output of URLWorker.inspect() / HTTPFetcher.fetch()
            url: The URL that was fetched (for context)

        Returns:
            Dict with:
              available (bool)
              indicators (list of {type, severity, detail})
              page_risk_score (0-100)
              has_credential_form (bool)
              has_fake_error (bool)
              has_urgency (bool)
              title, word_count, forms (mirrored from page_data)
        """
        # Handle fetch errors / blocked URLs
        security = page_data.get("security", {}) if page_data else {}
        if not page_data or security.get("error"):
            return {
                "available": False,
                "error": security.get("error", "Page could not be fetched"),
                "indicators": [],
                "page_risk_score": 0,
                "has_credential_form": False,
                "has_fake_error": False,
                "has_urgency": False,
            }

        visible_text = (page_data.get("visible_text") or "").lower()
        title = (page_data.get("title") or "").lower()
        forms = page_data.get("forms", {})
        word_count = page_data.get("word_count", 0)

        indicators: List[Dict[str, str]] = []
        risk_score = 0

        # --- 1. Fake error / warning page detection ---
        fake_error_matches = [p for p in self.FAKE_ERROR_PATTERNS if p in visible_text or p in title]
        has_fake_error = bool(fake_error_matches)
        if has_fake_error:
            indicators.append({
                "type": "FAKE_ERROR_PAGE",
                "severity": "HIGH",
                "detail": (
                    "Page contains deceptive error/warning language designed to scare users: "
                    + ", ".join(fake_error_matches[:3])
                ),
            })
            risk_score += 35

        # --- 2. Sparse credential-harvesting form ---
        has_password_field = forms.get("password_fields", 0) > 0
        has_email_field = forms.get("email_fields", 0) > 0
        has_credential_form = has_password_field

        if has_password_field:
            if word_count < 80:
                indicators.append({
                    "type": "SPARSE_CREDENTIAL_FORM",
                    "severity": "CRITICAL",
                    "detail": (
                        "Password form on a nearly empty page (" + str(word_count) + " words). "
                        "This is a hallmark of a credential-harvesting phishing page."
                    ),
                })
                risk_score += 55
            else:
                indicators.append({
                    "type": "CREDENTIAL_FORM",
                    "severity": "HIGH",
                    "detail": "Page contains a password input field. Verify this is a legitimate login page.",
                })
                risk_score += 25

        elif has_email_field and word_count < 100:
            indicators.append({
                "type": "SPARSE_EMAIL_FORM",
                "severity": "MEDIUM",
                "detail": (
                    "Email/username form on a sparse page (" + str(word_count) + " words). "
                    "May be a credential pre-harvesting step."
                ),
            })
            risk_score += 20

        # --- 3. Any form on an essentially empty page ---
        if forms.get("count", 0) > 0 and word_count < 40 and not has_password_field and not has_email_field:
            indicators.append({
                "type": "SPARSE_FORM_PAGE",
                "severity": "MEDIUM",
                "detail": (
                    "Form detected on a nearly empty page (" + str(word_count) + " words). "
                    "May be used for silent data collection."
                ),
            })
            risk_score += 20

        # --- 4. Urgency / pressure language ---
        urgency_matches = [p for p in self.URGENCY_PATTERNS if p in visible_text or p in title]
        has_urgency = bool(urgency_matches)
        if has_urgency:
            indicators.append({
                "type": "URGENCY_LANGUAGE",
                "severity": "MEDIUM",
                "detail": "Page uses urgency/pressure tactics: " + ", ".join(urgency_matches[:3]),
            })
            risk_score += 15

        # --- 5. Credential solicitation in page text ---
        cred_text_matches = [p for p in self.CREDENTIAL_TEXT_PATTERNS if p in visible_text]
        if cred_text_matches:
            indicators.append({
                "type": "CREDENTIAL_SOLICITATION",
                "severity": "HIGH",
                "detail": (
                    "Page explicitly requests sensitive information: "
                    + ", ".join(cred_text_matches[:3])
                ),
            })
            risk_score += 25

        # --- 6. Spoofed title heuristic ---
        spoofed_title = any(p in title for p in self.SPOOFED_TITLE_PATTERNS)
        if spoofed_title and word_count < 200:
            indicators.append({
                "type": "SUSPICIOUS_TITLE",
                "severity": "LOW",
                "detail": (
                    "Page title suggests a login/verification page: \""
                    + page_data.get("title", "")
                    + "\". Combined with sparse content, this may indicate a phishing clone."
                ),
            })
            risk_score += 10

        # --- 7. Redirect chain crossing multiple domains ---
        redirects = page_data.get("redirects") or []
        if isinstance(redirects, list) and len(redirects) >= 2:
            domains_in_chain = set()
            for hop in redirects:
                for field in ("from", "to"):
                    hop_url = hop.get(field, "")
                    try:
                        from urllib.parse import urlparse
                        d = urlparse(hop_url).hostname or ""
                        if d:
                            domains_in_chain.add(d.lower().lstrip("www."))
                    except Exception:
                        pass
            if len(domains_in_chain) > 1:
                indicators.append({
                    "type": "MULTI_DOMAIN_REDIRECT",
                    "severity": "MEDIUM",
                    "detail": (
                        "URL passed through " + str(len(redirects)) + " redirect hop(s) across "
                        + str(len(domains_in_chain)) + " different domains before reaching the final page."
                    ),
                })
                risk_score += 15

        return {
            "available": True,
            "title": page_data.get("title", ""),
            "word_count": word_count,
            "forms": forms,
            "indicators": indicators,
            "page_risk_score": min(risk_score, 100),
            "has_credential_form": has_credential_form,
            "has_fake_error": has_fake_error,
            "has_urgency": has_urgency,
        }
