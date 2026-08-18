"""
Attack Pattern Detection Engine for TunaMail Stage 5.

Detects named attack patterns using MULTI-SIGNAL evidence.
A single keyword NEVER classifies an email into a pattern.
Every pattern requires contextual evidence from multiple sources.

Supported Patterns:
    CREDENTIAL_HARVESTING, ACCOUNT_VERIFICATION_PHISHING, PASSWORD_RESET_PHISHING,
    INVOICE_FRAUD, PAYMENT_REQUEST, BUSINESS_EMAIL_COMPROMISE, EXECUTIVE_IMPERSONATION,
    MFA_FATIGUE, DELIVERY_SHIPPING_SCAM, TECH_SUPPORT_SCAM, MALWARE_ATTACHMENT,
    LINK_ONLY_PHISHING, BRAND_IMPERSONATION
"""

import re
from typing import List, Dict, Any


class PatternEngine:
    """
    Multi-signal attack pattern detection.
    Requires evidence from content, URLs, authentication, and context.
    """

    # Each pattern requires multiple signal groups to match
    _PATTERNS = {
        "CREDENTIAL_HARVESTING": {
            "description": "Email designed to steal credentials via fake login page",
            "required_signals": 3,
            "signals": [
                ("content_credential_request", "Contains credential request"),
                ("content_urgency", "Contains urgency language"),
                ("url_brand_impersonation", "URL impersonates a known brand"),
                ("auth_fail", "Authentication failed"),
                ("url_login_lookalike", "URL resembles a login page"),
            ]
        },
        "ACCOUNT_VERIFICATION_PHISHING": {
            "description": "Fake account verification request",
            "required_signals": 3,
            "signals": [
                ("content_verify_keywords", "Contains verification language"),
                ("content_urgency", "Contains urgency language"),
                ("url_mismatch", "URL domain does not match sender"),
                ("auth_fail", "Authentication failed"),
            ]
        },
        "PASSWORD_RESET_PHISHING": {
            "description": "Fake password reset request",
            "required_signals": 3,
            "signals": [
                ("content_password_reset_keywords", "Contains password reset language"),
                ("url_brand_impersonation", "URL impersonates known brand"),
                ("auth_fail", "Authentication failed"),
                ("content_urgency", "Contains urgency"),
            ]
        },
        "INVOICE_FRAUD": {
            "description": "Fake or fraudulent invoice email",
            "required_signals": 2,
            "signals": [
                ("content_invoice_keywords", "Contains invoice language"),
                ("attachment_present", "Has attachment"),
                ("auth_fail", "Authentication failed"),
            ]
        },
        "PAYMENT_REQUEST": {
            "description": "Fraudulent payment request",
            "required_signals": 2,
            "signals": [
                ("content_payment_keywords", "Contains payment request language"),
                ("content_urgency", "Contains urgency"),
                ("auth_fail", "Authentication failed"),
                ("url_mismatch", "URL domain does not match sender"),
            ]
        },
        "BUSINESS_EMAIL_COMPROMISE": {
            "description": "Business email compromise attempt (wire fraud, vendor impersonation)",
            "required_signals": 3,
            "signals": [
                ("content_payment_keywords", "Contains payment/wire transfer language"),
                ("content_bec_keywords", "Contains BEC-style language"),
                ("auth_fail", "Authentication failed"),
                ("url_mismatch", "URL mismatch"),
                ("content_urgency", "Urgency present"),
            ]
        },
        "EXECUTIVE_IMPERSONATION": {
            "description": "Impersonates executive or high-authority individual",
            "required_signals": 2,
            "signals": [
                ("content_executive_keywords", "Contains executive impersonation language"),
                ("auth_fail", "Authentication failed"),
                ("url_mismatch", "URL mismatch"),
            ]
        },
        "MFA_FATIGUE": {
            "description": "Attempts to override MFA or push notification fatigue",
            "required_signals": 2,
            "signals": [
                ("content_mfa_keywords", "Contains MFA-related language"),
                ("content_urgency", "Urgency present"),
                ("auth_fail", "Authentication failed"),
            ]
        },
        "DELIVERY_SHIPPING_SCAM": {
            "description": "Fake delivery/shipping notification",
            "required_signals": 2,
            "signals": [
                ("content_delivery_keywords", "Contains delivery language"),
                ("url_mismatch", "URL domain does not match official carrier"),
                ("auth_fail", "Authentication failed"),
            ]
        },
        "TECH_SUPPORT_SCAM": {
            "description": "Fake tech support or security alert",
            "required_signals": 2,
            "signals": [
                ("content_tech_support_keywords", "Contains tech support language"),
                ("content_urgency", "Urgency present"),
                ("url_mismatch", "URL mismatch"),
            ]
        },
        "MALWARE_ATTACHMENT": {
            "description": "Email carrying malicious attachment",
            "required_signals": 1,
            "signals": [
                ("attachment_dangerous", "Dangerous attachment type"),
                ("attachment_macro", "Macro-enabled document"),
                ("attachment_script", "Script attachment"),
                ("attachment_double_ext", "Double extension attachment"),
            ]
        },
        "LINK_ONLY_PHISHING": {
            "description": "Email containing only a link with no contextual content",
            "required_signals": 2,
            "signals": [
                ("link_only_body", "Email body is link-only"),
                ("url_mismatch", "URL domain does not match sender"),
                ("auth_fail", "Authentication failed"),
            ]
        },
        "BRAND_IMPERSONATION": {
            "description": "Impersonates a known brand via URL or content",
            "required_signals": 2,
            "signals": [
                ("url_brand_impersonation", "URL impersonates known brand"),
                ("content_brand_keywords", "Content references brand inappropriately"),
                ("auth_fail", "Authentication failed"),
            ]
        }
    }

    # Content keyword sets
    _VERIFY_KW = re.compile(r'\b(verify|verification|confirm|activate|validate)\b', re.I)
    _URGENCY_KW = re.compile(r'\b(urgent|immediately|suspended|limited time|act now|expire|within \d+ hours|account will be)\b', re.I)
    _CREDENTIAL_KW = re.compile(r'\b(password|username|login|sign.?in|credentials|account access)\b', re.I)
    _RESET_KW = re.compile(r'\b(reset|forgot|new password|change password|password expired)\b', re.I)
    _INVOICE_KW = re.compile(r'\b(invoice|receipt|payment due|billing|order confirmation|purchase)\b', re.I)
    _PAYMENT_KW = re.compile(r'\b(wire transfer|bank transfer|payment|send money|remit|ach|bitcoin|crypto)\b', re.I)
    _BEC_KW = re.compile(r'\b(ceo|president|executive|on behalf|confidential|do not discuss|vendor change|new banking)\b', re.I)
    _EXEC_KW = re.compile(r'\b(ceo|cfo|vp |director|president|chairman|founder)\b', re.I)
    _MFA_KW = re.compile(r'\b(mfa|two.?factor|authenticator|push notification|approve login|otp|one.?time)\b', re.I)
    _DELIVERY_KW = re.compile(r'\b(delivery|shipment|package|parcel|tracking|courier|fedex|ups|dhl|usps)\b', re.I)
    _SUPPORT_KW = re.compile(r'\b(tech support|helpdesk|call us|support team|your computer|virus detected|microsoft support|apple support|windows)\b', re.I)
    _BRAND_KW = re.compile(r'\b(google|microsoft|apple|paypal|amazon|linkedin|facebook|instagram|dropbox|netflix)\b', re.I)
    _LOGIN_URL = re.compile(r'(login|signin|secure|verify|account|auth|password)', re.I)

    def detect(
        self,
        parsed_email: dict,
        existing_analysis: dict,
        entities: dict
    ) -> List[Dict]:
        """
        Detect attack patterns from multi-signal evidence.

        Returns a list of detected patterns sorted by confidence descending.
        """
        if existing_analysis is None:
            existing_analysis = {}

        signals = self._extract_signals(parsed_email, existing_analysis, entities)
        detected = []

        for pattern_name, pattern_def in self._PATTERNS.items():
            matched = []
            for signal_key, signal_desc in pattern_def["signals"]:
                if signals.get(signal_key):
                    matched.append(signal_desc)

            if len(matched) >= pattern_def["required_signals"]:
                confidence = min(100, int((len(matched) / len(pattern_def["signals"])) * 100))
                # Boost confidence if multiple high-quality signals
                if signals.get("auth_fail") and signals.get("url_brand_impersonation"):
                    confidence = min(100, confidence + 10)
                detected.append({
                    "name": pattern_name,
                    "description": pattern_def["description"],
                    "confidence": confidence,
                    "matched_signals": matched
                })

        return sorted(detected, key=lambda x: x["confidence"], reverse=True)

    def _extract_signals(self, parsed_email: dict, existing_analysis: dict, entities: dict) -> dict:
        """Extract boolean signals from all evidence sources."""
        body = (parsed_email.get("body", "") or "").lower()
        subject = (parsed_email.get("subject", "") or "").lower()
        full_text = f"{subject} {body}"

        auth = existing_analysis.get("authentication", {})
        content = existing_analysis.get("content", {})
        url_analysis = existing_analysis.get("url", {})
        attachment = existing_analysis.get("attachment", {})

        # Auth signals
        auth_fail = not (auth.get("spf") == "pass" and auth.get("dkim") == "pass")

        # URL signals
        url_brand_impersonation = any(
            item.get("brand_impersonation", False)
            for item in url_analysis.get("analysis", [])
        )
        url_mismatch = any(
            item.get("email_alignment") == "misaligned"
            for item in url_analysis.get("analysis", [])
        )
        url_login_lookalike = any(
            bool(_PatternEngine_RE_LOGIN.search(item.get("url", "") or ""))
            for item in url_analysis.get("analysis", [])
        )

        # Content signals
        has_credential_request = bool(content.get("credential_request")) or bool(self._CREDENTIAL_KW.search(full_text))
        has_urgency = bool(content.get("urgency")) or bool(self._URGENCY_KW.search(full_text))
        has_threat = bool(content.get("threat_language"))

        # Attachment signals
        att_evidence = attachment.get("evidence", [])
        attachment_dangerous = any("Executable" in e for e in att_evidence)
        attachment_macro = any("Macro" in e for e in att_evidence)
        attachment_script = any("Script" in e for e in att_evidence)
        attachment_double_ext = any("Multiple extensions" in e for e in att_evidence)
        attachment_present = attachment.get("attachment_count", 0) > 0

        # Body structure signals
        body_words = body.split()
        link_only_body = (
            len(body_words) < 8 and
            bool(re.search(r'https?://', body))
        )

        return {
            "auth_fail": auth_fail,
            "url_brand_impersonation": url_brand_impersonation,
            "url_mismatch": url_mismatch,
            "url_login_lookalike": url_login_lookalike,
            "content_credential_request": has_credential_request,
            "content_urgency": has_urgency,
            "content_threat": has_threat,
            "content_verify_keywords": bool(self._VERIFY_KW.search(full_text)),
            "content_password_reset_keywords": bool(self._RESET_KW.search(full_text)),
            "content_invoice_keywords": bool(self._INVOICE_KW.search(full_text)),
            "content_payment_keywords": bool(self._PAYMENT_KW.search(full_text)),
            "content_bec_keywords": bool(self._BEC_KW.search(full_text)),
            "content_executive_keywords": bool(self._EXEC_KW.search(full_text)),
            "content_mfa_keywords": bool(self._MFA_KW.search(full_text)),
            "content_delivery_keywords": bool(self._DELIVERY_KW.search(full_text)),
            "content_tech_support_keywords": bool(self._SUPPORT_KW.search(full_text)),
            "content_brand_keywords": bool(self._BRAND_KW.search(full_text)),
            "attachment_present": attachment_present,
            "attachment_dangerous": attachment_dangerous,
            "attachment_macro": attachment_macro,
            "attachment_script": attachment_script,
            "attachment_double_ext": attachment_double_ext,
            "link_only_body": link_only_body,
        }


# Module-level RE to avoid recompilation
_PatternEngine_RE_LOGIN = re.compile(r'(login|signin|secure|verify|account|auth|password)', re.I)
