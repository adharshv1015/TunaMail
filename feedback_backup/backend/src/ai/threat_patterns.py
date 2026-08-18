from typing import List, Dict

class ThreatPatterns:
    # Contextual indicators for credential harvesting
    CREDENTIAL_KEYWORDS: List[str] = [
        "login",
        "signin",
        "sign in",
        "verify",
        "password",
        "reset",
        "authenticate",
        "account",
        "security",
        "unlock",
        "confirm"
    ]
    
    FINANCIAL_KEYWORDS: List[str] = [
        "invoice",
        "payment",
        "billing",
        "receipt",
        "transaction",
        "charge",
        "fund"
    ]
    
    URGENCY_KEYWORDS: List[str] = [
        "urgent",
        "immediately",
        "action required",
        "final notice",
        "suspend",
        "suspended",
        "terminate",
        "expire"
    ]

    @classmethod
    def match_credential_harvesting(cls, text: str) -> bool:
        if not text:
            return False
        text_lower = text.lower()
        return any(kw in text_lower for kw in cls.CREDENTIAL_KEYWORDS)

    @classmethod
    def match_financial_request(cls, text: str) -> bool:
        if not text:
            return False
        text_lower = text.lower()
        return any(kw in text_lower for kw in cls.FINANCIAL_KEYWORDS)

    @classmethod
    def match_urgency(cls, text: str) -> bool:
        if not text:
            return False
        text_lower = text.lower()
        return any(kw in text_lower for kw in cls.URGENCY_KEYWORDS)
