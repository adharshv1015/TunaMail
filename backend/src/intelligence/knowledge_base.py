"""
Local Knowledge Base for TunaMail Stage 5.

Provides a curated, extensible, locally-stored knowledge base of:
- Trusted domains (not a permanent whitelist — evidence signal only)
- Known brands and their official domains
- Suspicious TLD patterns
- Known attack pattern keywords (multi-signal; keywords alone never classify email)

A single analyst decision never permanently whitelists or blacklists an indicator.
"""

import json
import os
import logging

logger = logging.getLogger(__name__)

_KB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "knowledge_base.json"
)

# Seed knowledge base — initial curated values
_SEED = {
    "trusted_domains": [
        "google.com", "gmail.com", "googlemail.com", "googleapis.com",
        "gstatic.com", "googleusercontent.com",
        "microsoft.com", "outlook.com", "office.com", "live.com",
        "microsoftonline.com", "office365.com",
        "apple.com", "icloud.com",
        "paypal.com",
        "amazon.com", "aws.amazon.com",
        "github.com", "githubusercontent.com",
        "linkedin.com", "twitter.com", "x.com", "facebook.com",
        "instagram.com", "whatsapp.com",
        "dropbox.com", "box.com",
        "cloudflare.com", "fastly.net",
        "stripe.com", "braintreegateway.com"
    ],
    "brands": {
        "Google": ["google.com", "gmail.com", "googlemail.com", "googleapis.com", "googleusercontent.com", "gstatic.com"],
        "Microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com", "microsoftonline.com"],
        "Apple": ["apple.com", "icloud.com"],
        "PayPal": ["paypal.com"],
        "Amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in"],
        "GitHub": ["github.com", "githubusercontent.com"],
        "LinkedIn": ["linkedin.com"],
        "Twitter": ["twitter.com", "x.com"],
        "Facebook": ["facebook.com", "fb.com", "meta.com"],
        "Instagram": ["instagram.com"],
        "Dropbox": ["dropbox.com"],
        "Stripe": ["stripe.com"],
        "Cloudflare": ["cloudflare.com"]
    },
    "suspicious_tlds": [
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
        ".loan", ".work", ".rest", ".win", ".bid", ".review", ".trade",
        ".date", ".racing", ".download", ".accountant"
    ],
    "trusted_tls_issuers": [
        "Google Trust Services LLC",
        "Let's Encrypt",
        "DigiCert Inc",
        "GlobalSign nv-sa",
        "Sectigo Limited",
        "Cloudflare, Inc.",
        "Amazon",
        "Microsoft Corporation",
        "GoDaddy.com, Inc.",
        "IdenTrust",
        "ZeroSSL",
        "ISRG Root X1",
        "Baltimore CyberTrust Root"
    ],
    "suspicious_patterns": {
        "login_lookalike": ["login-", "-login.", "signin-", "-signin.", "secure-", "-secure."],
        "brand_lookalike": ["paypa1", "micros0ft", "app1e", "g00gle", "arnazon"],
        "urgency_domains": ["urgent-", "alert-", "action-", "verify-", "confirm-"]
    },
    "known_safe_iocs": [],
    "known_malicious_iocs": [],
    "domain_trust_adjustments": {},
    "sender_trust_adjustments": {}
}


class KnowledgeBase:
    """
    Local extensible knowledge store. JSON-backed for persistence.
    Loaded once per process; writes persist to disk.
    """

    def __init__(self, kb_path: str = None):
        self._path = kb_path or _KB_PATH
        self._data = self._load()

    def _load(self) -> dict:
        if os.path.exists(self._path):
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Merge any new seed keys not present in saved file
                    for k, v in _SEED.items():
                        if k not in data:
                            data[k] = v
                    return data
            except Exception as e:
                logger.warning(f"KnowledgeBase load failed, using seed: {e}")
        return dict(_SEED)

    def _save(self):
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        try:
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
        except Exception as e:
            logger.error(f"KnowledgeBase save failed: {e}")

    # ---- Queries ----

    def is_trusted_domain(self, domain: str) -> bool:
        """Check if a domain is in the trusted list (evidence signal, not verdict)."""
        d = domain.lower().strip()
        if d.startswith("www."):
            d = d[4:]
        return d in self._data.get("trusted_domains", [])

    def is_trusted_tls_issuer(self, issuer: str) -> bool:
        """Check if a TLS certificate issuer is explicitly trusted."""
        if not issuer:
            return False
        
        # Exact match or substring match (e.g., "Let's Encrypt" in "Let's Encrypt Authority X3")
        trusted_issuers = self._data.get("trusted_tls_issuers", [])
        return any(trusted.lower() in issuer.lower() for trusted in trusted_issuers)

    def brand_for_domain(self, domain: str) -> str | None:
        """Return the brand name associated with a domain, or None."""
        d = domain.lower().strip()
        if d.startswith("www."):
            d = d[4:]
        for brand, domains in self._data.get("brands", {}).items():
            if d in domains or any(d.endswith("." + bd) for bd in domains):
                return brand
        return None

    def has_suspicious_tld(self, domain: str) -> bool:
        for tld in self._data.get("suspicious_tlds", []):
            if domain.lower().endswith(tld):
                return True
        return False

    def has_suspicious_pattern(self, domain: str) -> list:
        """Returns list of matched suspicious pattern categories."""
        d = domain.lower()
        matched = []
        for category, patterns in self._data.get("suspicious_patterns", {}).items():
            if any(p in d for p in patterns):
                matched.append(category)
        return matched

    def is_known_malicious(self, ioc_value: str) -> bool:
        return ioc_value.lower() in [v.lower() for v in self._data.get("known_malicious_iocs", [])]

    def is_known_safe(self, ioc_value: str) -> bool:
        return ioc_value.lower() in [v.lower() for v in self._data.get("known_safe_iocs", [])]

    def get_domain_trust_adjustment(self, domain: str) -> float:
        """Returns analyst-driven trust adjustment for domain (-1.0 to +1.0)."""
        return self._data.get("domain_trust_adjustments", {}).get(domain.lower(), 0.0)

    def get_sender_trust_adjustment(self, sender: str) -> float:
        return self._data.get("sender_trust_adjustments", {}).get(sender.lower(), 0.0)


    def adjust_domain_trust(self, domain: str, delta: float):
        """
        Adjust trust for a domain by a delta (-1.0 to +1.0).
        Clamped to [-1.0, 1.0]. Never permanently whitelists.
        """
        key = domain.lower()
        adjustments = self._data.setdefault("domain_trust_adjustments", {})
        current = adjustments.get(key, 0.0)
        adjustments[key] = max(-1.0, min(1.0, current + delta))
        self._save()

    def adjust_sender_trust(self, sender: str, delta: float):
        key = sender.lower()
        adjustments = self._data.setdefault("sender_trust_adjustments", {})
        current = adjustments.get(key, 0.0)
        adjustments[key] = max(-1.0, min(1.0, current + delta))
        self._save()

    def mark_ioc_safe(self, ioc_value: str):
        """Add IOC to known_safe list (requires repeated analyst confirmation to be meaningful)."""
        safe_list = self._data.setdefault("known_safe_iocs", [])
        if ioc_value not in safe_list:
            safe_list.append(ioc_value)
            self._save()

    def mark_ioc_malicious(self, ioc_value: str):
        malicious_list = self._data.setdefault("known_malicious_iocs", [])
        if ioc_value not in malicious_list:
            malicious_list.append(ioc_value)
            self._save()

    def get_all(self) -> dict:
        return dict(self._data)


# Module-level singleton
_kb_instance = None


def get_knowledge_base() -> KnowledgeBase:
    global _kb_instance
    if _kb_instance is None:
        _kb_instance = KnowledgeBase()
    return _kb_instance
