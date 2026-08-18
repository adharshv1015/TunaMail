import re

class AdversarialAnalyzer:
    """
    Detects combinations of indicators and adversarial attempts to manipulate
    the detection system using misleading context or fake security language.
    """

    def __init__(self):
        # Keyword patterns for context detection (not standalone rules)
        self.security_kw = re.compile(r'\b(verify|security|login|password|alert|confirm|unauthorized|protect|suspicious)\b', re.IGNORECASE)
        self.urgency_kw = re.compile(r'\b(immediately|urgent|action required|final warning|now|24 hours)\b', re.IGNORECASE)
        self.credential_kw = re.compile(r'\b(password|login|credentials|sign in|auth|verify account)\b', re.IGNORECASE)
        self.threat_kw = re.compile(r'\b(suspend|close|terminate|block|restrict|locked)\b', re.IGNORECASE)
        self.finance_kw = re.compile(r'\b(invoice|payment|receipt|billing|transaction|remittance)\b', re.IGNORECASE)
        
        self.fake_brands_kw = re.compile(r'\b(microsoft|google|apple|paypal|amazon|netflix|meta|facebook|instagram)\b', re.IGNORECASE)

    def analyze(self, text_content: str, url_analysis: list, sender_domain: str, is_html: bool = False) -> list:
        evidence = []
        if not text_content:
            return evidence

        text_lower = text_content.lower()

        # Gather base signals
        sec_count = len(self.security_kw.findall(text_lower))
        has_urgency = bool(self.urgency_kw.search(text_lower))
        has_credential_req = bool(self.credential_kw.search(text_lower))
        has_threat = bool(self.threat_kw.search(text_lower))
        has_finance = bool(self.finance_kw.search(text_lower))
        has_fake_brand = bool(self.fake_brands_kw.search(text_lower))

        has_urls = len(url_analysis) > 0
        has_suspicious_url = any(u.get("threat_intelligence", {}).get("detections", 0) > 0 or u.get("punycode") for u in url_analysis)
        
        # Determine if URLs are "unrelated" (different from sender)
        has_unrelated_url = False
        for u in url_analysis:
            if u.get("domain") and sender_domain:
                if u.get("domain") not in sender_domain and sender_domain not in u.get("domain"):
                    has_unrelated_url = True

        # Rule 1: Urgency + Credential Request
        if has_urgency and has_credential_req:
            evidence.append(self._create_evidence("ADVERSARIAL", "HIGH", 0.85, "Urgency combined with credential request."))

        # Rule 2: Threat Language + Account Recovery/Login
        if has_threat and has_credential_req:
            evidence.append(self._create_evidence("ADVERSARIAL", "HIGH", 0.90, "Threat language combined with account recovery/login request."))

        # Rule 3: Verification + Unrelated Domain
        if sec_count >= 2 and has_unrelated_url:
            evidence.append(self._create_evidence("ADVERSARIAL", "HIGH", 0.80, "Security/verification language combined with unrelated external domain."))

        # Rule 4: Payment/Invoice + Suspicious URL
        if has_finance and has_suspicious_url:
            evidence.append(self._create_evidence("ADVERSARIAL", "HIGH", 0.90, "Payment/invoice request combined with suspicious URL."))

        # Rule 5: Fake Notifications (Brand + Security/Login + Unrelated domain)
        if has_fake_brand and has_credential_req and has_unrelated_url:
            evidence.append(self._create_evidence("ADVERSARIAL", "HIGH", 0.85, "Major brand mentioned alongside login request pointing to unrelated domain."))

        # Rule 6: Excessive benign/security keywords (trying to fool Bayes)
        words = text_lower.split()
        if len(words) > 50 and (sec_count / len(words)) > 0.15:
             evidence.append(self._create_evidence("ADVERSARIAL", "MEDIUM", 0.70, "Excessive security terminology density detected."))

        # Check obfuscated URLs / Anchor mismatch
        for u in url_analysis:
            if u.get("obfuscated"):
                evidence.append(self._create_evidence("ADVERSARIAL", "HIGH", 0.95, f"Obfuscated URL detected: {u.get('url')}"))
            if u.get("shortener"):
                evidence.append(self._create_evidence("ADVERSARIAL", "MEDIUM", 0.80, f"URL shortener used: {u.get('url')}"))

        return evidence

    def _create_evidence(self, category: str, severity: str, confidence: float, explanation: str) -> dict:
        return {
            "type": category,
            "severity": severity,
            "confidence": confidence,
            "source": "adversarial_analyzer",
            "explanation": explanation
        }
