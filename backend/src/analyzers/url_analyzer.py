import re
import ipaddress
from urllib.parse import urlparse, unquote
from email.utils import parseaddr
import tldextract

from src.services.url_inspection_service import URLInspectionService

class URLAnalyzer:

    TRUSTED_DOMAINS = [
        "google.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "paypal.com",
    ]

    SHORTENERS = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "shorturl.at",
    }

    SUSPICIOUS_KEYWORDS = [
        "login",
        "verify",
        "secure",
        "account",
        "password",
        "update",
        "confirm",
        "signin",
        "authenticate",
        "unlock",
        "suspended",
        "validation",
    ]

    def __init__(self):
        self.inspection_service = URLInspectionService()

    def analyze(self, body, sender_headers=None, auth_results=None):
        urls = self.extract_urls(body)
        results = []

        for url in urls:
            results.append(self.analyze_url(url, sender_headers, auth_results))

        return {
            "urls": urls,
            "analysis": results,
            "limited_context": self._is_limited_context(body, urls)
        }

    def _is_limited_context(self, body, urls):
        if not urls:
            return False
        # If the body is mostly just URLs, with very little text, it's limited context
        text_without_urls = body
        for url in urls:
            text_without_urls = text_without_urls.replace(url, "")
        
        cleaned_text = text_without_urls.strip()
        # If the remaining text is less than 20 characters or just a few words, it's limited context
        if len(cleaned_text) < 30 or len(cleaned_text.split()) < 5:
            return True
        return False

    def extract_urls(self, text):
        if not text:
            return []
        pattern = r'https?://[^\s<>"]+'
        urls = re.findall(pattern, text)
        cleaned_urls = []
        for url in urls:
            url = url.rstrip(".,;:!?)]}>")
            if url not in cleaned_urls:
                cleaned_urls.append(url)
        return cleaned_urls

    def analyze_url(self, url, sender_headers, auth_results):
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        domain = domain.lower().rstrip(".")

        # Run safe external inspection
        inspection_data = self.inspection_service.inspect(url)
        
        # Backward-compatible fields
        inspection_data["ip_based"] = self.is_ip(domain)
        inspection_data["shortener"] = self.is_shortener(domain)
        inspection_data["keywords"] = self.detect_keywords(url, domain)
        inspection_data["obfuscated"] = self.is_obfuscated(url)
        inspection_data["punycode"] = self.is_punycode(domain)
        inspection_data["suspicious_port"] = self.has_suspicious_port(parsed)
        inspection_data["subdomain_count"] = self.subdomain_count(domain)

        # Brand Analysis & Sender Alignment
        inspection_data["email_alignment"] = self.evaluate_alignment(inspection_data, sender_headers, auth_results)
        
        brand_rel = self.evaluate_brand_relationship(inspection_data)
        inspection_data["brand_relationship"] = brand_rel
        inspection_data["brand_impersonation"] = brand_rel in ["IMPERSONATION", "LOOKALIKE"]
        inspection_data["brand_match"] = brand_rel in ["OFFICIAL", "SUBDOMAIN_OF_OFFICIAL"]

        return inspection_data

    def get_email_domain(self, email_str):
        if not email_str:
            return None
        _, addr = parseaddr(email_str)
        if "@" in addr:
            return addr.split("@")[-1].lower()
        return None

    def evaluate_alignment(self, inspection_data, sender_headers, auth_results):
        if not sender_headers:
            return "unknown"

        url_reg_domain = inspection_data.get("registered_domain")
        if not url_reg_domain:
            return "unknown"

        from_domain = self.get_email_domain(sender_headers.get("from", ""))
        return_path_domain = self.get_email_domain(sender_headers.get("return-path", ""))
        
        # Must have at least a sender domain to compare
        if not from_domain:
            return "unknown"

        sender_ext = tldextract.extract(from_domain)
        sender_reg_domain = sender_ext.registered_domain if sender_ext.registered_domain else from_domain

        # Authenticated sender
        is_authenticated = False
        if auth_results:
            is_authenticated = auth_results.get("spf") == "pass" or auth_results.get("dkim") == "pass"

        if sender_reg_domain == url_reg_domain:
            if is_authenticated:
                return "aligned"
            else:
                return "partially_aligned"
                
        # If there's a return-path and it matches, partial alignment
        if return_path_domain:
            return_ext = tldextract.extract(return_path_domain)
            return_reg_domain = return_ext.registered_domain if return_ext.registered_domain else return_path_domain
            if return_reg_domain == url_reg_domain:
                return "partially_aligned"

        return "misaligned"

    def evaluate_brand_relationship(self, inspection_data):
        hostname = (inspection_data.get("domain") or "").lower()
        registered_domain = (inspection_data.get("registered_domain") or "").lower()
        
        if not hostname or not registered_domain:
            return "UNKNOWN"
            
        for trusted in self.TRUSTED_DOMAINS:
            trusted_brand = trusted.split(".")[0]
            
            # Exact match
            if hostname == trusted:
                return "OFFICIAL"
                
            # Subdomain of trusted
            if hostname.endswith("." + trusted):
                return "SUBDOMAIN_OF_OFFICIAL"
                
            # Impersonation (contains brand name but different registered domain)
            if trusted_brand in hostname and trusted not in registered_domain:
                return "IMPERSONATION"
                
            # Lookalike checks
            # Replace common substitutions (e.g., 1->l, 0->o)
            lookalike_host = hostname.replace("1", "l").replace("0", "o")
            if trusted_brand in lookalike_host and trusted not in registered_domain:
                return "LOOKALIKE"
                
        return "UNKNOWN"

    def is_ip(self, domain):
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False

    def is_shortener(self, domain):
        return domain in self.SHORTENERS

    def is_trusted_domain(self, domain):
        domain = domain.lower().rstrip(".")
        for trusted in self.TRUSTED_DOMAINS:
            if domain == trusted or domain.endswith("." + trusted):
                return True
        return False

    def detect_keywords(self, url, domain):
        if self.is_trusted_domain(domain):
            return []
        decoded_url = unquote(url).lower()
        found = []
        for word in self.SUSPICIOUS_KEYWORDS:
            if word in decoded_url:
                found.append(word)
        return found

    def is_obfuscated(self, url):
        parsed = urlparse(url)
        if "@" in parsed.netloc:
            return True
        if "%" in url:
            return True
        if parsed.hostname:
            try:
                if parsed.hostname.isdigit():
                    return True
            except Exception:
                pass
        return False

    def is_punycode(self, domain):
        return "xn--" in domain.lower()

    def has_suspicious_port(self, parsed):
        try:
            port = parsed.port
            if port is None:
                return False
            return port not in {80, 443}
        except ValueError:
            return True

    def subdomain_count(self, domain):
        if not domain:
            return 0
        if self.is_ip(domain):
            return 0
        parts = domain.split(".")
        if len(parts) <= 2:
            return 0
        return len(parts) - 2