import re
import ipaddress
from urllib.parse import urlparse, unquote, parse_qs
from email.utils import parseaddr
import tldextract
try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False

from src.services.url_inspection_service import URLInspectionService

# Known tracking/safety-redirect wrappers that encode the real URL in a query param
_REDIRECT_PATTERNS = [
    # Google Safety redirect: https://www.google.com/url?q=https%3A%2F%2F...
    ("google.com", "q"),
    ("google.com", "url"),
    # Outlook/Microsoft SafeLinks: https://nam.safelinks.protection.outlook.com/?url=...
    ("safelinks.protection.outlook.com", "url"),
    # Proofpoint URLDefense
    ("urldefense.com", "u"),
    # Generic tracking redirectors
    (None, "redirect_uri"),
    (None, "redirect_url"),
    (None, "target_url"),
]

class URLAnalyzer:

    TRUSTED_DOMAINS = [
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
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

    def _unwrap_redirect(self, url):
        """
        Unwrap known tracking/safety-redirect wrappers (e.g. Google's
        https://www.google.com/url?q=<encoded>) to reveal the real URL.
        Returns the inner URL if found, otherwise returns the original url.
        """
        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower().lstrip("www.")
            qs = parse_qs(parsed.query)

            for domain, param in _REDIRECT_PATTERNS:
                # domain=None means we check the param on any host
                if domain is not None and not hostname.endswith(domain):
                    continue
                if param in qs:
                    inner = unquote(qs[param][0]).strip()
                    # Must look like a real URL
                    if inner.startswith(("http://", "https://")):
                        return inner
        except Exception:
            pass
        return url

    def extract_urls(self, text):
        if not text:
            return []

        raw_urls = []

        # --- Pass 1: Parse HTML href/src attributes directly (most reliable for HTML email) ---
        if _BS4_AVAILABLE and ("<a " in text or "<A " in text or "href=" in text):
            try:
                soup = BeautifulSoup(text, "html.parser")
                for tag in soup.find_all(["a", "link", "img", "iframe", "form"]):
                    for attr in ("href", "src", "action", "data-url"):
                        val = tag.get(attr, "")
                        if val and isinstance(val, str) and val.startswith(("http://", "https://")):
                            raw_urls.append(val.strip())
            except Exception:
                pass

        # --- Pass 2: Regex fallback — catches URLs in plain text and any missed by BS4 ---
        pattern1 = r'https?://[^\s<>"\']+'  
        pattern2 = r'(?<!/)\bwww\.[^\s<>"\']+'  

        raw_urls.extend(re.findall(pattern1, text))
        www_urls = re.findall(pattern2, text)
        for w in www_urls:
            raw_urls.append("http://" + w)

        # --- Pass 3: Clean, deduplicate, and unwrap redirect wrappers ---
        cleaned_urls = []
        seen = set()
        for url in raw_urls:
            url = url.rstrip(".,;:!?)]}<>'\"")
            # Unwrap tracking/safety redirectors (e.g. Google safety links)
            url = self._unwrap_redirect(url)
            url = url.rstrip(".,;:!?)]}<>'\"")
            if url not in seen and url.startswith("http"):
                seen.add(url)
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

        # TLS Policy Evaluation
        tls_info = inspection_data.get("tls", {})
        violation = tls_info.get("violation")
        
        inspection_data["http_policy_warning"] = tls_info.get("https") is False
        
        policy_violations = [
            "EXPIRED_CERTIFICATE", 
            "HOSTNAME_MISMATCH", 
            "SELF_SIGNED_CERTIFICATE", 
            "UNTRUSTED_ISSUER", 
            "CERTIFICATE_INVALID"
        ]
        inspection_data["tls_policy_violation"] = violation in policy_violations
        
        unavailable_issues = [
            "TLS_HANDSHAKE_FAILED",
            "TLS_UNAVAILABLE"
        ]
        inspection_data["tls_inspection_unavailable"] = violation in unavailable_issues

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
        import difflib
        hostname = (inspection_data.get("domain") or "").lower()
        registered_domain = (inspection_data.get("registered_domain") or "").lower()
        
        if not hostname or not registered_domain:
            return "UNKNOWN"
            
        # First pass: check for exact match or subdomain of any trusted domain
        for trusted in self.TRUSTED_DOMAINS:
            if hostname == trusted:
                return "OFFICIAL"
            if hostname.endswith("." + trusted):
                return "SUBDOMAIN_OF_OFFICIAL"
                
        # Second pass: check for impersonation and lookalikes
        for trusted in self.TRUSTED_DOMAINS:
            trusted_brand = trusted.split(".")[0]
            
            # Impersonation (contains brand name but different registered domain)
            if trusted_brand in hostname and trusted not in registered_domain:
                return "IMPERSONATION"
                
            # Lookalike checks
            # Replace common substitutions (e.g., 1->l, 0->o)
            lookalike_host = hostname.replace("1", "l").replace("0", "o")
            if trusted_brand in lookalike_host and trusted not in registered_domain:
                return "LOOKALIKE"
            
            # Typo-squatting via SequenceMatcher (e.g., 'gogle' for 'google')
            for part in hostname.split("."):
                # Avoid matching very short parts to prevent false positives
                if len(part) < 4:
                    continue
                ratio = difflib.SequenceMatcher(None, trusted_brand, part).ratio()
                if ratio > 0.8 and trusted not in registered_domain:
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

        # Trusted domains are never considered obfuscated
        domain = (parsed.hostname or "").lower()
        if self.is_trusted_domain(domain):
            return False

        # Credentials embedded in the URL (e.g. http://user@evil.com)
        if "@" in parsed.netloc:
            return True

        # Percent encoding in the DOMAIN/NETLOC is suspicious
        # (e.g. http://g%6f%6fgle.com) — but NOT in path or query string
        # which is perfectly normal (e.g. ?continue=...%3D...)
        if "%" in parsed.netloc:
            return True

        # IP-literal hostname
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