"""
IOC (Indicator of Compromise) Extractor for TunaMail Stage 5.

Extracts indicators from parsed email data and existing analysis results.
Does NOT classify extracted IOCs as malicious — only extracts and normalizes.

Supported IOC types:
    EMAIL_ADDRESS, DOMAIN, URL, IP_ADDRESS, HASH_MD5, HASH_SHA1, HASH_SHA256,
    PHONE_NUMBER, CRYPTO_ADDRESS, ATTACHMENT_NAME, FILE_EXTENSION
"""

import re
import ipaddress
import tldextract
from urllib.parse import urlparse
from typing import List, Dict

# Regex patterns
_RE_EMAIL = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')
_RE_DOMAIN = re.compile(r'\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b')
_RE_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_RE_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
_RE_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
_RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_RE_PHONE = re.compile(r'\b(?:\+\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b')
_RE_CRYPTO_BTC = re.compile(r'\b(?:1|3)[a-zA-HJ-NP-Z1-9]{25,34}\b')
_RE_CRYPTO_ETH = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
_RE_URL = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)

# Known generic non-IOC domains to skip
_SKIP_DOMAINS = {"localhost", "example.com", "example.org", "test.com", "invalid"}

# Benign extensions that are not useful as attachment IOCs
_SKIP_EXTENSIONS = {".txt", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico"}


def _normalize_domain(domain: str) -> str:
    """Lowercase, strip www. prefix for normalization."""
    d = domain.lower().strip()
    if d.startswith("www."):
        d = d[4:]
    return d


def _normalize_url(url: str) -> str:
    """Strip trailing slash, lowercase scheme+host, keep path."""
    try:
        p = urlparse(url)
        path = p.path.rstrip("/") if p.path != "/" else p.path
        normalized = f"{p.scheme.lower()}://{p.netloc.lower()}{path}"
        if p.query:
            normalized += f"?{p.query}"
        return normalized
    except Exception:
        return url.lower().strip()


def _normalize_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip


def _is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _is_valid_domain(domain: str) -> bool:
    if domain in _SKIP_DOMAINS:
        return False
    if _is_valid_ip(domain):
        return False
    ext = tldextract.extract(domain)
    return bool(ext.domain and ext.suffix)


def _make_ioc(ioc_type: str, value: str, normalized: str, source: str, confidence: float) -> Dict:
    return {
        "type": ioc_type,
        "value": value,
        "original": value,
        "normalized": normalized,
        "source": source,
        "confidence": round(confidence, 3)
    }


class IOCExtractor:
    """
    Extracts indicators of compromise from email data.
    All IOCs are neutral observations — not pre-classified as malicious.
    """

    def extract(self, parsed_email: dict, existing_analysis: dict = None) -> List[Dict]:
        """
        Main entry point. Returns a deduplicated list of IOC dicts.

        Args:
            parsed_email: Output of GmailParser.parse_message()
            existing_analysis: Output of full analysis pipeline (url, attachment, etc.)
        """
        if existing_analysis is None:
            existing_analysis = {}

        iocs = []
        seen_normalized = set()

        def add(ioc: dict):
            key = f"{ioc['type']}:{ioc['normalized']}"
            if key not in seen_normalized:
                seen_normalized.add(key)
                iocs.append(ioc)

        # --- Headers ---
        headers = parsed_email.get("headers", {})
        from_header = parsed_email.get("from", "") or headers.get("from", "")
        to_header = parsed_email.get("to", "") or headers.get("to", "")
        reply_to = headers.get("reply-to", "")
        return_path = headers.get("return-path", "")

        for header_val, src in [
            (from_header, "header_from"),
            (to_header, "header_to"),
            (reply_to, "header_reply_to"),
            (return_path, "header_return_path"),
        ]:
            if not header_val:
                continue
            for m in _RE_EMAIL.finditer(str(header_val)):
                em = m.group()
                norm = em.lower()
                add(_make_ioc("EMAIL_ADDRESS", em, norm, src, 0.98))
                domain_part = em.split("@")[-1].lower()
                if _is_valid_domain(domain_part):
                    add(_make_ioc("DOMAIN", domain_part, _normalize_domain(domain_part), src, 0.95))

        # --- Body text ---
        body = parsed_email.get("body", "") or ""

        # URLs from body
        for m in _RE_URL.finditer(body):
            raw_url = m.group()
            norm_url = _normalize_url(raw_url)
            add(_make_ioc("URL", raw_url, norm_url, "email_body", 0.95))
            try:
                host = urlparse(raw_url).hostname or ""
                if host and _is_valid_domain(host):
                    add(_make_ioc("DOMAIN", host, _normalize_domain(host), "email_body_url", 0.9))
                elif host and _is_valid_ip(host):
                    add(_make_ioc("IP_ADDRESS", host, _normalize_ip(host), "email_body_url", 0.9))
            except Exception:
                pass

        # Hashes from body
        for m in _RE_SHA256.finditer(body):
            val = m.group().upper()
            add(_make_ioc("HASH_SHA256", m.group(), val, "email_body", 0.85))
        for m in _RE_SHA1.finditer(body):
            val = m.group().upper()
            # Skip if it matches SHA256 already found
            if f"HASH_SHA256:{val}" not in seen_normalized:
                add(_make_ioc("HASH_SHA1", m.group(), val, "email_body", 0.8))
        for m in _RE_MD5.finditer(body):
            val = m.group().upper()
            if f"HASH_SHA256:{val}" not in seen_normalized and f"HASH_SHA1:{val}" not in seen_normalized:
                add(_make_ioc("HASH_MD5", m.group(), val, "email_body", 0.75))

        # Phone numbers from body
        for m in _RE_PHONE.finditer(body):
            ph = re.sub(r'[\s\-\(\)]', '', m.group())
            add(_make_ioc("PHONE_NUMBER", m.group(), ph, "email_body", 0.6))

        # Crypto addresses from body
        for m in _RE_CRYPTO_BTC.finditer(body):
            add(_make_ioc("CRYPTO_ADDRESS", m.group(), m.group(), "email_body", 0.7))
        for m in _RE_CRYPTO_ETH.finditer(body):
            add(_make_ioc("CRYPTO_ADDRESS", m.group(), m.group().lower(), "email_body", 0.7))

        # --- URL Analysis results ---
        url_analysis = existing_analysis.get("url", {})
        for item in url_analysis.get("analysis", []):
            raw_url = item.get("url", "")
            if raw_url:
                norm_url = _normalize_url(raw_url)
                add(_make_ioc("URL", raw_url, norm_url, "url_analysis", 0.99))
            domain = item.get("domain", "")
            if domain and _is_valid_domain(domain):
                add(_make_ioc("DOMAIN", domain, _normalize_domain(domain), "url_analysis", 0.99))
            registered = item.get("registered_domain", "")
            if registered and registered != domain and _is_valid_domain(registered):
                add(_make_ioc("DOMAIN", registered, _normalize_domain(registered), "url_analysis_registered", 0.99))
            # DNS IPs from url_analysis
            dns_data = item.get("dns", {})
            for ip in dns_data.get("a", []):
                if _is_valid_ip(ip):
                    add(_make_ioc("IP_ADDRESS", ip, _normalize_ip(ip), "url_dns", 0.9))

        # --- Attachment Analysis ---
        attachment_analysis = existing_analysis.get("attachment", {})
        # attachments come from parsed_email
        for att in parsed_email.get("attachments", []):
            filename = att.get("filename", "")
            if not filename:
                continue
            add(_make_ioc("ATTACHMENT_NAME", filename, filename.lower(), "attachment", 0.9))
            import os as _os
            _, ext = _os.path.splitext(filename.lower())
            if ext and ext not in _SKIP_EXTENSIONS:
                add(_make_ioc("FILE_EXTENSION", ext, ext, "attachment", 0.7))
            # Hash if available
            for hash_field, hash_type in [("md5", "HASH_MD5"), ("sha1", "HASH_SHA1"), ("sha256", "HASH_SHA256")]:
                hval = att.get(hash_field, "")
                if hval:
                    add(_make_ioc(hash_type, hval, hval.upper(), "attachment_hash", 0.99))

        return iocs
