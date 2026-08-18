"""
Entity Extractor for TunaMail Stage 5.

Extracts structured named entities from parsed email and existing analysis.
Reuses existing analysis outputs — does not re-analyze.
"""

import re
import tldextract
from email.utils import parseaddr
from typing import Dict, Any


class EntityExtractor:
    """
    Extracts structured entities from a parsed email and its analysis results.
    """

    def extract(self, parsed_email: dict, existing_analysis: dict = None) -> Dict[str, Any]:
        """
        Returns a dict of named entities for the email.

        Args:
            parsed_email: GmailParser output
            existing_analysis: Full pipeline analysis output
        """
        if existing_analysis is None:
            existing_analysis = {}

        headers = parsed_email.get("headers", {})

        # ---- Sender / Recipient ----
        raw_from = parsed_email.get("from", "") or headers.get("from", "") or ""
        raw_to = parsed_email.get("to", "") or headers.get("to", "") or ""
        raw_reply_to = headers.get("reply-to", "") or ""
        raw_return_path = headers.get("return-path", "") or ""

        sender = self._parse_email_addr(raw_from)
        recipient = self._parse_email_addr(raw_to)
        reply_to = self._parse_email_addr(raw_reply_to)
        return_path_addr = self._parse_email_addr(raw_return_path)

        sender_domain = self._domain_from_email(sender)
        return_path_domain = self._domain_from_email(return_path_addr)

        # ---- URL domains ----
        url_analysis = existing_analysis.get("url", {})
        url_domains = []
        registered_domains = []
        ips = []
        redirect_domains = []

        for item in url_analysis.get("analysis", []):
            domain = item.get("domain", "")
            if domain and domain not in url_domains:
                url_domains.append(domain)

            reg_domain = item.get("registered_domain", "")
            if reg_domain and reg_domain not in registered_domains:
                registered_domains.append(reg_domain)

            dns_data = item.get("dns", {})
            for ip in dns_data.get("a", []):
                if ip and ip not in ips:
                    ips.append(ip)

            redirects = item.get("redirects", {})
            for r_url in redirects.get("chain", []):
                try:
                    from urllib.parse import urlparse
                    h = urlparse(r_url).hostname or ""
                    if h and h not in redirect_domains:
                        redirect_domains.append(h)
                except Exception:
                    pass

        # ---- Attachments / Hashes ----
        attachments = parsed_email.get("attachments", [])
        attachment_names = [a.get("filename", "") for a in attachments if a.get("filename")]
        hashes = []
        for a in attachments:
            for hf in ["md5", "sha1", "sha256"]:
                hv = a.get(hf, "")
                if hv and hv not in hashes:
                    hashes.append(hv)

        # ---- Brands (from url_analysis brand_relationship) ----
        brands = []
        for item in url_analysis.get("analysis", []):
            br = item.get("brand_relationship", "")
            domain = item.get("domain", "")
            if br in ["OFFICIAL", "SUBDOMAIN_OF_OFFICIAL"] and domain:
                brand_name = self._brand_from_domain(domain)
                if brand_name and brand_name not in brands:
                    brands.append(brand_name)
            elif br in ["IMPERSONATION", "LOOKALIKE"] and domain:
                brand_name = self._brand_from_domain(domain)
                if brand_name and f"(impersonated) {brand_name}" not in brands:
                    brands.append(f"(impersonated) {brand_name}")

        # ---- Auth info ----
        auth = existing_analysis.get("authentication", {})

        return {
            "sender": sender,
            "recipient": recipient,
            "reply_to": reply_to,
            "return_path_addr": return_path_addr,
            "sender_domain": sender_domain,
            "return_path_domain": return_path_domain,
            "url_domains": url_domains,
            "registered_domains": registered_domains,
            "redirect_domains": redirect_domains,
            "ips": ips,
            "brands": brands,
            "attachment_names": attachment_names,
            "hashes": hashes,
            "auth": {
                "spf": auth.get("spf", "unknown"),
                "dkim": auth.get("dkim", "unknown"),
                "dmarc": auth.get("dmarc", "unknown"),
            }
        }

    def _parse_email_addr(self, raw: str) -> str:
        """Extract the email address from a raw header value."""
        if not raw:
            return ""
        _, addr = parseaddr(raw)
        return addr.lower().strip() if addr else raw.strip().lower()

    def _domain_from_email(self, email_addr: str) -> str:
        """Extract domain from an email address."""
        if not email_addr or "@" not in email_addr:
            return ""
        return email_addr.split("@")[-1].lower().strip()

    def _brand_from_domain(self, domain: str) -> str:
        """Extract a human-readable brand name from a domain."""
        try:
            ext = tldextract.extract(domain)
            name = ext.domain
            return name.capitalize() if name else ""
        except Exception:
            return domain.split(".")[0].capitalize()
