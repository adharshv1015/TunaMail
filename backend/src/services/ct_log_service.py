import logging
import time
import requests
import ipaddress
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Domains that are well-known, always established, and generate noisy CT 502s.
# For these, we skip the external lookup entirely and return a synthetic trusted result.
_ALWAYS_TRUSTED_DOMAINS = frozenset({
    # Google infra
    "google.com", "googleapis.com", "fonts.googleapis.com", "gstatic.com",
    "googlesyndication.com", "googletagmanager.com", "googleanalytics.com",
    "doubleclick.net", "googleusercontent.com",
    # CDN / infra
    "cloudflare.com", "cloudfront.net", "fastly.net", "akamaized.net",
    "akamai.net", "edgekey.net", "cdn.jsdelivr.net", "jsdelivr.net",
    "cdnjs.cloudflare.com", "unpkg.com",
    # Microsoft
    "microsoft.com", "microsoftonline.com", "live.com", "outlook.com",
    "office.com", "office365.com", "sharepoint.com",
    # Meta
    "facebook.com", "fbcdn.net", "instagram.com",
    # Major job portals
    "naukri.com", "linkedin.com", "indeed.com", "glassdoor.com",
    "monster.com", "shine.com", "timesjobs.com",
    # Email infra
    "sendgrid.net", "sendgrid.com", "mailgun.org", "mailchimp.com",
    "amazonses.com", "smtp.google.com",
    # Common CDNs / analytics
    "jquery.com", "bootstrapcdn.com", "fontawesome.com",
})

# TLD + root suffix groups that are categorically trusted infra
_TRUSTED_SUFFIXES = (
    ".googleapis.com", ".gstatic.com", ".cloudfront.net",
    ".akamaized.net", ".akamai.net", ".edgekey.net",
    ".naukri.com", ".linkedin.com", ".microsoft.com",
    ".amazonses.com", ".sendgrid.net",
)


class CTLogService:
    """
    Service to query Certificate Transparency (CT) logs via crt.sh.
    Provides intelligent caching, robust timeouts, safe parsing,
    and a skip-list for always-trusted well-known infrastructure domains.
    """

    def __init__(self, cache_ttl_seconds: int = 3600):
        # In-memory cache: domain -> {"data": dict, "timestamp": float}
        self._cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl_seconds = cache_ttl_seconds
        self.timeout = 3.0  # Allow 3s for a proper response

        # Negative cache TTL: suppress repeated lookups for unavailable domains
        self.negative_cache_ttl_seconds = 300  # 5 minutes

    def _normalize_domain(self, domain: str) -> str:
        """Strip www, leading dots, and lower case."""
        d = domain.lower().strip()
        if d.startswith("www."):
            d = d[4:]
        return d.lstrip(".")

    def _is_trusted_infra(self, norm_domain: str) -> bool:
        """Return True if domain is a well-known infra/CDN that doesn't need CT lookup."""
        if norm_domain in _ALWAYS_TRUSTED_DOMAINS:
            return True
        for suffix in _TRUSTED_SUFFIXES:
            if norm_domain.endswith(suffix):
                return True
        return False

    def _normalize_issuer(self, issuer_name: str) -> str:
        """Normalize issuer names (extracts O= or CN= from DN strings)."""
        if not issuer_name:
            return "Unknown"
        parts = issuer_name.split(",")
        org_name = None
        cn_name = None
        for part in parts:
            part = part.strip()
            if part.startswith("O="):
                org_name = part[2:].strip('"')
            elif part.startswith("CN="):
                cn_name = part[3:].strip('"')

        if org_name:
            return org_name
        if cn_name:
            return cn_name
        return issuer_name.strip()

    def _synthetic_trusted_result(self) -> Dict[str, Any]:
        """Return a synthetic result for globally-trusted infra domains."""
        return {
            "available": True,
            "trusted_infra": True,
            "first_seen": None,
            "latest_seen": None,
            "first_seen_days_ago": 3650,  # Treated as 10+ year established domain
            "certificate_count": 999,
            "issuer_count": 5,
            "note": "Well-known infrastructure domain; CT lookup skipped."
        }

    def _build_crtsh_url(self, norm_domain: str) -> str:
        """Build crt.sh query URL. Use wildcard prefix to catch subdomains."""
        return f"https://crt.sh/?q=%25.{norm_domain}&output=json"

    def fetch_ct_logs(
        self,
        domain: str,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Fetch CT logs for a given domain safely.
        Returns a dict with intelligence metrics or an 'unavailable' state.
        """
        # Skip IP addresses
        try:
            ipaddress.ip_address(domain)
            return {"available": False, "reason": "ip_address"}
        except ValueError:
            pass

        norm_domain = self._normalize_domain(domain)
        if not norm_domain or len(norm_domain) < 4:
            return {"available": False, "reason": "invalid_domain"}

        # Always-trusted infra: return synthetic result without any network call
        if self._is_trusted_infra(norm_domain):
            return self._synthetic_trusted_result()

        # Check cache
        now = time.time()
        cached = self._cache.get(norm_domain)
        if cached:
            expires_at = cached.get("expires_at") or (cached.get("timestamp", 0) + self.cache_ttl_seconds)
            if now < expires_at:
                return cached["data"]
            self._cache.pop(norm_domain, None)

        # --- Query crt.sh ---
        url = self._build_crtsh_url(norm_domain)
        req_timeout = min(self.timeout, timeout) if timeout is not None else self.timeout

        try:
            response = requests.get(
                url,
                timeout=req_timeout,
                headers={"Accept": "application/json", "User-Agent": "TunaMail-CTCheck/1.0"},
            )
            response.raise_for_status()
            data = response.json()

        except requests.exceptions.Timeout:
            logger.debug(f"CT Log lookup timed out for {norm_domain} (non-critical)")
            result = {"available": False, "reason": "timeout"}
            self._cache[norm_domain] = {
                "data": result,
                "timestamp": now,
                "expires_at": now + self.negative_cache_ttl_seconds,
            }
            return result

        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else "?"
            # 502/503/504 from crt.sh are transient infra issues — log at debug, not warning
            if status in (502, 503, 504):
                logger.debug(f"CT Log transient {status} for {norm_domain} — using cached/unavailable state")
            else:
                logger.warning(f"CT Log HTTP {status} error for {norm_domain}: {e}")
            result = {"available": False, "reason": f"http_{status}"}
            self._cache[norm_domain] = {
                "data": result,
                "timestamp": now,
                "expires_at": now + self.negative_cache_ttl_seconds,
            }
            return result

        except requests.exceptions.RequestException as e:
            logger.debug(f"CT Log connection error for {norm_domain}: {type(e).__name__}")
            result = {"available": False, "reason": "connection_error"}
            self._cache[norm_domain] = {
                "data": result,
                "timestamp": now,
                "expires_at": now + self.negative_cache_ttl_seconds,
            }
            return result

        except (ValueError, Exception) as e:
            logger.debug(f"CT Log parse error for {norm_domain}: {e}")
            return {"available": False, "reason": "invalid_json"}

        # Parse response
        if not isinstance(data, list):
            return {"available": False, "reason": "invalid_format"}

        if not data:
            result = {
                "available": True,
                "trusted_infra": False,
                "first_seen": None,
                "latest_seen": None,
                "first_seen_days_ago": None,
                "certificate_count": 0,
                "issuer_count": 0,
            }
            self._cache[norm_domain] = {"data": result, "timestamp": now, "expires_at": now + self.cache_ttl_seconds}
            return result

        # Parse and sanitize results
        first_seen_dt = None
        latest_seen_dt = None
        unique_issuers: set = set()
        cert_count = 0

        for entry in data:
            name_value = (entry.get("name_value") or "").lower().strip()
            if not name_value:
                continue

            # Validate the cert covers our domain (wildcard or exact/subdomain)
            if name_value.startswith("*."):
                root = name_value[2:]
                if root != norm_domain and not norm_domain.endswith(f".{root}"):
                    continue
            else:
                if name_value != norm_domain and not name_value.endswith(f".{norm_domain}"):
                    continue

            cert_count += 1
            issuer_raw = entry.get("issuer_name", "")
            if issuer_raw:
                unique_issuers.add(self._normalize_issuer(issuer_raw))

            # Parse issue date
            not_before_str = entry.get("not_before")
            if not_before_str:
                try:
                    dt = datetime.fromisoformat(str(not_before_str))
                    if not first_seen_dt or dt < first_seen_dt:
                        first_seen_dt = dt
                    if not latest_seen_dt or dt > latest_seen_dt:
                        latest_seen_dt = dt
                except Exception:
                    pass

        first_seen_days_ago = None
        if first_seen_dt:
            first_seen_days_ago = (datetime.now() - first_seen_dt).days

        result = {
            "available": True,
            "trusted_infra": False,
            "first_seen": first_seen_dt.isoformat() if first_seen_dt else None,
            "latest_seen": latest_seen_dt.isoformat() if latest_seen_dt else None,
            "first_seen_days_ago": first_seen_days_ago,
            "certificate_count": cert_count,
            "issuer_count": len(unique_issuers),
        }

        self._cache[norm_domain] = {"data": result, "timestamp": now, "expires_at": now + self.cache_ttl_seconds}
        return result


# Singleton instance
ct_log_service = CTLogService()
