import logging
import time
import requests
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class CTLogService:
    """
    Service to query Certificate Transparency (CT) logs via crt.sh.
    Provides intelligent caching, robust timeouts, and safe parsing.
    """
    
    def __init__(self, cache_ttl_seconds: int = 3600):
        # In-memory cache: domain -> {"data": dict, "timestamp": float}
        self._cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl_seconds = cache_ttl_seconds
        self.timeout = 3.0  # Strict 3-second timeout

    def _normalize_domain(self, domain: str) -> str:
        """Strip www, leading dots, and lower case."""
        d = domain.lower().strip()
        if d.startswith("www."):
            d = d[4:]
        return d.lstrip(".")

    def _normalize_issuer(self, issuer_name: str) -> str:
        """
        Normalize issuer names to prevent artificial count inflation.
        e.g., 'C=US, O=Let's Encrypt, CN=R3' -> 'Let's Encrypt' or similar.
        """
        if not issuer_name:
            return "Unknown"
        # Simplistic normalization: Extract O=... or CN=... if it's a DN string
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

    def fetch_ct_logs(self, domain: str) -> Dict[str, Any]:
        """
        Fetch CT logs for a given domain safely.
        Returns a dict with intelligence metrics or an 'unavailable' state.
        """
        # Skip IP addresses (basic check)
        import ipaddress
        try:
            ipaddress.ip_address(domain)
            return {"available": False, "reason": "ip_address"}
        except ValueError:
            pass

        norm_domain = self._normalize_domain(domain)
        if not norm_domain:
            return {"available": False, "reason": "invalid_domain"}

        # Check Cache
        now = time.time()
        cached = self._cache.get(norm_domain)
        if cached and (now - cached["timestamp"] < self.cache_ttl_seconds):
            return cached["data"]

        # Proceed to query crt.sh
        url = f"https://crt.sh/?q={norm_domain}&output=json"
        
        try:
            # Use requests with strict timeout
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.Timeout:
            logger.warning(f"CT Log lookup timed out for {norm_domain}")
            return {"available": False, "reason": "timeout"}
        except requests.exceptions.RequestException as e:
            logger.warning(f"CT Log HTTP error for {norm_domain}: {e}")
            return {"available": False, "reason": "http_error"}
        except ValueError:
            logger.warning(f"CT Log invalid JSON for {norm_domain}")
            return {"available": False, "reason": "invalid_json"}

        # crt.sh returns a list of certificate objects
        if not isinstance(data, list):
            logger.warning(f"CT Log unexpected format for {norm_domain}")
            return {"available": False, "reason": "invalid_format"}

        if not data:
            result = {
                "available": True,
                "first_seen": None,
                "latest_seen": None,
                "first_seen_days_ago": None,
                "certificate_count": 0,
                "issuer_count": 0
            }
            self._cache[norm_domain] = {"data": result, "timestamp": now}
            return result

        # Parse and sanitize results
        first_seen_dt = None
        latest_seen_dt = None
        unique_issuers = set()
        cert_count = 0

        for entry in data:
            # Verify the cert name actually relates to our domain to avoid wildcard overreach
            name_value = entry.get("name_value", "").lower()
            if not name_value:
                continue
                
            # If it's a wildcard, ensure the root domain matches
            if name_value.startswith("*."):
                if not name_value.endswith(f".{norm_domain}") and name_value != f"*.{norm_domain}":
                    continue
            else:
                # Must be exact match or a proper subdomain
                if name_value != norm_domain and not name_value.endswith(f".{norm_domain}"):
                    continue

            cert_count += 1
            issuer_raw = entry.get("issuer_name", "")
            if issuer_raw:
                unique_issuers.add(self._normalize_issuer(issuer_raw))

            # Parse dates
            not_before_str = entry.get("not_before")
            if not_before_str:
                try:
                    # crt.sh date format: "2024-05-20T00:00:00"
                    dt = datetime.fromisoformat(not_before_str)
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
            "first_seen": first_seen_dt.isoformat() if first_seen_dt else None,
            "latest_seen": latest_seen_dt.isoformat() if latest_seen_dt else None,
            "first_seen_days_ago": first_seen_days_ago,
            "certificate_count": cert_count,
            "issuer_count": len(unique_issuers)
        }

        self._cache[norm_domain] = {"data": result, "timestamp": now}
        return result

# Singleton instance
ct_log_service = CTLogService()
