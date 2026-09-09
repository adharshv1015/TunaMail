from whois.exceptions import UnknownTldError
from datetime import datetime, timezone
import tldextract
import whois
from src.services.whois_cache import WhoisCache


class WhoisAnalyzer:
    def __init__(self):
        self.cache = WhoisCache()

    def analyze(self, domain):
        if not domain:
            return {}

        # Normalize domain
        ext = tldextract.extract(domain)
        if ext.registered_domain:
            norm_domain = ext.registered_domain.lower()
        else:
            norm_domain = domain.lower()
            
        cache_key = norm_domain
        
        lock = self.cache.get_lock(cache_key)
        with lock:
            cached_result = self.cache.get(cache_key)
            if cached_result:
                result = dict(cached_result)
                # Keep original domain for display
                result["domain"] = domain
                return result

            result = {
                "domain": domain,
                "normalized_domain": norm_domain,
                "available": False,
                "created": None,
                "creation_date": None,
                "expires": None,
                "expiration_date": None,
                "registrar": None,
                "country": None,
                "age_days": None,
                "domain_age_days": None,
                "age_category": "Unknown",
                "error": None
            }
    
            try:
                data = whois.whois(norm_domain, timeout=5, quiet=True)
                result["available"] = True
    
                creation = data.creation_date
                expiration = data.expiration_date
    
                if isinstance(creation, list) and len(creation) > 0:
                    creation = creation[0]
    
                if isinstance(expiration, list) and len(expiration) > 0:
                    expiration = expiration[0]

                created_iso = None
                if creation:
                    if hasattr(creation, "isoformat"):
                        created_iso = creation.isoformat()
                    else:
                        created_iso = str(creation)

                expires_iso = None
                if expiration:
                    if hasattr(expiration, "isoformat"):
                        expires_iso = expiration.isoformat()
                    else:
                        expires_iso = str(expiration)
    
                result["created"] = created_iso
                result["creation_date"] = created_iso
                result["expires"] = expires_iso
                result["expiration_date"] = expires_iso
    
                result["registrar"] = data.registrar
                result["country"] = getattr(
                    data,
                    "country",
                    None
                )
    
                if creation:
                    try:
                        if hasattr(creation, "tzinfo") and creation.tzinfo is None:
                            creation = creation.replace(
                                tzinfo=timezone.utc
                            )
                        if hasattr(creation, "timestamp"):
                            diff_days = (datetime.now(timezone.utc) - creation).days
                            result["age_days"] = diff_days
                            result["domain_age_days"] = diff_days
                    except Exception:
                        pass
    
                    age_days = result.get("age_days")
                    if age_days is not None:
                        if age_days >= 3650:
                            result["age_category"] = "very_old"
                        elif age_days >= 365:
                            result["age_category"] = "established"
                        elif age_days >= 90:
                            result["age_category"] = "recent"
                        elif age_days >= 0:
                            result["age_category"] = "new"
                        
                self.cache.set(cache_key, result, is_failure=False)
    
            except Exception as e:
                error_str = str(e).strip().split('\n')[0]
                words = error_str.split()
                
                if len(words) > 10:
                    result["error"] = " ".join(words[:10]) + "..."
                else:
                    result["error"] = error_str
                    
                self.cache.set(cache_key, result, is_failure=True)
    
            return result