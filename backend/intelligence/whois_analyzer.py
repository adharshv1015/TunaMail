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
                "expires": None,
                "registrar": None,
                "country": None,
                "age_days": None,
                "age_category": "Unknown",
                "error": None
            }
    
            try:
                data = whois.whois(norm_domain, timeout=2, quiet=True)
                result["available"] = True
    
                creation = data.creation_date
                expiration = data.expiration_date
    
                if isinstance(creation, list):
                    creation = creation[0]
    
                if isinstance(expiration, list):
                    expiration = expiration[0]
    
                result["created"] = (
                    creation.isoformat()
                    if creation else None
                )
    
                result["expires"] = (
                    expiration.isoformat()
                    if expiration else None
                )
    
                result["registrar"] = data.registrar
                result["country"] = getattr(
                    data,
                    "country",
                    None
                )
    
                if creation:
                    if creation.tzinfo is None:
                        creation = creation.replace(
                            tzinfo=timezone.utc
                        )
    
                    result["age_days"] = (
                        datetime.now(timezone.utc) - creation
                    ).days
    
                    age_days = result["age_days"]
    
                    if age_days >= 3650:
                        result["age_category"] = "very_old"
                    elif age_days >= 1095:
                        result["age_category"] = "established"
                    elif age_days >= 365:
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