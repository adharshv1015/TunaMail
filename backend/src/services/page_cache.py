import time
from typing import Dict, Any, Optional
import hashlib
from urllib.parse import urlparse

class PageCache:
    """
    Cache for public sanitized URL intelligence.
    Must not store private user data or credentials.
    """
    def __init__(self, ttl_seconds: int = 3600):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self.ttl_seconds = ttl_seconds

    def _normalize_url(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            # Remove fragments and queries that might be user-specific tracking,
            # though some sites require query params. We'll keep query for now but remove fragment.
            # A strict implementation might strip queries if not careful.
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        except Exception:
            return url

    def _generate_key(self, url: str) -> str:
        normalized = self._normalize_url(url)
        return hashlib.sha256(normalized.encode()).hexdigest()

    def get(self, url: str) -> Optional[Dict[str, Any]]:
        key = self._generate_key(url)
        entry = self._cache.get(key)
        if not entry:
            return None
            
        if time.time() - entry["timestamp"] > self.ttl_seconds:
            del self._cache[key]
            return None
            
        return entry["data"]

    def set(self, url: str, data: Dict[str, Any]) -> None:
        key = self._generate_key(url)
        self._cache[key] = {
            "timestamp": time.time(),
            "data": data
        }

page_cache = PageCache(ttl_seconds=3600)  # 1 hour cache
