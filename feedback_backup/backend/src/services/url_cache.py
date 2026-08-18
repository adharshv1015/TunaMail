import time
import threading
from typing import Dict, Any, Optional
import os

URL_CACHE_TTL_SECONDS = int(os.environ.get("URL_CACHE_TTL_SECONDS", "3600"))
DNS_CACHE_TTL_SECONDS = int(os.environ.get("DNS_CACHE_TTL_SECONDS", "300"))
TLS_CACHE_TTL_SECONDS = int(os.environ.get("TLS_CACHE_TTL_SECONDS", "3600"))
MAX_CACHE_ENTRIES = 5000

class URLCache:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(URLCache, cls).__new__(cls)
                cls._instance._init_cache()
            return cls._instance

    def _init_cache(self):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.locks: Dict[str, threading.Lock] = {}
        self.lock = threading.RLock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        
    def get_lock(self, key: str) -> threading.Lock:
        with self.lock:
            if key not in self.locks:
                self.locks[key] = threading.Lock()
            return self.locks[key]

    def get(self, key: str, cache_type: str = "full") -> Optional[Any]:
        with self.lock:
            if key not in self.cache:
                self._misses += 1
                return None
                
            entry = self.cache[key]
            
            # Determine TTL based on cache type
            ttl = URL_CACHE_TTL_SECONDS
            if cache_type == "dns":
                ttl = DNS_CACHE_TTL_SECONDS
            elif cache_type == "tls":
                ttl = TLS_CACHE_TTL_SECONDS
                
            # For failures, cache only for a short time (e.g. 60s)
            is_failure = entry.get("is_failure", False)
            if is_failure:
                ttl = 60
                
            if time.time() - entry["timestamp"] > ttl:
                # Expired
                del self.cache[key]
                if key in self.locks:
                    del self.locks[key]
                self._misses += 1
                return None
                
            # Update access time for LRU
            entry["last_accessed"] = time.time()
            self._hits += 1
            return entry["data"]

    def set(self, key: str, data: Any, is_failure: bool = False):
        with self.lock:
            if len(self.cache) >= MAX_CACHE_ENTRIES:
                self._evict_lru()
                
            self.cache[key] = {
                "data": data,
                "timestamp": time.time(),
                "last_accessed": time.time(),
                "is_failure": is_failure
            }

    def _evict_lru(self):
        # Evict 10% of least recently used items
        num_to_evict = max(1, int(MAX_CACHE_ENTRIES * 0.1))
        
        # Sort by last_accessed
        sorted_keys = sorted(
            self.cache.keys(), 
            key=lambda k: self.cache[k]["last_accessed"]
        )
        
        for key in sorted_keys[:num_to_evict]:
            del self.cache[key]
            if key in self.locks:
                del self.locks[key]
            self._evictions += 1

    def invalidate(self, key: str) -> None:
        with self.lock:
            if key in self.cache:
                del self.cache[key]
            if key in self.locks:
                del self.locks[key]

    def clear(self):
        with self.lock:
            self.cache.clear()
            self.locks.clear()

    def statistics(self):
        with self.lock:
            total = self._hits + self._misses
            return {
                "entries": len(self.cache),
                "max_entries": MAX_CACHE_ENTRIES,
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "hit_ratio": round(self._hits / total, 4) if total > 0 else 0.0,
            }
