import time
import threading
from typing import Dict, Any, Optional
import hashlib
import json
import os

AI_CACHE_TTL_SECONDS = int(os.environ.get("AI_CACHE_TTL_SECONDS", "86400"))
MAX_CACHE_ENTRIES = 2000

class InferenceCache:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(InferenceCache, cls).__new__(cls)
                cls._instance._init_cache()
            return cls._instance

    def _init_cache(self):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.locks: Dict[str, threading.Lock] = {}
        self.lock = threading.RLock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        
    def _generate_fingerprint(self, parsed_email: dict, existing_analysis: dict) -> str:
        # Create a deterministic fingerprint using safe fields only
        # We don't include the raw body to save memory/prevent leaks,
        # but we include enough metadata that if it changes, the hash changes.
        
        sender = parsed_email.get("from", "")
        subject = parsed_email.get("subject", "")
        
        # Hash of the body
        body = parsed_email.get("body", "")
        body_hash = hashlib.sha256(body.encode('utf-8')).hexdigest() if body else ""
        
        auth_spf = existing_analysis.get("authentication", {}).get("spf", "")
        auth_dkim = existing_analysis.get("authentication", {}).get("dkim", "")
        
        urls = []
        for u in existing_analysis.get("url", {}).get("analysis", []):
            urls.append(u.get("domain", ""))
        urls_str = ",".join(sorted(urls))
        
        attachments = []
        for a in existing_analysis.get("attachment", {}).get("analysis", []):
            attachments.append(a.get("filename", ""))
        attachments_str = ",".join(sorted(attachments))
        
        fingerprint_data = {
            "sender": sender,
            "subject": subject,
            "body_hash": body_hash,
            "auth": f"{auth_spf}-{auth_dkim}",
            "urls": urls_str,
            "attachments": attachments_str
        }
        
        # Sort keys to guarantee deterministic json output
        json_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(json_str.encode('utf-8')).hexdigest()

    def get_lock(self, parsed_email: dict, existing_analysis: dict) -> tuple[str, threading.Lock]:
        key = self._generate_fingerprint(parsed_email, existing_analysis)
        with self.lock:
            if key not in self.locks:
                self.locks[key] = threading.Lock()
            return key, self.locks[key]

    def get(self, key: str) -> Optional[Any]:
        with self.lock:
            if key not in self.cache:
                self._misses += 1
                return None
                
            entry = self.cache[key]
                
            if time.time() - entry["timestamp"] > AI_CACHE_TTL_SECONDS:
                del self.cache[key]
                if key in self.locks:
                    del self.locks[key]
                self._misses += 1
                return None
                
            entry["last_accessed"] = time.time()
            self._hits += 1
            return entry["data"]

    def set(self, key: str, data: Any):
        with self.lock:
            if len(self.cache) >= MAX_CACHE_ENTRIES:
                self._evict_lru()
                
            self.cache[key] = {
                "data": data,
                "timestamp": time.time(),
                "last_accessed": time.time()
            }

    def _evict_lru(self):
        num_to_evict = max(1, int(MAX_CACHE_ENTRIES * 0.1))
        
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

    def clear(self) -> None:
        with self.lock:
            self.cache.clear()
            self.locks.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0

    def statistics(self) -> dict:
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
