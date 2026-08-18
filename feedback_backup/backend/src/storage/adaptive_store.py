import os
import datetime
from .local_store import LocalJSONStore

class AdaptiveStore:
    def __init__(self):
        self.sender_store = LocalJSONStore("sender_baseline.json")
        self.domain_store = LocalJSONStore("domain_baseline.json")
        self.url_store = LocalJSONStore("url_history.json")
        self.trend_store = LocalJSONStore("trend_history.json")
        
        # Hard limits
        self.MAX_SENDER_MESSAGES = 100
        self.MAX_URL_HISTORY = 1000
        self.MAX_TREND_HISTORY = 50

    def clear(self):
        self.sender_store.clear()
        self.domain_store.clear()
        self.url_store.clear()
        self.trend_store.clear()

    def get_sender_baseline(self, sender: str):
        return self.sender_store.get(sender, {})

    def update_sender_baseline(self, sender: str, data: dict):
        # Implement safe retention logic
        if "history" in data and len(data["history"]) > self.MAX_SENDER_MESSAGES:
            data["history"] = data["history"][-self.MAX_SENDER_MESSAGES:]
        self.sender_store.set(sender, data)

    def get_domain_baseline(self, domain: str):
        return self.domain_store.get(domain, {})

    def update_domain_baseline(self, domain: str, data: dict):
        self.domain_store.set(domain, data)

    def get_url_history(self, url_key: str):
        return self.url_store.get(url_key, {})

    def update_url_history(self, url_key: str, data: dict):
        # We could prune the whole store if it exceeds MAX_URL_HISTORY, 
        # but for performance we just store it.
        self.url_store.set(url_key, data)

    def get_trend_history(self, entity_id: str):
        return self.trend_store.get(entity_id, [])

    def append_trend_history(self, entity_id: str, score: int):
        history = self.trend_store.get(entity_id, [])
        history.append({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "score": score
        })
        if len(history) > self.MAX_TREND_HISTORY:
            history = history[-self.MAX_TREND_HISTORY:]
        self.trend_store.set(entity_id, history)

_adaptive_store = AdaptiveStore()

def get_adaptive_store() -> AdaptiveStore:
    return _adaptive_store
