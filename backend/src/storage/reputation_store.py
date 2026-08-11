from .local_store import LocalJSONStore

class ReputationStore:
    def __init__(self):
        self.store = LocalJSONStore("reputation.json")
        self.domain_store = LocalJSONStore("domain_reputation.json")

    def get_sender_reputation(self, sender_email: str):
        return self.store.get(sender_email, None)

    def update_sender_reputation(self, sender_email: str, profile: dict):
        self.store.set(sender_email, profile)

    def get_domain_reputation(self, domain: str):
        return self.domain_store.get(domain, None)

    def update_domain_reputation(self, domain: str, profile: dict):
        self.domain_store.set(domain, profile)

_reputation_store = None
def get_reputation_store() -> ReputationStore:
    global _reputation_store
    if _reputation_store is None:
        _reputation_store = ReputationStore()
    return _reputation_store
