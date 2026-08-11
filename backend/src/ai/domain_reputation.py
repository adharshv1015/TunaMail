from ..storage.reputation_store import get_reputation_store

class DomainReputation:
    def __init__(self):
        self.store = get_reputation_store()

    def get_profile(self, domain: str) -> dict:
        profile = self.store.get_domain_reputation(domain)
        if not profile:
            profile = {
                "domain": domain,
                "message_count": 0,
                "legitimate_count": 0,
                "suspicious_count": 0,
                "phishing_count": 0,
                "brand_matches": 0,
                "brand_mismatches": 0
            }
        return profile
