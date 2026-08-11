from ..storage.reputation_store import get_reputation_store

class SenderReputation:
    def __init__(self):
        self.store = get_reputation_store()

    def get_profile(self, sender_email: str) -> dict:
        profile = self.store.get_sender_reputation(sender_email)
        if not profile:
            profile = {
                "sender": sender_email,
                "messages_seen": 0,
                "legitimate_count": 0,
                "suspicious_count": 0,
                "phishing_count": 0,
                "reputation": "UNKNOWN"
            }
        
        # Calculate reputation based on current stats
        if profile["messages_seen"] == 0:
            profile["reputation"] = "UNKNOWN"
        elif profile["messages_seen"] < 3:
            profile["reputation"] = "NEW"
        else:
            if profile["phishing_count"] >= 2 or (profile["phishing_count"] > 0 and profile["messages_seen"] < 5):
                profile["reputation"] = "HIGH_RISK"
            elif profile["suspicious_count"] > profile["legitimate_count"] or profile["suspicious_count"] >= 3:
                profile["reputation"] = "SUSPICIOUS"
            elif profile["legitimate_count"] >= 10 and profile["suspicious_count"] == 0 and profile["phishing_count"] == 0:
                profile["reputation"] = "TRUSTED"
            elif profile["legitimate_count"] > profile["suspicious_count"]:
                profile["reputation"] = "ESTABLISHED"
            else:
                profile["reputation"] = "UNKNOWN"
                
        return profile
