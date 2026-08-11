import datetime
from ..storage.behavior_store import get_behavior_store
from ..storage.reputation_store import get_reputation_store
from ..storage.campaign_store import get_campaign_store
from .campaign_detector import CampaignDetector

class LocalLearning:
    def __init__(self):
        self.behavior_store = get_behavior_store()
        self.reputation_store = get_reputation_store()
        self.campaign_store = get_campaign_store()
        self.detector = CampaignDetector()

    def learn(self, parsed_email: dict, existing_analysis: dict, final_verdict: str):
        sender_email = parsed_email.get("from", "")
        # extract email
        if "<" in sender_email and ">" in sender_email:
            sender_email = sender_email.split("<")[1].split(">")[0]
            
        sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""
        
        url_analysis = existing_analysis.get("url", {}).get("analysis", [])
        auth_analysis = existing_analysis.get("authentication", {})
        
        # 1. Update Reputation
        rep_profile = self.reputation_store.get_sender_reputation(sender_email)
        if not rep_profile:
            rep_profile = {
                "sender": sender_email,
                "messages_seen": 0,
                "legitimate_count": 0,
                "suspicious_count": 0,
                "phishing_count": 0,
                "reputation": "UNKNOWN"
            }
            
        rep_profile["messages_seen"] += 1
        
        if final_verdict in ["VERIFIED LEGITIMATE", "LIKELY LEGITIMATE", "SAFE"]:
            rep_profile["legitimate_count"] += 1
        elif final_verdict in ["SUSPICIOUS", "UNKNOWN", "LOW RISK"]:
            rep_profile["suspicious_count"] += 1
        elif final_verdict in ["PHISHING", "HIGH RISK"]:
            rep_profile["phishing_count"] += 1
            
        self.reputation_store.update_sender_reputation(sender_email, rep_profile)
        
        # 2. Update Behavior
        beh_profile = self.behavior_store.get_sender_behavior(sender_email)
        if not beh_profile:
            beh_profile = {
                "timestamps": [],
                "url_domains": [],
                "auth_summary": []
            }
            
        beh_profile["timestamps"].append(datetime.datetime.utcnow().timestamp())
        
        for u in url_analysis:
            d = u.get("domain")
            if d and d not in beh_profile["url_domains"]:
                beh_profile["url_domains"].append(d)
                
        auth_str = f"SPF:{auth_analysis.get('spf','none')} DKIM:{auth_analysis.get('dkim','none')} DMARC:{auth_analysis.get('dmarc','none')}"
        if auth_str not in beh_profile["auth_summary"]:
            beh_profile["auth_summary"].append(auth_str)
            
        self.behavior_store.update_sender_behavior(sender_email, beh_profile)
        
        # 3. Update Campaign Store
        subject = parsed_email.get("subject", "")
        norm_sub = self.detector.normalize_subject(subject)
        
        if norm_sub:
            campaigns = self.campaign_store.get_all_campaigns()
            matched_id = None
            for c_id, c_data in campaigns.items():
                if self.detector.token_overlap(norm_sub, c_data.get("normalized_subject", "")) > 0.8:
                    matched_id = c_id
                    break
                    
            if not matched_id:
                matched_id = f"c_{int(datetime.datetime.utcnow().timestamp())}"
                self.campaign_store.update_campaign(matched_id, {
                    "normalized_subject": norm_sub,
                    "sender_domains": [sender_domain] if sender_domain else [],
                    "url_domains": [u.get("domain") for u in url_analysis if u.get("domain")],
                    "messages_seen": 1
                })
            else:
                c_data = self.campaign_store.get_campaign(matched_id)
                if sender_domain and sender_domain not in c_data["sender_domains"]:
                    c_data["sender_domains"].append(sender_domain)
                for u in url_analysis:
                    d = u.get("domain")
                    if d and d not in c_data["url_domains"]:
                        c_data["url_domains"].append(d)
                c_data["messages_seen"] += 1
                self.campaign_store.update_campaign(matched_id, c_data)
