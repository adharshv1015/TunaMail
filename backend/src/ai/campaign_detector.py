import re
import datetime
from ..storage.campaign_store import get_campaign_store
from .evidence_model import EvidenceItem, EvidenceDirection

class CampaignDetector:
    def __init__(self):
        self.store = get_campaign_store()

    def normalize_subject(self, subject: str) -> str:
        s = subject.lower()
        # Remove standard prefixes
        s = re.sub(r'^(re|fw|fwd|reply):\s*', '', s)
        # Remove common IDs
        s = re.sub(r'#\d+', '', s)
        s = re.sub(r'\b\d{4,}\b', '', s)
        return s.strip()

    def token_overlap(self, text1: str, text2: str) -> float:
        set1 = set(text1.split())
        set2 = set(text2.split())
        if not set1 or not set2:
            return 0.0
        return len(set1.intersection(set2)) / len(set1.union(set2))

    def detect(self, parsed_email: dict, url_domains: list) -> list:
        evidence = []
        subject = parsed_email.get("subject", "")
        norm_sub = self.normalize_subject(subject)
        
        campaigns = self.store.get_all_campaigns()
        
        best_match = None
        best_sim = 0.0
        
        for c_id, c_data in campaigns.items():
            hist_sub = c_data.get("normalized_subject", "")
            sim = self.token_overlap(norm_sub, hist_sub)
            if sim > best_sim:
                best_sim = sim
                best_match = c_data
                
        if best_sim > 0.8 and best_match:
            # Check if it matches sender or URL
            sender_domain = parsed_email.get("from", "").split("@")[-1].replace(">", "").strip()
            
            shared_indicators = []
            if norm_sub: shared_indicators.append("subject_similarity")
            
            same_infra = False
            if sender_domain in best_match.get("sender_domains", []):
                same_infra = True
                shared_indicators.append("sender_domain")
                
            for ud in url_domains:
                if ud in best_match.get("url_domains", []):
                    same_infra = True
                    shared_indicators.append("url_domain")
                    
            if not same_infra and best_sim > 0.9:
                evidence.append(EvidenceItem(
                    category="behavior",
                    type="CAMPAIGN_ANOMALY",
                    severity="HIGH",
                    confidence=80,
                    direction=EvidenceDirection.NEGATIVE,
                    source="campaign_detector",
                    value={"similarity": best_sim, "shared_indicators": shared_indicators},
                    explanation="Email matches a known campaign structural pattern but uses different infrastructure."
                ))
            else:
                evidence.append(EvidenceItem(
                    category="behavior",
                    type="CAMPAIGN_MATCH",
                    severity="MEDIUM",
                    confidence=75,
                    direction=EvidenceDirection.NEUTRAL,
                    source="campaign_detector",
                    value={"similarity": best_sim, "shared_indicators": shared_indicators},
                    explanation=f"Email belongs to an observed campaign with {int(best_sim*100)}% similarity."
                ))
                
        return evidence
