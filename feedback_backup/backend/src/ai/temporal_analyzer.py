import datetime
from ..storage.behavior_store import get_behavior_store
from .evidence_model import EvidenceItem, EvidenceDirection

class TemporalAnalyzer:
    def __init__(self):
        self.store = get_behavior_store()

    def analyze(self, sender_email: str) -> list:
        evidence = []
        history = self.store.get_sender_behavior(sender_email)
        timestamps = history.get("timestamps", [])
        
        if not timestamps:
            return evidence
            
        # Check bursts in the last 10 minutes
        now = datetime.datetime.utcnow().timestamp()
        recent = [ts for ts in timestamps if now - ts < 600]
        
        if len(recent) > 10:
            evidence.append(EvidenceItem(
                category="behavior",
                type="ANOMALOUS_SENDING_BURST",
                severity="MEDIUM",
                confidence=70,
                direction=EvidenceDirection.NEGATIVE,
                source="temporal_analyzer",
                value={"recent_count": len(recent), "window": "10m"},
                explanation=f"Anomalous sending burst: {len(recent)} messages received in the last 10 minutes."
            ))
            
        return evidence
