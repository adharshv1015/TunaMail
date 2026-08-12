from typing import List, Dict, Any, Tuple
from .evidence_model import EvidenceItem, EvidenceDirection, EvidenceCategory

class ConfidenceCalibrator:
    def __init__(self):
        pass

    def calibrate(self, evidence_items: List[EvidenceItem], graph: Dict[str, Any], initial_risk: int, reputation_profile: dict = None) -> Tuple[int, str]:
        """
        Calibrates the confidence score based on the collected evidence and relationship graph.
        Returns (confidence_score, reasoning_state)
        """
        reputation = reputation_profile.get("reputation", "UNKNOWN") if reputation_profile else "UNKNOWN"
        positive_count = sum(1 for e in evidence_items if e.direction == EvidenceDirection.POSITIVE)
        negative_count = sum(1 for e in evidence_items if e.direction == EvidenceDirection.NEGATIVE)
        
        has_contradiction = any(r["type"] in ["AUTHENTICATION_CONTRADICTS", "CONTENT_CONTRADICTS_URL", "BRAND_DOMAIN_MISMATCH"] for r in graph["relationships"])
        has_insufficient_context = any(e.type == "insufficient_context" for e in evidence_items)
        malicious_count = sum(1 for e in evidence_items if e.direction == EvidenceDirection.NEGATIVE and e.type != "insufficient_context")
        
        # Start with a base confidence of 50
        confidence = 50
        reasoning_state = "SUFFICIENT_EVIDENCE"

        # Historical Evidence influence
        if reputation in ["TRUSTED", "ESTABLISHED"]:
            if malicious_count == 0:
                confidence = min(100, confidence + 20)
            else:
                reasoning_state = "TRUST_HISTORY_CONFLICT"
                confidence = max(10, confidence - 20)
        elif reputation in ["SUSPICIOUS", "HIGH_RISK"]:
            if negative_count > 0:
                confidence = min(100, confidence + 20)
        elif reputation == "NEW":
            confidence = max(10, confidence - 20)
        elif reputation == "UNKNOWN":
            confidence = max(10, confidence - 30)

        if has_insufficient_context:
            confidence = min(confidence, 40) # Allow trust to keep it at 40
            if reputation in ["NEW", "UNKNOWN"]:
                confidence = min(confidence, 30)
            reasoning_state = "INSUFFICIENT_EVIDENCE" if reasoning_state != "TRUST_HISTORY_CONFLICT" else "TRUST_HISTORY_CONFLICT"
            return confidence, reasoning_state

        if has_contradiction:
            confidence = max(10, confidence - 30)
            reasoning_state = "CONFLICTING_EVIDENCE"
            
            # If we have massive negative evidence, the confidence in the *maliciousness* can still be high
            if negative_count >= 4:
                confidence = min(85, confidence + 40)
            return confidence, reasoning_state

        # Strong agreement rules
        if positive_count >= 4 and negative_count == 0:
            confidence = min(100, confidence + (positive_count * 10))
        elif negative_count >= 4 and positive_count == 0:
            confidence = min(100, confidence + (negative_count * 10))
        else:
            # Mixed but non-contradictory (or just sparse evidence)
            total_strong_signals = positive_count + negative_count
            if total_strong_signals <= 1:
                confidence = 30
                reasoning_state = "LIMITED_CONTEXT"
            elif total_strong_signals >= 3:
                confidence = min(90, confidence + 20)

        if reputation in ["SUSPICIOUS", "HIGH_RISK"] and negative_count > 0:
            reasoning_state = "SUSPICIOUS_HISTORY"
        elif reputation == "NEW":
            reasoning_state = "NEW_SENDER"
        elif reputation == "UNKNOWN":
            reasoning_state = "UNKNOWN_SENDER"

        return confidence, reasoning_state
