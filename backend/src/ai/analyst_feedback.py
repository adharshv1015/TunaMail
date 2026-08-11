import datetime
from src.storage.feedback_store import get_feedback_store
from src.storage.audit_store import get_audit_store
from src.storage.reputation_store import get_reputation_store

def process_analyst_feedback(message_id: str, sender: str, label: str, reason: str, previous_verdict: str, previous_risk_score: int):
    # Store explicit feedback
    feedback_data = {
        "message_id": message_id,
        "analyst_label": label,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "previous_verdict": previous_verdict,
        "previous_risk_score": previous_risk_score,
        "reason": reason
    }
    
    get_feedback_store().save_feedback(message_id, feedback_data)
    
    # Safely modify reputation
    rep_store = get_reputation_store()
    if sender:
        profile = rep_store.get_sender_reputation(sender) or {
            "total_messages": 0,
            "legitimate_count": 0,
            "suspicious_count": 0,
            "phishing_count": 0,
            "reputation": "UNKNOWN",
            "score": 50,
            "first_seen": datetime.datetime.utcnow().isoformat(),
            "last_seen": datetime.datetime.utcnow().isoformat()
        }
        
        if label == "CONFIRMED_PHISHING":
            profile["phishing_count"] += 1
        elif label == "CONFIRMED_SAFE":
            profile["legitimate_count"] += 1
        elif label == "FALSE_POSITIVE":
            profile["legitimate_count"] += 1
        elif label == "FALSE_NEGATIVE":
            profile["phishing_count"] += 1
            
        profile["total_messages"] += 1
        rep_store.update_sender_reputation(sender, profile)
            
    # Audit log
    get_audit_store().log_event(message_id, "ANALYST_FEEDBACK", feedback_data)
    
    return feedback_data

def get_analyst_feedback(message_id: str):
    return get_feedback_store().get_feedback(message_id)

def delete_analyst_feedback(message_id: str):
    get_feedback_store().delete_feedback(message_id)
    get_audit_store().log_event(message_id, "ANALYST_FEEDBACK_DELETED", {"message_id": message_id})
