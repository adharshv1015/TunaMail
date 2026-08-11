import datetime
from .local_store import LocalJSONStore

class AuditStore:
    def __init__(self):
        self.store = LocalJSONStore("audit.json")

    def log_event(self, message_id: str, event_type: str, details: dict):
        logs = self.store.get(message_id, [])
            
        logs.append({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "event": event_type,
            "details": details
        })
        
        self.store.set(message_id, logs)

    def get_events(self, message_id: str) -> list:
        return self.store.get(message_id, [])

_audit_store = AuditStore()

def get_audit_store() -> AuditStore:
    return _audit_store
