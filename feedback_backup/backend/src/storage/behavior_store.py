from .local_store import LocalJSONStore

class BehaviorStore:
    def __init__(self):
        self.store = LocalJSONStore("behavior.json")

    def get_sender_behavior(self, sender_email: str):
        return self.store.get(sender_email, {})

    def update_sender_behavior(self, sender_email: str, behavior_data: dict):
        self.store.set(sender_email, behavior_data)

_behavior_store = None
def get_behavior_store() -> BehaviorStore:
    global _behavior_store
    if _behavior_store is None:
        _behavior_store = BehaviorStore()
    return _behavior_store
