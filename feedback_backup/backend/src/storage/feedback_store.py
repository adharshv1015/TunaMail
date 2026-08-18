from .local_store import LocalJSONStore

class FeedbackStore:
    def __init__(self):
        self.store = LocalJSONStore("feedback.json")
        
    def get_all_feedback(self):
        return self.store.get_all()

    def get_feedback(self, message_id: str):
        return self.store.get(message_id, None)

    def save_feedback(self, message_id: str, feedback_data: dict):
        self.store.set(message_id, feedback_data)

    def delete_feedback(self, message_id: str):
        self.store.delete(message_id)

_feedback_store = None
def get_feedback_store() -> FeedbackStore:
    global _feedback_store
    if _feedback_store is None:
        _feedback_store = FeedbackStore()
    return _feedback_store
