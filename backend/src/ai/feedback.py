from ..storage.feedback_store import get_feedback_store

class FeedbackEngine:
    def __init__(self):
        self.store = get_feedback_store()

    def process_feedback(self, message_id: str, user_label: str, previous_verdict: str):
        self.store.save_feedback(message_id, {
            "user_label": user_label,
            "previous_verdict": previous_verdict
        })
        # Note: Feedback must NOT instantly whitelist a sender. It's just a signal.
