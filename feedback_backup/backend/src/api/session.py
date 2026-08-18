import secrets
import logging

logger = logging.getLogger(__name__)

class SessionManager:
    """
    In-memory session manager.
    
    WARNING: This in-memory implementation is NOT safe for multiple independent 
    backend workers (e.g., Gunicorn with workers > 1). For production scaling 
    with multiple workers, this must be migrated to a shared store such as Redis.
    """
    
    def __init__(self):
        self._sessions = {}

    def _generate_id(self):
        return secrets.token_urlsafe(32)

    def create_session(self, initial_data=None):
        session_id = self._generate_id()
        self._sessions[session_id] = initial_data or {}
        return session_id

    def get_session(self, session_id):
        if not session_id:
            return None
        return self._sessions.get(session_id)

    def update_session(self, session_id, data):
        if session_id in self._sessions:
            self._sessions[session_id].update(data)
            return True
        return False

    def delete_session(self, session_id):
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False

    def rotate_session(self, old_session_id):
        """
        Invalidates the old session ID and returns a new session ID
        containing the same authenticated data. This prevents session fixation.
        """
        if old_session_id not in self._sessions:
            return self.create_session()
            
        data = self._sessions.pop(old_session_id)
        new_session_id = self._generate_id()
        self._sessions[new_session_id] = data
        return new_session_id

# Global instance for development / single-worker production
session_manager = SessionManager()
