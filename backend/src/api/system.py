from fastapi import APIRouter, Request
from datetime import datetime
from src.config.version import VERSION
from src.api.session import session_manager

router = APIRouter()

@router.get("/health")
def health(request: Request):
    session_id = request.session.get("session_id")
    server_session = session_manager.get_session(session_id)
    is_connected = server_session and server_session.get("authenticated")
    
    return {
        "status": "online",
        "version": VERSION["version"],
        "engine": "ready",
        "gmail": "connected" if is_connected else "disconnected",
        "time": datetime.utcnow().isoformat()
    }

@router.get("/version")
def version():
    return VERSION
