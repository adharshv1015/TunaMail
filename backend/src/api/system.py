from fastapi import APIRouter
from datetime import datetime
from src.api.gmail import gmail_sessions
from src.config.version import VERSION

router = APIRouter()

@router.get("/health")
def health():
    return {
        "status": "online",
        "version": VERSION["version"],
        "engine": "ready",
        "gmail": "connected" if "credentials" in gmail_sessions else "disconnected",
        "time": datetime.utcnow().isoformat()
    }

@router.get("/version")
def version():
    return VERSION
