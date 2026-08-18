import uuid
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

class URLInspectionJob(BaseModel):
    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    message_id: str
    url: str
    status: str = "QUEUED" # QUEUED, RUNNING, COMPLETED, TIMEOUT, BLOCKED, FAILED
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    user_id: str  # For multi-user isolation (from session)

class InspectionQueue:
    """
    Abstract interface for the URL inspection queue.
    Future implementations can use Redis/Celery without changing the core logic.
    """
    def enqueue(self, job: URLInspectionJob) -> str:
        raise NotImplementedError

    def get_job(self, job_id: str) -> Optional[URLInspectionJob]:
        raise NotImplementedError

    def update_job(self, job_id: str, status: str, result: Optional[Dict[str, Any]] = None, error: Optional[str] = None) -> None:
        raise NotImplementedError

    def dequeue(self) -> Optional[URLInspectionJob]:
        """For the worker to pick up jobs."""
        raise NotImplementedError

class LocalInspectionQueue(InspectionQueue):
    """
    In-memory implementation of the InspectionQueue for local deployments.
    """
    def __init__(self):
        self._jobs: Dict[str, URLInspectionJob] = {}
        self._queue = []

    def enqueue(self, job: URLInspectionJob) -> str:
        self._jobs[job.job_id] = job
        self._queue.append(job.job_id)
        return job.job_id

    def get_job(self, job_id: str) -> Optional[URLInspectionJob]:
        return self._jobs.get(job_id)

    def update_job(self, job_id: str, status: str, result: Optional[Dict[str, Any]] = None, error: Optional[str] = None) -> None:
        job = self._jobs.get(job_id)
        if not job:
            return
        
        job.status = status
        if status == "RUNNING" and not job.started_at:
            job.started_at = datetime.now(timezone.utc)
        elif status in ["COMPLETED", "TIMEOUT", "BLOCKED", "FAILED"]:
            job.completed_at = datetime.now(timezone.utc)
            
        if result is not None:
            job.result = result
        if error is not None:
            job.error = error

    def dequeue(self) -> Optional[URLInspectionJob]:
        if not self._queue:
            return None
        job_id = self._queue.pop(0)
        return self._jobs.get(job_id)

# Global local queue instance for now
url_queue = LocalInspectionQueue()
