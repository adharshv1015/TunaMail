from fastapi import APIRouter, HTTPException
from pydantic import BaseModel


router = APIRouter()


class FeedbackRequest(BaseModel):
    feedback: str


_feedback_store = {}


@router.post("/gmail/message/{message_id}/feedback")
def submit_feedback(
    message_id: str,
    data: FeedbackRequest,
):
    if not message_id:
        raise HTTPException(
            status_code=400,
            detail="Message ID is required",
        )

    feedback = data.feedback.strip()

    if not feedback:
        raise HTTPException(
            status_code=400,
            detail="Feedback is required",
        )

    _feedback_store[message_id] = feedback

    return {
        "status": "success",
        "message_id": message_id,
        "feedback": feedback,
    }


@router.get("/gmail/message/{message_id}/feedback")
def get_feedback(message_id: str):
    return {
        "status": "success",
        "message_id": message_id,
        "feedback": _feedback_store.get(message_id),
    }


@router.delete("/gmail/message/{message_id}/feedback")
def delete_feedback(message_id: str):
    _feedback_store.pop(message_id, None)

    return {
        "status": "success",
        "message_id": message_id,
    }
