from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from src.connectors.google_auth import GoogleAuth
from api.gmail import gmail_sessions

router = APIRouter()

google_auth = GoogleAuth()

# Temporary in-memory state
oauth_states = {}


@router.get("/login")
def login():

    auth_url, state = google_auth.authorization_url()

    oauth_states[state] = True

    return RedirectResponse(auth_url)


@router.get("/callback")
def callback(request: Request):

    state = request.query_params.get("state")
    code = request.query_params.get("code")

    credentials = google_auth.fetch_credentials(
        authorization_response=str(request.url)
    )

    # store temporary session
    gmail_sessions["credentials"] = credentials

    return {
        "status": "login_success",
        "message": "Gmail connected successfully"
    }