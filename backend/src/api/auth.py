from fastapi import APIRouter, Request, HTTPException, Response
from fastapi.responses import RedirectResponse
import secrets

from src.connectors.google_auth import GoogleAuth
from src.api.session import session_manager

router = APIRouter()
google_auth = GoogleAuth()

@router.get("/login")
def login(request: Request):
    # Generate cryptographically secure state
    state = secrets.token_urlsafe(32)
    
    # Generate OAuth URL and get PKCE code verifier
    auth_url, _, code_verifier = google_auth.authorization_url(state=state)
    
    # Store state and verifier in a new server-side session
    session_id = session_manager.create_session({
        "oauth_state": state,
        "code_verifier": code_verifier
    })
    
    # Attach session to browser cookie (also backup state and verifier in signed cookie across reloads)
    request.session["session_id"] = session_id
    request.session["oauth_state"] = state
    request.session["code_verifier"] = code_verifier

    return RedirectResponse(auth_url)


@router.get("/callback")
def callback(request: Request):
    returned_state = request.query_params.get("state")
    session_id = request.session.get("session_id")
    
    # Retrieve server-side session
    server_session = session_manager.get_session(session_id) if session_id else None
    
    # Recover state and PKCE verifier (from server session or signed session cookie across reloads)
    expected_state = (server_session.get("oauth_state") if server_session else None) or request.session.get("oauth_state")
    code_verifier = (server_session.get("code_verifier") if server_session else None) or request.session.get("code_verifier")
    
    if not expected_state or not code_verifier:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
        
    if not server_session:
        session_id = session_manager.create_session({
            "oauth_state": expected_state,
            "code_verifier": code_verifier
        })
        request.session["session_id"] = session_id
        
    # Constant-time comparison to mitigate timing attacks
    if not returned_state or not secrets.compare_digest(expected_state, returned_state):
        raise HTTPException(status_code=401, detail="Invalid state parameter")

    # Exchange code for credentials using the PKCE verifier
    try:
        credentials = google_auth.fetch_credentials(
            authorization_response=str(request.url),
            state=returned_state,
            code_verifier=code_verifier
        )
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"OAuth Fetch Error: {e}", exc_info=True)
        raise HTTPException(status_code=401, detail=f"Failed to fetch credentials: {e}")

    # Rotate session ID to prevent session fixation
    new_session_id = session_manager.rotate_session(session_id)
    
    # Store credentials and mark authenticated
    session_manager.update_session(new_session_id, {
        "credentials": credentials,
        "authenticated": True,
        "oauth_state": None # Clear state
    })
    
    # Clear temporary oauth state from cookie session
    request.session.pop("oauth_state", None)
    request.session.pop("code_verifier", None)
    
    # Update browser cookie
    request.session["session_id"] = new_session_id

    return RedirectResponse("http://localhost:5173")


@router.post("/logout")
def logout(request: Request):
    session_id = request.session.get("session_id")
    if session_id:
        session_manager.delete_session(session_id)
        request.session.clear()

    return {
        "status": "success",
        "message": "Logged out successfully"
    }


@router.get("/status")
def status(request: Request):
    session_id = request.session.get("session_id")
    server_session = session_manager.get_session(session_id)
    
    if server_session and server_session.get("authenticated"):
        return {"authenticated": True}
        
    return {"authenticated": False}

