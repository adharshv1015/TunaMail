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


def format_name_from_email(email_str: str) -> str:
    if not email_str or not isinstance(email_str, str):
        return "You"
    import re
    # Check if format like "Name <email@domain>"
    m_angle = re.match(r"^([^<@]+)<[^>]+>$", email_str.strip())
    if m_angle and m_angle.group(1).strip():
        clean_name = m_angle.group(1).strip().strip("'\"")
        if clean_name:
            return clean_name
        
    email_clean = re.sub(r"[<>]", "", email_str).strip()
    if "@" not in email_clean:
        return email_clean.strip("'\"")
        
    username = email_clean.split("@")[0].strip()
    # If dots, underscores, dashes
    if re.search(r"[\._\-]", username):
        parts = re.split(r"[\._\-]+", username)
        words = [re.sub(r"\d+", "", p).capitalize() for p in parts if p]
        words = [w for w in words if w]
        if words:
            return " ".join(words)
            
    # Strip trailing numbers
    clean_word = re.sub(r"\d+$", "", username)
    # Check camel case
    clean_word = re.sub(r"([a-z])([A-Z])", r"\1 \2", clean_word)
    # Common names with initial e.g. adharshv -> Adharsh V
    if len(clean_word) > 4:
        base = clean_word[:-1]
        initial = clean_word[-1].upper()
        if base.lower() in ["adharsh", "rahul", "suresh", "ramesh", "vijay", "ajay", "karthik", "arun", "rohit", "anand"]:
            return f"{base.capitalize()} {initial}"
            
    return clean_word.capitalize() if clean_word else username.capitalize()


@router.get("/status")
def status(request: Request):
    session_id = request.session.get("session_id")
    server_session = session_manager.get_session(session_id)
    
    if server_session and server_session.get("authenticated"):
        user_email = server_session.get("user_email")
        if not user_email and server_session.get("credentials"):
            try:
                from googleapiclient.discovery import build
                service = build("gmail", "v1", credentials=server_session["credentials"])
                profile = service.users().getProfile(userId="me").execute()
                user_email = profile.get("emailAddress")
                if user_email:
                    server_session["user_email"] = user_email
            except Exception:
                pass

        user_name = format_name_from_email(user_email) if user_email else None
        return {
            "authenticated": True,
            "email": user_email,
            "name": user_name
        }
        
    return {"authenticated": False}


