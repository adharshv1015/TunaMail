from pathlib import Path

from google_auth_oauthlib.flow import Flow


CLIENT_SECRET_FILE = (
    Path(__file__).resolve().parents[2]
    / "client_secret.json"
)

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly"
]


def create_flow():

    flow = Flow.from_client_secrets_file(
        str(CLIENT_SECRET_FILE),
        scopes=SCOPES,
        redirect_uri="http://127.0.0.1:8000/auth/google/callback"
    )

    return flow
