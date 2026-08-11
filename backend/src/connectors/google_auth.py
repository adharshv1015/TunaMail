import os

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

from google_auth_oauthlib.flow import Flow

CLIENT_SECRET_FILE = "client_secret.json"

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly"
]

REDIRECT_URI = "http://localhost:8000/auth/callback"

class GoogleAuth:

    def create_flow(self, state=None):
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRET_FILE,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI,
            state=state
        )
        return flow

    def authorization_url(self, state):
        flow = self.create_flow(state=state)
        
        auth_url, returned_state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
            state=state
        )

        code_verifier = getattr(flow, 'code_verifier', None)
        return auth_url, returned_state, code_verifier

    def fetch_credentials(self, authorization_response, state, code_verifier=None):
        flow = self.create_flow(state=state)
        if code_verifier:
            flow.code_verifier = code_verifier
        
        flow.fetch_token(
            authorization_response=authorization_response
        )

        return flow.credentials
