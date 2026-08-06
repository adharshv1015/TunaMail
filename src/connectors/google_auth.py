import os

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

from google_auth_oauthlib.flow import Flow


CLIENT_SECRET_FILE = "client_secret.json"


SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly"
]


REDIRECT_URI = "http://localhost:8000/auth/callback"


class GoogleAuth:

    def __init__(self):
        self.flow = None


    def create_flow(self):

        self.flow = Flow.from_client_secrets_file(
            CLIENT_SECRET_FILE,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI
        )

        return self.flow



    def authorization_url(self):

        flow = self.create_flow()


        auth_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent"
        )


        return auth_url, state



    def fetch_credentials(
        self,
        authorization_response
    ):

        if self.flow is None:
            raise Exception(
                "OAuth flow expired. Restart login."
            )


        self.flow.fetch_token(
            authorization_response=authorization_response
        )


        return self.flow.credentials
