from googleapiclient.discovery import build
from google.auth.credentials import Credentials


class GmailConnector:

    def __init__(self, credentials: Credentials):

        self.service = build(
            "gmail",
            "v1",
            credentials=credentials
        )


    def list_messages(
        self,
        period="recent",
        max_results=10
    ):

        query = ""

        if period == "month":
            query = "newer_than:30d"
        elif period == "year":
            query = "newer_than:365d"

        response = (
            self.service.users()
            .messages()
            .list(
                userId="me",
                maxResults=max_results,
                q=query
            )
            .execute()
        )

        return response.get(
            "messages",
            []
        )


    def get_message(self, message_id):

        message = (
            self.service.users()
            .messages()
            .get(
                userId="me",
                id=message_id,
                format="full"
            )
            .execute()
        )

        return message