from googleapiclient.discovery import build
from google.auth.credentials import Credentials

# Period → Gmail search operator mapping (canonical definition)
PERIOD_QUERY_MAP = {
    "recent": "",          # No date filter
    "month": "newer_than:30d",
    "year": "newer_than:365d",
}


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
        max_results=10,
        page_token=None,
        query=None,
    ):
        """
        Lightweight message listing — returns metadata only (no body).
        Returns a dict with:
            messages: list of {id, threadId}
            next_page_token: str or None
        """
        # Build the Gmail query string. If a structured query is passed
        # (constructed server-side), use it directly. Otherwise apply the
        # period preset.
        if query is not None:
            q = query
        else:
            q = PERIOD_QUERY_MAP.get(period, "")

        request_kwargs = dict(
            userId="me",
            maxResults=max_results,
            q=q,
            # Lightweight metadata — avoids downloading message bodies
        )
        if page_token:
            request_kwargs["pageToken"] = page_token

        response = (
            self.service.users()
            .messages()
            .list(**request_kwargs)
            .execute()
        )

        return {
            "messages": response.get("messages", []),
            "next_page_token": response.get("nextPageToken"),
        }

    def get_message_metadata(self, message_id):
        """
        Fetch lightweight message metadata (headers + snippet only).
        Used to build the inbox list without triggering full analysis.
        """
        message = (
            self.service.users()
            .messages()
            .get(
                userId="me",
                id=message_id,
                format="metadata",
                metadataHeaders=["From", "Subject", "Date"],
            )
            .execute()
        )
        return message

    def get_message(self, message_id):
        """Fetch the full message payload for deep analysis."""
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

    def get_attachment(self, message_id, attachment_id):
        """Fetch raw attachment bytes (base64url encoded) from Gmail API."""
        attachment = (
            self.service.users()
            .messages()
            .attachments()
            .get(
                userId="me",
                messageId=message_id,
                id=attachment_id,
            )
            .execute()
        )
        
        return attachment