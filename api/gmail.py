from fastapi import APIRouter, HTTPException

from src.connectors.gmail_connector import GmailConnector
from src.connectors.gmail_parser import GmailParser
from src.analyzers.authentication_analyzer import AuthenticationAnalyzer

router = APIRouter()


# Temporary in-memory credentials
gmail_sessions = {}


@router.get("/messages")
def list_messages(
    period: str = "recent"
):

    if "credentials" not in gmail_sessions:
        raise HTTPException(
            status_code=401,
            detail="Please login first."
        )

    connector = GmailConnector(
        gmail_sessions["credentials"]
    )

    messages = connector.list_messages(
        period=period,
        max_results=10
    )

    parser = GmailParser()
    auth_analyzer = AuthenticationAnalyzer()
    results = []

    for msg in messages:
        full_message = connector.get_message(
            msg["id"]
        )

        parsed = parser.parse_message(
            full_message
        )

        parsed["authentication"] = (
            auth_analyzer.analyze(
                parsed["headers"]
            )
        )

        print(
            "AUTH ANALYSIS:",
            parsed["authentication"]
        )

        results.append(parsed)

    return {
        "count": len(results),
        "messages": results
    }


@router.get("/message/{message_id}")
def get_message(
    message_id: str
):

    if "credentials" not in gmail_sessions:
        raise HTTPException(
            status_code=401,
            detail="Please login first."
        )

    connector = GmailConnector(
        gmail_sessions["credentials"]
    )

    message = connector.get_message(
        message_id
    )

    return message