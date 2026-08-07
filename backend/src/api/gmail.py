from fastapi import APIRouter, HTTPException

from src.connectors.gmail_connector import GmailConnector
from src.connectors.gmail_parser import GmailParser
from src.analyzers.authentication_analyzer import AuthenticationAnalyzer
from src.analyzers.url_analyzer import URLAnalyzer
from src.analyzers.content_analyzer import ContentAnalyzer
from src.engines.are import AnalyticalReasoningEngine
from src.analyzers.attachment_analyzer import AttachmentAnalyzer
from src.engines.decision_fusion_engine import DecisionFusionEngine
from src.analyzers.trust_analyzer import TrustAnalyzer
from src.analyzers.email_categorizer import EmailCategorizer

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
    url_analyzer = URLAnalyzer()
    content_analyzer = ContentAnalyzer()
    are = AnalyticalReasoningEngine()
    attachment_analyzer = AttachmentAnalyzer()
    decision_engine = DecisionFusionEngine()
    trust_analyzer = TrustAnalyzer()
    categorizer = EmailCategorizer()
    results = []

    for msg in messages:
        full_message = connector.get_message(
            msg["id"]
        )

        parsed = parser.parse_message(
            full_message
        )

        attachment_analysis = attachment_analyzer.analyze(parsed["attachments"])
        auth_analysis = auth_analyzer.analyze(parsed["headers"])
        url_analysis = url_analyzer.analyze(parsed["body"])
        trust_analysis = trust_analyzer.evaluate(parsed_email=parsed, url_analysis=url_analysis)
        content_analysis = content_analyzer.analyze(
            body=parsed["body"],
            sender=parsed.get("from", ""),
            auth_results=auth_analysis
        )

        are_result = are.evaluate(
            auth_analysis,
            url_analysis,
            content_analysis,
            attachment_analysis,
            trust_analysis
        )

        decision_result = decision_engine.evaluate(are_result)

        parsed["analysis"] = {
            "authentication": auth_analysis,
            "content": content_analysis,
            "url": url_analysis,
            "attachment": attachment_analysis,
            "trust": trust_analysis,
            "reasoning": are_result.get("evidence", {}),
            "decision": decision_result
        }

        parsed["categories"] = categorizer.categorize(
            parsed_email=parsed,
            content_analysis=content_analysis,
            url_analysis=url_analysis,
            attachment_analysis=attachment_analysis,
            decision=decision_result
        )

        print(
            "AUTH ANALYSIS:",
            auth_analysis
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

    parser = GmailParser()
    auth_analyzer = AuthenticationAnalyzer()
    url_analyzer = URLAnalyzer()
    content_analyzer = ContentAnalyzer()
    are = AnalyticalReasoningEngine()
    attachment_analyzer = AttachmentAnalyzer()
    decision_engine = DecisionFusionEngine()
    trust_analyzer = TrustAnalyzer()
    categorizer = EmailCategorizer()

    parsed = parser.parse_message(message)

    attachment_analysis = attachment_analyzer.analyze(parsed["attachments"])
    auth_analysis = auth_analyzer.analyze(parsed["headers"])
    url_analysis = url_analyzer.analyze(parsed["body"])
    trust_analysis = trust_analyzer.evaluate(parsed_email=parsed, url_analysis=url_analysis)
    content_analysis = content_analyzer.analyze(
        body=parsed["body"],
        sender=parsed.get("from", ""),
        auth_results=auth_analysis
    )

    are_result = are.evaluate(
        auth_analysis,
        url_analysis,
        content_analysis,
        attachment_analysis,
        trust_analysis
    )

    decision_result = decision_engine.evaluate(are_result)

    parsed["analysis"] = {
        "authentication": auth_analysis,
        "content": content_analysis,
        "url": url_analysis,
        "attachment": attachment_analysis,
        "trust": trust_analysis,
        "reasoning": are_result.get("evidence", {}),
        "decision": decision_result
    }

    parsed["categories"] = categorizer.categorize(
        parsed_email=parsed,
        content_analysis=content_analysis,
        url_analysis=url_analysis,
        attachment_analysis=attachment_analysis,
        decision=decision_result
    )

    return parsed
