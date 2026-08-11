from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from src.connectors.gmail_connector import GmailConnector
from src.connectors.gmail_parser import GmailParser
from src.analyzers.authentication_analyzer import AuthenticationAnalyzer
from src.analyzers.url_analyzer import URLAnalyzer
from src.analyzers.content_analyzer import ContentAnalyzer
from src.engines.are import AnalyticalReasoningEngine
from src.analyzers.attachment_analyzer import AttachmentAnalyzer
from src.engines.decision_fusion_engine import DecisionFusionEngine
from src.ai.local_learning import LocalLearning
from src.engines.evidence_conflict_engine import EvidenceConflictEngine
from src.engines.explanation_engine import ExplanationEngine
from src.analyzers.trust_analyzer import TrustAnalyzer
from src.analyzers.email_categorizer import EmailCategorizer
from intelligence.whois_analyzer import WhoisAnalyzer
from src.api.session import session_manager
from src.ai.orchestrator import analyze_email_with_ai
from src.intelligence.pipeline import run_intelligence

import logging
logger = logging.getLogger(__name__)

from src.ai.analyst_feedback import process_analyst_feedback, get_analyst_feedback, delete_analyst_feedback

class FeedbackRequest(BaseModel):
    label: str
    reason: str = ""
    sender: str = ""
    previous_verdict: str = ""
    previous_risk_score: int = 0

router = APIRouter()


@router.get("/messages")
def list_messages(
    request: Request,
    period: str = "recent"
):

    session_id = request.session.get("session_id")
    server_session = session_manager.get_session(session_id)
    
    if not server_session or not server_session.get("authenticated"):
        raise HTTPException(
            status_code=401,
            detail="Please login first."
        )

    credentials = server_session.get("credentials")
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Credentials missing from session."
        )

    connector = GmailConnector(credentials)

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
    conflict_engine = EvidenceConflictEngine()
    explanation_engine = ExplanationEngine()
    trust_analyzer = TrustAnalyzer()
    categorizer = EmailCategorizer()
    whois_analyzer = WhoisAnalyzer()
    learner = LocalLearning()
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
        url_analysis = url_analyzer.analyze(parsed["body"], sender_headers=parsed["headers"], auth_results=auth_analysis)

        whois_analysis = []
        seen_domains = set()

        for item in url_analysis.get("analysis", []):

            domain = item.get("domain", "").strip().lower()

            if not domain or domain in seen_domains:
                continue

            seen_domains.add(domain)
            whois_result = whois_analyzer.analyze(domain)
            whois_analysis.append(whois_result)

        trust_analysis = trust_analyzer.evaluate(
            parsed_email=parsed,
            url_analysis=url_analysis
        )
        content_analysis = content_analyzer.analyze(
            body=parsed["body"],
            sender=parsed.get("from", ""),
            auth_results=auth_analysis,
            urls=url_analysis.get("urls", [])
        )

        existing_analysis = {
            "authentication": auth_analysis,
            "content": content_analysis,
            "url": url_analysis,
            "whois": whois_analysis,
            "attachment": attachment_analysis,
            "trust": trust_analysis
        }
        
        ai_analysis = analyze_email_with_ai(parsed, existing_analysis)

        are_result = are.evaluate(
            auth_analysis,
            url_analysis,
            whois_analysis,
            content_analysis,
            attachment_analysis,
            trust_analysis,
            ai_analysis=ai_analysis
        )
        
        conflict_result = conflict_engine.evaluate(
            parsed,
            auth_analysis,
            url_analysis,
            whois_analysis,
            content_analysis,
            attachment_analysis,
            trust_analysis,
            ai_analysis
        )

        decision_result = decision_engine.evaluate(are_result, conflict_result)
        
        learner.learn(parsed, existing_analysis, decision_result["verdict"])
        
        explanation = explanation_engine.evaluate(
            verdict=decision_result["verdict"],
            confidence=decision_result["confidence"],
            risk_score=decision_result["risk_score"],
            conflict_state=conflict_result["conflict_state"],
            structured_evidence=conflict_result["structured_evidence"]
        )

        # --- Stage 5: Intelligence Pipeline (additive, non-blocking) ---
        intelligence_result = {}
        try:
            intelligence_result = run_intelligence(parsed, existing_analysis)
        except Exception as _intel_err:
            logger.warning(f"Intelligence pipeline error (non-critical): {_intel_err}")

        parsed["analysis"] = {
            "authentication": auth_analysis,
            "content": content_analysis,
            "url": url_analysis,
            "whois": whois_analysis,
            "attachment": attachment_analysis,
            "trust": trust_analysis,
            "ai": ai_analysis,
            "reasoning": are_result.get("evidence", {}),
            "decision": decision_result,
            "explanation": explanation,
            "conflict": conflict_result,
            "intelligence": intelligence_result
        }

        parsed["categories"] = categorizer.categorize(
            parsed_email=parsed,
            content_analysis=content_analysis,
            url_analysis=url_analysis,
            attachment_analysis=attachment_analysis,
            decision=decision_result
        )

        results.append(parsed)

    return {
        "count": len(results),
        "messages": results
    }


@router.get("/message/{message_id}")
def get_message(
    request: Request,
    message_id: str
):

    session_id = request.session.get("session_id")
    server_session = session_manager.get_session(session_id)
    
    if not server_session or not server_session.get("authenticated"):
        raise HTTPException(
            status_code=401,
            detail="Please login first."
        )

    credentials = server_session.get("credentials")
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Credentials missing from session."
        )

    connector = GmailConnector(credentials)

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
    conflict_engine = EvidenceConflictEngine()
    explanation_engine = ExplanationEngine()
    trust_analyzer = TrustAnalyzer()
    categorizer = EmailCategorizer()
    whois_analyzer = WhoisAnalyzer()
    learner = LocalLearning()

    parsed = parser.parse_message(message)

    attachment_analysis = attachment_analyzer.analyze(parsed["attachments"])
    auth_analysis = auth_analyzer.analyze(parsed["headers"])
    url_analysis = url_analyzer.analyze(parsed["body"], sender_headers=parsed["headers"], auth_results=auth_analysis)

    whois_analysis = []
    seen_domains = set()

    for item in url_analysis.get("analysis", []):

        domain = item.get("domain", "").strip().lower()

        if not domain or domain in seen_domains:
            continue

        seen_domains.add(domain)
        whois_result = whois_analyzer.analyze(domain)
        whois_analysis.append(whois_result)

    trust_analysis = trust_analyzer.evaluate(
        parsed_email=parsed,
        url_analysis=url_analysis
    )
    content_analysis = content_analyzer.analyze(
        body=parsed["body"],
        sender=parsed.get("from", ""),
        auth_results=auth_analysis,
        urls=url_analysis.get("urls", [])
    )

    existing_analysis = {
        "authentication": auth_analysis,
        "content": content_analysis,
        "url": url_analysis,
        "whois": whois_analysis,
        "attachment": attachment_analysis,
        "trust": trust_analysis
    }
    
    ai_analysis = analyze_email_with_ai(parsed, existing_analysis)

    are_result = are.evaluate(
        auth_analysis,
        url_analysis,
        whois_analysis,
        content_analysis,
        attachment_analysis,
        trust_analysis,
        ai_analysis=ai_analysis
    )

    conflict_result = conflict_engine.evaluate(
        parsed,
        auth_analysis,
        url_analysis,
        whois_analysis,
        content_analysis,
        attachment_analysis,
        trust_analysis,
        ai_analysis
    )

    decision_result = decision_engine.evaluate(are_result, conflict_result)

    learner.learn(parsed, existing_analysis, decision_result["verdict"])

    explanation = explanation_engine.evaluate(
        verdict=decision_result["verdict"],
        confidence=decision_result["confidence"],
        risk_score=decision_result["risk_score"],
        conflict_state=conflict_result["conflict_state"],
        structured_evidence=conflict_result["structured_evidence"]
    )

    # --- Stage 5: Intelligence Pipeline (additive, non-blocking) ---
    intelligence_result = {}
    try:
        intelligence_result = run_intelligence(parsed, existing_analysis)
    except Exception as _intel_err:
        logger.warning(f"Intelligence pipeline error (non-critical): {_intel_err}")

    parsed["analysis"] = {
        "authentication": auth_analysis,
        "content": content_analysis,
        "url": url_analysis,
        "whois": whois_analysis,
        "attachment": attachment_analysis,
        "trust": trust_analysis,
        "ai": ai_analysis,
        "reasoning": are_result.get("evidence", {}),
        "decision": decision_result,
        "explanation": explanation,
        "conflict": conflict_result,
        "intelligence": intelligence_result
    }

    parsed["categories"] = categorizer.categorize(
        parsed_email=parsed,
        content_analysis=content_analysis,
        url_analysis=url_analysis,
        attachment_analysis=attachment_analysis,
        decision=decision_result
    )

    return parsed


@router.post("/message/{message_id}/feedback")
def submit_feedback(
    request: Request,
    message_id: str,
    feedback: FeedbackRequest
):
    session_id = request.session.get("session_id")
    server_session = session_manager.get_session(session_id)
    
    if not server_session or not server_session.get("authenticated"):
        raise HTTPException(status_code=401, detail="Please login first.")
        
    result = process_analyst_feedback(
        message_id=message_id,
        sender=feedback.sender,
        label=feedback.label,
        reason=feedback.reason,
        previous_verdict=feedback.previous_verdict,
        previous_risk_score=feedback.previous_risk_score
    )
    
    return {
        "status": "success",
        "message_id": message_id,
        "label": feedback.label
    }

@router.get("/message/{message_id}/feedback")
def get_feedback(
    request: Request,
    message_id: str
):
    session_id = request.session.get("session_id")
    server_session = session_manager.get_session(session_id)
    
    if not server_session or not server_session.get("authenticated"):
        raise HTTPException(status_code=401, detail="Please login first.")
        
    data = get_analyst_feedback(message_id)
    if not data:
        raise HTTPException(status_code=404, detail="Feedback not found.")
    return data

@router.delete("/message/{message_id}/feedback")
def delete_feedback(
    request: Request,
    message_id: str
):
    session_id = request.session.get("session_id")
    server_session = session_manager.get_session(session_id)
    
    if not server_session or not server_session.get("authenticated"):
        raise HTTPException(status_code=401, detail="Please login first.")
        
    delete_analyst_feedback(message_id)
    return {"status": "success"}
