from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
import os

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
from src.ai.explanation_engine import ExplanationEngine
from src.analyzers.trust_analyzer import TrustAnalyzer
from src.analyzers.email_categorizer import EmailCategorizer
from intelligence.whois_analyzer import WhoisAnalyzer
from src.api.session import session_manager
from src.ai.orchestrator import analyze_email_with_ai
from src.intelligence.pipeline import run_intelligence
from src.monitoring.performance import PerformanceTracker
from src.services.analysis_cache import analysis_cache, get_analysis_fingerprint
from src.utils.json_safe import json_safe

import logging
import time
logger = logging.getLogger(__name__)

# Global singletons for batch processing optimization
_analyzers = {}

def get_analyzers():
    global _analyzers
    if not _analyzers:
        _analyzers = {
            "parser": GmailParser(),
            "auth": AuthenticationAnalyzer(),
            "url": URLAnalyzer(),
            "content": ContentAnalyzer(),
            "are": AnalyticalReasoningEngine(),
            "attachment": AttachmentAnalyzer(),
            "decision": DecisionFusionEngine(),
            "conflict": EvidenceConflictEngine(),
            "explanation": ExplanationEngine(),
            "trust": TrustAnalyzer(),
            "categorizer": EmailCategorizer(),
            "whois": WhoisAnalyzer(),
            "learner": LocalLearning()
        }
    return _analyzers

def safe_analyze(analyzer_name, message_id, func, tracker, *args, **kwargs):
    logger.info({"event": "analyzer_start", "analyzer": analyzer_name, "message_id": message_id})
    try:
        with tracker.measure(analyzer_name):
            result = func(*args, **kwargs)
        if isinstance(result, dict) and "analysis_status" not in result:
            result["analysis_status"] = "AVAILABLE"
        return result
    except Exception as e:
        logger.error({"event": "analyzer_error", "analyzer": analyzer_name, "message_id": message_id, "error": str(e)})
        if analyzer_name == "WhoisAnalyzer":
            return {}
        return {"analysis_status": "UNAVAILABLE"}

from src.engines.intelligence_pipeline import IntelligencePipeline
from src.engines.decision_validator import DecisionValidator
from src.engines.decision_fusion_guard import (
    enforce_deterministic_priority,
    enforce_unknown_when_insufficient,
)
from src.ai.context_decision import apply_context_rules

decision_validator = DecisionValidator()

def finalize_intelligence(
    parsed_email,
    analysis,
    decision,
):

    decision = apply_context_rules(
        parsed_email,
        analysis,
        decision,
    )

    decision = enforce_deterministic_priority(
        decision,
        analysis,
    )

    decision = enforce_unknown_when_insufficient(
        decision,
        analysis,
    )

    decision = decision_validator.validate(
        decision
    )

    return decision

# ============================================================
# BACKWARD COMPATIBILITY DEFAULTS
# ============================================================

def ensure_analysis_schema(analysis):

    analysis = analysis or {}

    defaults = {
        "authentication": {},
        "content": {},
        "urls": {},
        "whois": [],
        "attachments": {},
        "trust": {},
        "ai": {},
        "reasoning": {},
        "pipeline": {},
    }

    for key, default in defaults.items():

        if key not in analysis:
            analysis[key] = default

    return analysis

# ============================================================
# API RESPONSE NORMALIZATION
# ============================================================

def normalize_message_response(
    parsed_email,
    analysis,
    decision,
):

    analysis = ensure_analysis_schema(analysis)

    decision = finalize_intelligence(
        parsed_email,
        analysis,
        decision,
    )

    parsed_email["analysis"] = analysis
    parsed_email["analysis"]["decision"] = decision

    parsed_email["decision"] = decision

    return parsed_email

from src.ai.analyst_feedback import process_analyst_feedback, get_analyst_feedback, delete_analyst_feedback

class FeedbackRequest(BaseModel):
    label: str
    reason: str = ""
    sender: str = ""
    previous_verdict: str = ""
    previous_risk_score: int = 0

router = APIRouter()

MAX_URLS_PER_EMAIL = int(os.environ.get("MAX_URLS_PER_EMAIL", "50"))
MAX_EMAIL_ANALYSIS_SECONDS = float(os.environ.get("MAX_EMAIL_ANALYSIS_SECONDS", "15.0"))
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(100 * 1024)))  # 100 KB



def process_single_message(connector, msg_id, is_batch=False):
    # ------------------------------------------------------------------
    # Analysis cache: single-flight lock prevents duplicate pipeline runs
    # ------------------------------------------------------------------
    msg_lock = analysis_cache.get_lock(msg_id)
    with msg_lock:
        tracker = PerformanceTracker(budget_seconds=MAX_EMAIL_ANALYSIS_SECONDS)
        
        with tracker.measure("fetch_message"):
            full_message = connector.get_message(msg_id)

        analyzers = get_analyzers()

        parsed = safe_analyze("GmailParser", msg_id, analyzers["parser"].parse_message, tracker, full_message)
        if parsed.get("analysis_status") == "UNAVAILABLE":
            if is_batch:
                return None
            raise HTTPException(status_code=500, detail="Failed to parse message")

        # Check analysis cache AFTER parsing (fingerprint needs parsed content)
        fingerprint = get_analysis_fingerprint(parsed)
        cached = analysis_cache.get(msg_id, fingerprint)
        if cached is not None:
            logger.info({"event": "analysis_cache_hit", "message_id": msg_id})
            return cached

        # ------------------------------------------------------------------
        # Large body truncation — evidence is added; body is truncated for
        # downstream processing only. Original metadata is preserved.
        # ------------------------------------------------------------------
        body = parsed.get("body", "") or ""
        body_bytes = len(body.encode("utf-8", errors="replace"))
        body_truncated = False
        if body_bytes > MAX_BODY_BYTES:
            body = body.encode("utf-8", errors="replace")[:MAX_BODY_BYTES].decode("utf-8", errors="replace")
            body_truncated = True
            parsed["body_truncation"] = {
                "truncated": True,
                "original_length": body_bytes,
                "processed_length": MAX_BODY_BYTES,
                "status": "INPUT_TRUNCATED",
            }
            parsed["body"] = body
            logger.info({"event": "body_truncated", "message_id": msg_id,
                         "original_bytes": body_bytes, "limit_bytes": MAX_BODY_BYTES})

        attachment_analysis = safe_analyze("AttachmentAnalyzer", msg_id, analyzers["attachment"].analyze, tracker, parsed.get("attachments", []))
        auth_analysis = safe_analyze("AuthenticationAnalyzer", msg_id, analyzers["auth"].analyze, tracker, parsed.get("headers", {}))

        # URL processing
        combined_text_for_urls = (parsed.get("body", "") or "") + "\n" + (parsed.get("html_body", "") or "")
        url_analysis = safe_analyze("URLAnalyzer", msg_id, analyzers["url"].analyze, tracker, combined_text_for_urls, sender_headers=parsed.get("headers", {}), auth_results=auth_analysis)

        if "analysis" in url_analysis and len(url_analysis["analysis"]) > MAX_URLS_PER_EMAIL:
            original_url_count = len(url_analysis["analysis"])
            url_analysis["analysis"] = url_analysis["analysis"][:MAX_URLS_PER_EMAIL]
            url_analysis["truncated"] = True
            url_analysis["original_url_count"] = original_url_count
            url_analysis["processed_url_count"] = MAX_URLS_PER_EMAIL
            logger.info({"event": "urls_truncated", "message_id": msg_id,
                         "original": original_url_count, "limit": MAX_URLS_PER_EMAIL})

        whois_analysis = []
        seen_domains = set()

        for item in url_analysis.get("analysis", []):
            domain = item.get("domain", "").strip().lower()
            if not domain or domain in seen_domains:
                continue
            seen_domains.add(domain)
            if tracker.is_over_budget():
                tracker.record_timeout("WhoisAnalyzer", reason="Analysis budget exceeded before WHOIS")
                break
            whois_result = safe_analyze("WhoisAnalyzer", msg_id, analyzers["whois"].analyze, tracker, domain)
            if whois_result:
                whois_analysis.append(whois_result)

        trust_analysis = safe_analyze("TrustAnalyzer", msg_id, analyzers["trust"].evaluate, tracker, parsed_email=parsed, url_analysis=url_analysis)

        content_analysis = safe_analyze("ContentAnalyzer", msg_id, analyzers["content"].analyze, tracker, body=parsed.get("body", ""), sender=parsed.get("from", ""), auth_results=auth_analysis, urls=url_analysis.get("urls", []))

        existing_analysis = {
            "authentication": auth_analysis,
            "content": content_analysis,
            "url": url_analysis,
            "whois": whois_analysis,
            "attachment": attachment_analysis,
            "trust": trust_analysis,
        }

        # URL Page Intelligence for LINK_ONLY
        is_link_only = content_analysis.get("link_only", False)
        url_page_intelligence = {}
        if is_link_only:
            urls_to_inspect = [item.get("url") for item in url_analysis.get("analysis", []) if item.get("url")]
            from src.services.url_inspection_service import URLInspectionService
            url_page_intelligence = URLInspectionService.inspect_urls(urls_to_inspect, msg_id)
        
        existing_analysis["url_page_intelligence"] = url_page_intelligence

        # Timeout check before expensive AI
        if tracker.is_over_budget():
            tracker.record_timeout("LocalAI", reason="Analysis budget exceeded before AI inference")
            ai_analysis = {
                "enabled": False,
                "reasoning_state": "INSUFFICIENT_EVIDENCE",
                "confidence": 0.0,
                "reasoning_summary": "Local AI analysis skipped due to timeout.",
                "recommended_classification": "UNKNOWN"
            }
        else:
            ai_analysis = safe_analyze("LocalAI", msg_id, analyze_email_with_ai, tracker, parsed, existing_analysis)

        are_result = safe_analyze("AnalyticalReasoningEngine", msg_id, analyzers["are"].evaluate, tracker, auth_analysis, url_analysis, whois_analysis, content_analysis, attachment_analysis, trust_analysis, ai_analysis=ai_analysis, url_page_intelligence=url_page_intelligence)

        conflict_result = safe_analyze("EvidenceConflictEngine", msg_id, analyzers["conflict"].evaluate, tracker, parsed, auth_analysis, url_analysis, whois_analysis, content_analysis, attachment_analysis, trust_analysis, ai_analysis, url_page_intelligence)

        decision_result = safe_analyze("DecisionFusionEngine", msg_id, analyzers["decision"].evaluate, tracker, are_result, conflict_result)

        with tracker.measure("LocalLearning"):
            analyzers["learner"].learn(parsed, existing_analysis, decision_result.get("verdict", "UNKNOWN"))

        existing_analysis["ai"] = ai_analysis
        existing_analysis["reasoning"] = are_result.get("evidence", {})
        existing_analysis["conflict"] = conflict_result

        explanation = safe_analyze("ExplanationEngine", msg_id, analyzers["explanation"].generate, tracker, parsed, existing_analysis, decision_result)

        # --- Intelligence Pipeline (additive, non-blocking, only if budget allows) ---
        intelligence_result = {}
        if not tracker.is_over_budget():
            try:
                with tracker.measure("IntelligencePipeline"):
                    intelligence_result = run_intelligence(parsed, existing_analysis)
            except Exception as _intel_err:
                logger.warning(f"Intelligence pipeline error (non-critical): {_intel_err}")
        else:
            tracker.record_timeout("IntelligencePipeline", reason="Analysis budget exceeded")

        tracker.complete()
        pipeline_stats = tracker.get_summary()

        result = parsed
        result["analysis"] = json_safe({
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
            "intelligence": intelligence_result,
            "pipeline": pipeline_stats,
            "url_page_intelligence": url_page_intelligence,
        })

        with tracker.measure("EmailCategorizer"):
            result["categories"] = analyzers["categorizer"].categorize(
                parsed_email=parsed,
                content_analysis=content_analysis,
                url_analysis=url_analysis,
                attachment_analysis=attachment_analysis,
                decision=decision_result
            )

        # Cache the full result for subsequent requests
        analysis_cache.set(msg_id, fingerprint, result)
        return result


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

    results = []

    for msg in messages:
        parsed = process_single_message(connector, msg["id"], is_batch=True)
        if parsed:
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
    
    return process_single_message(connector, message_id, is_batch=False)


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
