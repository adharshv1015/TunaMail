from fastapi import APIRouter, HTTPException, Request, Query
from fastapi.responses import StreamingResponse
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
from src.services.verdict_store import VerdictStore
from src.engines.decision_consistency_validator import DecisionConsistencyValidator
from src.utils.json_safe import json_safe

import logging
import time
import json
import queue
import threading

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
            "learner": LocalLearning(),
            "consistency_validator": DecisionConsistencyValidator(),
            "verdict_store": VerdictStore()
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



router = APIRouter()

MAX_URLS_PER_EMAIL = int(os.environ.get("MAX_URLS_PER_EMAIL", "50"))
MAX_EMAIL_ANALYSIS_SECONDS = float(os.environ.get("MAX_EMAIL_ANALYSIS_SECONDS", "15.0"))
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(100 * 1024)))  # 100 KB

def emit_progress(progress_callback, step, progress, detail=None):
    """
    Emit a real-time analysis progress event when a callback is provided.

    The existing analysis pipeline remains unchanged when no callback
    is supplied.
    """
    if progress_callback is None:
        return

    event = {
        "type": "progress",
        "step": step,
        "progress": max(0, min(100, int(progress))),
    }

    if detail:
        event["detail"] = detail

    try:
        progress_callback(event)
    except Exception as exc:
        logger.debug(
            {
                "event": "progress_callback_error",
                "error": str(exc),
            }
        )

def process_single_message(
    connector,
    msg_id,
    is_batch=False,
    progress_callback=None,
):
    # ------------------------------------------------------------------
    # Analysis cache: single-flight lock prevents duplicate pipeline runs
    # ------------------------------------------------------------------
    msg_lock = analysis_cache.get_lock(msg_id)
    if msg_lock.locked():
        emit_progress(
            progress_callback,
            "Resuming analysis",
            5,
            "Waiting for existing analysis process to finish..."
        )
    
    with msg_lock:
        tracker = PerformanceTracker(budget_seconds=MAX_EMAIL_ANALYSIS_SECONDS)
        
        emit_progress(
            progress_callback,
            "Fetching email",
            5,
            "Retrieving the message from Gmail..."
        )

        with tracker.measure("fetch_message"):
            full_message = connector.get_message(msg_id)

        analyzers = get_analyzers()

        emit_progress(
            progress_callback,
            "Parsing email",
            10,
            "Extracting headers, body, links and attachments..."
        )

        parsed = safe_analyze(
            "GmailParser",
            msg_id,
            analyzers["parser"].parse_message,
            tracker,
            full_message
        )

        if parsed.get("analysis_status") == "UNAVAILABLE":
            if is_batch:
                return None
            raise HTTPException(status_code=500, detail="Failed to parse message")

        # Check analysis cache AFTER parsing (fingerprint needs parsed content)
        fingerprint = get_analysis_fingerprint(parsed)
        cached = analysis_cache.get(msg_id, fingerprint)

        if cached is not None:
            logger.info(
                {
                    "event": "analysis_cache_hit",
                    "message_id": msg_id,
                }
            )

            emit_progress(
                progress_callback,
                "Analysis complete",
                100,
                "Loaded existing analysis from cache."
            )

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
        emit_progress(
            progress_callback,
            "Analyzing attachments",
            15,
            "Checking email attachments..."
        )

        attachment_analysis = safe_analyze(
            "AttachmentAnalyzer", 
            msg_id, 
            lambda atts: analyzers["attachment"].analyze(
                attachments=atts, 
                connector=connector, 
                message_id=msg_id, 
                progress_callback=progress_callback
            ), 
            tracker, 
            parsed.get("attachments", [])
        )
        
        emit_progress(
            progress_callback,
            "Checking authentication",
            22,
            "Evaluating SPF, DKIM and DMARC..."
        )
        auth_analysis = safe_analyze("AuthenticationAnalyzer", msg_id, analyzers["auth"].analyze, tracker, parsed.get("headers", {}))

        # URL processing
        combined_text_for_urls = (parsed.get("body", "") or "") + "\n" + (parsed.get("html_body", "") or "")
        url_start = time.perf_counter()

        emit_progress(
            progress_callback,
            "Analyzing URLs",
            32,
            "Inspecting links, domains, redirects and URL security..."
        )

        url_analysis = safe_analyze(
            "URLAnalyzer",
            msg_id,
            analyzers["url"].analyze,
            tracker,
            combined_text_for_urls,
            sender_headers=parsed.get("headers", {}),
            auth_results=auth_analysis
        )

        print(
            "URL_DIAG:",
            "body_chars=", len(combined_text_for_urls),
            "urls=", len(url_analysis.get("analysis", [])),
            "ms=", round((time.perf_counter() - url_start) * 1000, 2),
            flush=True,
        )

        if "analysis" in url_analysis and len(url_analysis["analysis"]) > MAX_URLS_PER_EMAIL:
            original_url_count = len(url_analysis["analysis"])
            url_analysis["analysis"] = url_analysis["analysis"][:MAX_URLS_PER_EMAIL]
            url_analysis["truncated"] = True
            url_analysis["original_url_count"] = original_url_count
            url_analysis["processed_url_count"] = MAX_URLS_PER_EMAIL
            logger.info({"event": "urls_truncated", "message_id": msg_id,
                         "original": original_url_count, "limit": MAX_URLS_PER_EMAIL})

        emit_progress(
            progress_callback,
            "Investigating domains",
            45,
            "Checking domain registration intelligence..."
        )

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

        emit_progress(
            progress_callback,
            "Evaluating sender trust",
            52,
            "Evaluating sender and domain trust..."
        )

        trust_analysis = safe_analyze("TrustAnalyzer", msg_id, analyzers["trust"].evaluate, tracker, parsed_email=parsed, url_analysis=url_analysis)

        emit_progress(
            progress_callback,
            "Analyzing email content",
            58,
            "Checking for phishing language, urgency and suspicious requests..."
        )

        content_analysis = safe_analyze("ContentAnalyzer", msg_id, analyzers["content"].analyze, tracker, body=parsed.get("body", ""), sender=parsed.get("from", ""), auth_results=auth_analysis, urls=url_analysis.get("urls", []), attachment_analysis=attachment_analysis)

        existing_analysis = {
            "authentication": auth_analysis,
            "content": content_analysis,
            "url": url_analysis,
            "whois": whois_analysis,
            "attachment": attachment_analysis,
            "trust": trust_analysis,
        }

        # URL Page Intelligence — fetch and analyze for ALL emails (up to 5 URLs)
        # Budget-guarded: skip if time is already tight
        url_page_intelligence = {}
        url_items = url_analysis.get("analysis", [])
        urls_to_inspect = [item.get("url") for item in url_items if item.get("url")][:5]

        emit_progress(
            progress_callback,
            "Inspecting linked pages",
            65,
            "Analyzing webpage intelligence for detected URLs..."
        )

        if urls_to_inspect and not tracker.is_over_budget():
            from src.services.url_inspection_service import URLInspectionService
            from src.analyzers.page_phishing_analyzer import PagePhishingAnalyzer
            page_phishing_analyzer = PagePhishingAnalyzer()

            with tracker.measure("URLPageInspection"):
                url_page_intelligence = URLInspectionService.inspect_urls(urls_to_inspect, msg_id)

            # Enrich each URL analysis item with page phishing analysis
            for item in url_items:
                item_url = item.get("url", "")
                page_data = url_page_intelligence.get(item_url)
                if page_data is not None:
                    item["page_analysis"] = page_phishing_analyzer.analyze(page_data, item_url)
                else:
                    item["page_analysis"] = {
                        "available": False,
                        "status": "NOT_ANALYZED",
                        "indicators": [],
                        "page_risk_score": None,
                    }
        else:
            if tracker.is_over_budget():
                tracker.record_timeout("URLPageInspection", reason="Analysis budget exceeded before page inspection")
            if urls_to_inspect:
                url_page_intelligence["_status"] = "SKIPPED_TIMEOUT"
            for item in url_items:
                item["page_analysis"] = {
                    "available": False,
                    "status": "NOT_ANALYZED",
                    "indicators": [],
                    "page_risk_score": None,
                }

        existing_analysis["url_page_intelligence"] = url_page_intelligence

        emit_progress(
            progress_callback,
            "Running Local AI reasoning",
            74,
            "Performing contextual reasoning over the collected evidence..."
        )

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

        historical_evidence = analyzers["verdict_store"].get_historical_evidence(msg_id, parsed, url_analysis)
       
        emit_progress(
            progress_callback,
            "Analytical reasoning",
            82,
            "Evaluating evidence and determining the security reasoning state..."
        )

        are_result = safe_analyze("AnalyticalReasoningEngine", msg_id, analyzers["are"].evaluate, tracker, auth_analysis, url_analysis, whois_analysis, content_analysis, attachment_analysis, trust_analysis, ai_analysis=ai_analysis, url_page_intelligence=url_page_intelligence, historical_evidence=historical_evidence)

        emit_progress(
            progress_callback,
            "Resolving evidence conflicts",
            87,
            "Checking consistency between security signals..."
        )

        conflict_result = safe_analyze("EvidenceConflictEngine", msg_id, analyzers["conflict"].evaluate, tracker, parsed, auth_analysis, url_analysis, whois_analysis, content_analysis, attachment_analysis, trust_analysis, ai_analysis, url_page_intelligence)

        emit_progress(
            progress_callback,
            "Making final decision",
            90,
            "Merging all analyses into final verdict..."
        )

        emit_progress(
            progress_callback,
            "Building final decision",
            91,
            "Combining security evidence into the final verdict..."
        )

        decision_result = safe_analyze(
            "DecisionFusionEngine",
            msg_id,
            analyzers["decision"].evaluate,
            tracker,
            are_result,
            conflict_result,
        )
        emit_progress(
            progress_callback,
            "Applying security safeguards",
            94,
            "Applying deterministic decision priority and safety guards..."
        )
        # ------------------------------------------------------------
        # FINAL DETERMINISTIC DECISION GUARD
        # ------------------------------------------------------------
        # Build the complete analysis context before applying the
        # deterministic safety layer. This ensures the guard sees:
        # authentication, content, URL, WHOIS, attachments, trust,
        # AI, page intelligence, ARE evidence and conflict evidence.

        final_analysis = {
            **existing_analysis,
            "ai": ai_analysis,
            "reasoning": are_result.get(
                "evidence",
                {},
            ),
            "conflict": conflict_result,
            "url_page_intelligence": url_page_intelligence,
        }

        # First normalize the fused decision through the existing
        # consistency validator.
        decision_result = analyzers[
            "consistency_validator"
        ].validate(
            decision_result
        )

        # Then run the deterministic safety architecture that was
        # previously only used by normalize_message_response().
        decision_result = finalize_intelligence(
            parsed,
            final_analysis,
            decision_result,
        )

        with tracker.measure("LocalLearning"):
            analyzers["learner"].learn(parsed, existing_analysis, decision_result.get("verdict", "UNKNOWN"))

        existing_analysis["ai"] = ai_analysis
        existing_analysis["reasoning"] = are_result.get("evidence", {})
        existing_analysis["conflict"] = conflict_result

        emit_progress(
            progress_callback,
            "Generating explanation",
            96,
            "Preparing the analyst-readable security explanation..."
        )


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


        emit_progress(
            progress_callback,
            "Finalizing analysis",
            98,
            "Saving results and preparing the final report..."
        )   

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

        # Record verdict to persistent historical store
        full_analysis_for_store = {
            "authentication": auth_analysis,
            "url": url_analysis,
            "conflict": conflict_result
        }
        analyzers["verdict_store"].record_if_safe(msg_id, parsed, full_analysis_for_store, decision_result)

        # Cache the full result for subsequent requests
        analysis_cache.set(msg_id, fingerprint, result)

        emit_progress(
            progress_callback,
            "Analysis complete",
            100,
            "Security analysis completed successfully."
        )

        return result


@router.get("/message/{message_id}/stream")
def stream_message_analysis(
    request: Request,
    message_id: str,
):
    """
    Stream real-time email analysis progress using Server-Sent Events.

    The existing process_single_message() pipeline is reused unchanged.
    Progress callbacks are pushed into a thread-safe queue and streamed
    to the frontend as SSE events.
    """

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
    progress_queue = queue.Queue()

    def progress_callback(event):
        progress_queue.put(event)

    def run_analysis():
        try:
            result = process_single_message(
                connector,
                message_id,
                is_batch=False,
                progress_callback=progress_callback,
            )

            progress_queue.put({
                "type": "result",
                "data": result,
            })

        except HTTPException as exc:
            progress_queue.put({
                "type": "error",
                "status": exc.status_code,
                "message": str(exc.detail),
            })

        except Exception as exc:
            import traceback
            tb = traceback.format_exc()
            logger.exception(
                "Streaming email analysis failed for %s",
                message_id,
            )

            progress_queue.put({
                "type": "error",
                "status": 500,
                "message": f"Email analysis failed: {str(exc)} | Trace: {tb}",
            })

        finally:
            progress_queue.put({
                "type": "done",
            })

    thread = threading.Thread(
        target=run_analysis,
        daemon=True,
    )
    thread.start()

    def event_stream():
        while True:

            try:
                event = progress_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"

            if event.get("type") == "done":
                break

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

@router.get("/messages")
def list_messages(
    request: Request,
    period: str = Query(default="recent"),
    limit: int = Query(default=10, ge=1, le=100),
    page_token: str = Query(default=None),
    # Structured search fields — the backend builds the Gmail query
    sender: str = Query(default=None, max_length=200),
    subject: str = Query(default=None, max_length=200),
    keyword: str = Query(default=None, max_length=200),
    domain: str = Query(default=None, max_length=200),
    after: str = Query(default=None, max_length=20),   # YYYY-MM-DD
    before: str = Query(default=None, max_length=20),  # YYYY-MM-DD
):
    import re

    session_id = request.session.get("session_id")
    server_session = session_manager.get_session(session_id)

    if not server_session or not server_session.get("authenticated"):
        raise HTTPException(status_code=401, detail="Please login first.")

    credentials = server_session.get("credentials")
    if not credentials:
        raise HTTPException(status_code=401, detail="Credentials missing from session.")

    # ----------------------------------------------------------------
    # Build Gmail query server-side from validated structured fields.
    # Only pass individual validated parts — never raw user syntax.
    # ----------------------------------------------------------------
    DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

    def _gmail_date(value: str) -> str:
        """Convert YYYY-MM-DD to YYYY/MM/DD for Gmail search."""
        return value.replace("-", "/")

    query_parts = []
    use_custom_query = any([sender, subject, keyword, domain, after, before])

    if use_custom_query:
        if sender:
            query_parts.append(f"from:{sender.strip()}")
        if subject:
            query_parts.append(f"subject:{subject.strip()}")
        if keyword:
            query_parts.append(keyword.strip())
        if domain:
            # Search for the domain in the full message content
            query_parts.append(domain.strip())
        if after:
            if DATE_RE.match(after):
                query_parts.append(f"after:{_gmail_date(after)}")
            else:
                raise HTTPException(status_code=422, detail="Invalid 'after' date format. Use YYYY-MM-DD.")
        if before:
            if DATE_RE.match(before):
                query_parts.append(f"before:{_gmail_date(before)}")
            else:
                raise HTTPException(status_code=422, detail="Invalid 'before' date format. Use YYYY-MM-DD.")

    constructed_query = " ".join(query_parts) if query_parts else None

    # ----------------------------------------------------------------
    # Retrieve lightweight metadata list from Gmail
    # ----------------------------------------------------------------
    connector = GmailConnector(credentials)
    response = connector.list_messages(
        period=period,
        max_results=limit,
        page_token=page_token if page_token else None,
        query=constructed_query,
    )

    raw_messages = response["messages"]
    next_page_token = response["next_page_token"]

    # ----------------------------------------------------------------
    # For each message, fetch lightweight metadata (no full body).
    # If a cached verdict exists, attach it. Otherwise: UNANALYZED.
    # ----------------------------------------------------------------
    from src.services.analysis_cache import analysis_cache

    results = []
    for msg in raw_messages:
        msg_id = msg["id"]
        try:
            meta = connector.get_message_metadata(msg_id)
        except Exception:
            continue

        # Parse headers
        headers = {h["name"]: h["value"] for h in meta.get("payload", {}).get("headers", [])}
        item = {
            "id": msg_id,
            "thread_id": meta.get("threadId"),
            "from": headers.get("From", ""),
            "subject": headers.get("Subject", "(No subject)"),
            "date": headers.get("Date", ""),
            "snippet": meta.get("snippet", ""),
            "analysis_status": "UNANALYZED",
            "analysis": None,
        }

        # Check if a valid cached analysis exists
        cached = analysis_cache.get_by_message_id(msg_id)
        if cached is not None:
            item["analysis_status"] = "ANALYZED"
            item["analysis"] = cached.get("analysis")
            item["decision"] = cached.get("decision")

        results.append(item)

    return {
        "count": len(results),
        "messages": results,
        "retrieval": {
            "mode": "SEARCH" if use_custom_query else "INBOX",
            "query": constructed_query,
            "page_size": limit,
            "has_more": next_page_token is not None,
        },
        "pagination": {
            "next_page_token": next_page_token,
        }
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

class UnlockPDFRequest(BaseModel):
    attachment_id: str
    password: str

@router.post("/message/{message_id}/unlock-pdf")
def unlock_pdf(
    request: Request,
    message_id: str,
    payload: UnlockPDFRequest
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
    
    try:
        raw_attachment = connector.get_attachment(message_id, payload.attachment_id)
        data = raw_attachment.get("data", "")
        import base64
        file_bytes = base64.urlsafe_b64decode(data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to retrieve attachment: {str(e)}")

    if not file_bytes.startswith(b"%PDF-"):
        raise HTTPException(status_code=400, detail="Attachment is not a PDF")

    # Enforce size limits (from AttachmentAnalyzer)
    from src.analyzers.attachment_analyzer import ATTACHMENT_DEEP_SCAN_MAX_BYTES
    if len(file_bytes) > ATTACHMENT_DEEP_SCAN_MAX_BYTES:
        raise HTTPException(status_code=400, detail="Attachment exceeds maximum scan size")

    analyzer = AttachmentAnalyzer()
    # Provide a placeholder filename since we are only statically scanning the bytes
    result = analyzer.analyze_encrypted_pdf(file_bytes, "unlocked.pdf", payload.password)
    
    if result.get("status") == "SUCCESS":
        from src.services.analysis_cache import analysis_cache, get_analysis_fingerprint
        cached = analysis_cache.get_by_message_id(message_id)
        if cached and isinstance(cached, dict) and "analysis" in cached:
            analysis = cached["analysis"]
            attachments = analysis.get("attachment", {})
            
            # Remove PDF_ENCRYPTED evidence
            if "structured_evidence" in attachments:
                attachments["structured_evidence"] = [
                    ev for ev in attachments["structured_evidence"]
                    if ev.get("type") != "PDF_ENCRYPTED"
                ]
            if "evidence" in attachments:
                attachments["evidence"] = [
                    ev for ev in attachments["evidence"]
                    if "encrypted" not in str(ev).lower()
                ]
                
            if "structured_evidence" in attachments and result.get("structured_evidence"):
                attachments["structured_evidence"].extend(result["structured_evidence"])
            if "evidence" in attachments and result.get("evidence"):
                attachments["evidence"].extend(result["evidence"])
                
            decision = analysis.get("decision", {})
            from src.engines.decision_fusion_guard import enforce_deterministic_priority
            decision = enforce_deterministic_priority(decision, analysis)
            
            # Do not convert UNKNOWN to SAFE merely because the risk score is low.
            # UNKNOWN must remain UNKNOWN when evidence is insufficient or degraded.
            #
            # Re-run the complete deterministic decision architecture after removing
            # PDF_ENCRYPTED so the result is governed by the same safety rules as the
            # main production analysis path.
            parsed = cached
            decision = finalize_intelligence(
                parsed,
                analysis,
                decision,
            )
                
            cached["decision"] = decision
            analysis["decision"] = decision
            
            fingerprint = get_analysis_fingerprint(cached)
            analysis_cache.set(message_id, fingerprint, cached)
            
            result["new_decision"] = decision
            
    return result
