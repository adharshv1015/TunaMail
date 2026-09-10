from fastapi import APIRouter, HTTPException, Request, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import os

from src.connectors.gmail_connector import GmailConnector, PERIOD_QUERY_MAP
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
import re

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

def _safe_int(val, default=0):
    try:
        if val is None:
            return default
        return int(round(float(val)))
    except (ValueError, TypeError):
        return default

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

    auth_data = analysis.get("authentication") or {}
    url_data = analysis.get("url") or analysis.get("urls") or {}
    att_data = analysis.get("attachment") or analysis.get("attachments") or {}
    content_data = analysis.get("content") or {}
    intel_data = analysis.get("intelligence") or {}

    spf_pass = str(auth_data.get("spf", "")).lower() == "pass"
    dkim_pass = str(auth_data.get("dkim", "")).lower() == "pass"
    url_items = url_data.get("analysis") if isinstance(url_data.get("analysis"), list) else []
    has_bad_urls = any(
        isinstance(u, dict) and (u.get("reputation") == "MALICIOUS" or (u.get("risk_score", 0) >= 50))
        for u in url_items
    ) or url_data.get("risk_score", 0) >= 40
    has_bad_att = att_data.get("risk_score", 0) >= 40
    has_bad_content = content_data.get("credential_harvesting") or content_data.get("financial_lure") or content_data.get("urgency")
    has_bad_intel = intel_data.get("threat_score", 0) >= 40

    if spf_pass and dkim_pass and not has_bad_urls and not has_bad_att and not has_bad_content and not has_bad_intel:
        decision["verdict"] = "SAFE"
        decision["detail_verdict"] = "CLEAR_POSITIVE_EVIDENCE"
        decision["risk_score"] = 0
        decision["confidence"] = max(_safe_int(decision.get("confidence"), 85), 85)
        decision["recommendation"] = "Verified sender, safe links, and no malicious content detected. Safe to read, click links, and reply."

    risk_int = _safe_int(decision.get("risk_score") if isinstance(decision, dict) else 0, 0)

    if risk_int == 0 and isinstance(decision, dict):
        if str(decision.get("verdict", "")).upper() in ("UNKNOWN", "SUSPICIOUS"):
            decision["verdict"] = "SAFE"
            if decision.get("detail_verdict") in ("INSUFFICIENT_EVIDENCE", "LIMITED_CONTEXT", "UNKNOWN", None, ""):
                decision["detail_verdict"] = "CLEAR_POSITIVE_EVIDENCE"
            decision["recommendation"] = "Verified sender, safe links, and no malicious content detected. Safe to read, click links, and reply."

        are_raw = analysis.get("are_confidence") or analysis.get("confidence") or 90
        are_conf = _safe_int(are_raw, 90)
        dec_conf = _safe_int(decision.get("confidence"), 0)
        decision["confidence"] = max(dec_conf, are_conf, 85)

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

    # Synchronize alias keys for backward and forward compatibility
    if "url" in analysis and (not analysis.get("urls") or analysis.get("urls") == {}):
        analysis["urls"] = analysis["url"]
    elif "urls" in analysis and (not analysis.get("url") or analysis.get("url") == {}):
        analysis["url"] = analysis["urls"]

    if "attachment" in analysis and (not analysis.get("attachments") or analysis.get("attachments") == {}):
        analysis["attachments"] = analysis["attachment"]
    elif "attachments" in analysis and (not analysis.get("attachment") or analysis.get("attachment") == {}):
        analysis["attachment"] = analysis["attachments"]

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
MAX_EMAIL_ANALYSIS_SECONDS = float(os.environ.get("MAX_EMAIL_ANALYSIS_SECONDS", "30.0"))
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

        try:
            with tracker.measure("fetch_message"):
                full_message = connector.get_message(msg_id)
        except Exception as exc:
            err_msg = str(exc).lower()
            if any(tok in err_msg for tok in ["invalid_grant", "token", "unauthorized", "expired", "401", "credentials"]):
                raise HTTPException(status_code=401, detail="Gmail session expired. Please reconnect Gmail.")
            logger.error(f"Failed to retrieve full message from Gmail: {exc}", exc_info=True)
            raise HTTPException(status_code=502, detail=f"Failed to fetch email from Gmail: {exc}")

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
            cached_dec = cached.get("decision") or (cached.get("analysis", {}).get("decision") if isinstance(cached.get("analysis"), dict) else None)
            if cached_dec and _safe_int(cached_dec.get("risk_score"), 0) == 0:
                if str(cached_dec.get("verdict", "")).upper() == "UNKNOWN":
                    cached_dec["verdict"] = "SAFE"
                    if cached_dec.get("detail_verdict") in ("INSUFFICIENT_EVIDENCE", "LIMITED_CONTEXT", "UNKNOWN", None, ""):
                        cached_dec["detail_verdict"] = "CLEAR_POSITIVE_EVIDENCE"
                    cached_dec["recommendation"] = "No immediate threats were detected."
                if _safe_int(cached_dec.get("confidence"), 0) <= 40:
                    cached_dec["confidence"] = 90
                cached["decision"] = cached_dec
                if isinstance(cached.get("analysis"), dict):
                    cached["analysis"]["decision"] = cached_dec

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

        logger.debug(
            "URL_DIAG: body_chars=%d urls=%d ms=%.2f",
            len(combined_text_for_urls),
            len(url_analysis.get("analysis", [])),
            round((time.perf_counter() - url_start) * 1000, 2),
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
            if len(seen_domains) > 5:
                break
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
            "urls": url_analysis,
            "whois": whois_analysis,
            "attachment": attachment_analysis,
            "attachments": attachment_analysis,
            "trust": trust_analysis,
        }

        # ============================================================
        # Local AI reasoning MUST run before deep URL page inspection.
        #
        # URL page inspection is network-heavy and can consume the
        # cumulative pipeline budget. Local AI is a core reasoning
        # stage and must not be starved by optional page inspection.
        # ============================================================

        emit_progress(
            progress_callback,
            "Running Local AI reasoning",
            65,
            "Performing contextual reasoning over the collected evidence..."
        )

        if tracker.is_over_budget():
            tracker.record_timeout(
                "LocalAI",
                reason="Analysis budget exceeded before AI inference",
            )
            ai_analysis = {
                "enabled": False,
                "reasoning_state": "INSUFFICIENT_EVIDENCE",
                "confidence": 0.0,
                "reasoning_summary": (
                    "Local AI analysis skipped due to timeout."
                ),
                "recommended_classification": "UNKNOWN",
            }
        else:
            ai_analysis = safe_analyze(
                "LocalAI",
                msg_id,
                analyze_email_with_ai,
                tracker,
                parsed,
                existing_analysis,
            )

        existing_analysis["ai"] = ai_analysis

        # ============================================================
        # URL Page Intelligence — optional/deep network enrichment.
        # This runs AFTER Local AI so page inspection cannot starve
        # the core reasoning stage.
        # ============================================================

        url_page_intelligence = {}
        url_items = url_analysis.get("analysis", [])
        urls_to_inspect = [
            item.get("url")
            for item in url_items
            if item.get("url")
        ][:5]

        emit_progress(
            progress_callback,
            "Inspecting linked pages",
            74,
            "Analyzing webpage intelligence for detected URLs..."
        )

        if urls_to_inspect and not tracker.is_over_budget():
            from src.services.url_inspection_service import (
                URLInspectionService,
            )
            from src.analyzers.page_phishing_analyzer import (
                PagePhishingAnalyzer,
            )

            page_phishing_analyzer = PagePhishingAnalyzer()

            with tracker.measure("URLPageInspection"):
                url_page_intelligence = (
                    URLInspectionService.inspect_urls(
                        urls_to_inspect,
                        msg_id,
                    )
                )

            # Enrich each URL analysis item with page phishing analysis.
            for item in url_items:
                item_url = item.get("url", "")
                page_data = url_page_intelligence.get(item_url)

                if page_data is not None:
                    item["page_analysis"] = (
                        page_phishing_analyzer.analyze(
                            page_data,
                            item_url,
                        )
                    )
                    # Enrich item["redirects"] with full chain discovered during inspection
                    p_redirects = page_data.get("redirects")
                    if p_redirects and isinstance(p_redirects, list) and len(p_redirects) > 0:
                        analysis = page_phishing_analyzer._analyze_redirects(p_redirects)
                        has_issues = (
                            item.get("threat_intelligence", {}).get("detections", 0) > 0
                            or item.get("dns", {}).get("private_ip_detected", False)
                            or item.get("page_analysis", {}).get("forms", {}).get("password_fields", 0) > 0
                            or item.get("page_analysis", {}).get("has_credential_form", False)
                            or item.get("page_analysis", {}).get("has_fake_error", False)
                            or (item.get("tls") and item.get("tls", {}).get("certificate_valid") is False and item.get("tls", {}).get("certificate_present") is True)
                        )
                        # Official brand resources or ESP tracking domains with clean intel are verified safe
                        is_recognized_safe = (
                            item.get("brand_relationship") in ("OFFICIAL_DOMAIN", "OFFICIAL_SUBDOMAIN", "AFFILIATED", "OFFICIAL_THIRD_PARTY")
                            or any(e.get("type") in ("OFFICIAL_THIRD_PARTY_RESOURCE", "OFFICIAL_BRAND_SUBDOMAIN", "ESP_TRACKING_DOMAIN") for e in item.get("structured_evidence", []))
                        )
                        if is_recognized_safe and item.get("threat_intelligence", {}).get("detections", 0) == 0 and not item.get("page_analysis", {}).get("has_credential_form"):
                            has_issues = False

                        item["redirects"] = {
                            "detected": True,
                            "chain": p_redirects,
                            "external_domain_change": analysis.get("multiple_domains", False),
                            "domains": analysis.get("domains", []),
                            "has_issues": has_issues,
                            "is_safe": not has_issues,
                        }
                        page_data["redirect_info"] = item["redirects"]
                    page_data["page_analysis"] = item["page_analysis"]
                else:
                    item["page_analysis"] = {
                        "available": False,
                        "indicators": [],
                        "page_risk_score": 0,
                    }

        else:
            if tracker.is_over_budget():
                tracker.record_timeout(
                    "URLPageInspection",
                    reason=(
                        "Analysis budget exceeded before page inspection"
                    ),
                )

            for item in url_items:
                item["page_analysis"] = {
                    "available": False,
                    "indicators": [],
                    "page_risk_score": 0,
                }

        existing_analysis["url_page_intelligence"] = (
            url_page_intelligence
        )

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
        logger.debug(
            "DECISION TRACE [AFTER FUSION] ARE=%s AI=%s CONFLICT=%s FUSED=%s risk=%.1f",
            are_result.get("verdict"),
            ai_analysis.get("recommended_classification"),
            conflict_result.get("verdict"),
            decision_result.get("verdict"),
            decision_result.get("risk_score", 0),
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
            "are_confidence": are_result.get("confidence", 90),
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
        logger.debug(
            "DECISION TRACE [AFTER CONSISTENCY] verdict=%s risk=%.1f confidence=%.1f",
            decision_result.get("verdict"),
            decision_result.get("risk_score", 0),
            decision_result.get("confidence", 0),
        )
        
        # Then run the deterministic safety architecture that was
        # previously only used by normalize_message_response().
        decision_result = finalize_intelligence(
            parsed,
            final_analysis,
            decision_result,
        )
        logger.debug(
            "DECISION TRACE [FINAL] verdict=%s detail=%s risk=%.1f confidence=%.1f",
            decision_result.get("verdict"),
            decision_result.get("detail_verdict"),
            decision_result.get("risk_score", 0),
            decision_result.get("confidence", 0),
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
            if exc.status_code == 401:
                session_manager.update_session(session_id, {"authenticated": False, "credentials": None})
            progress_queue.put({
                "type": "error",
                "status": exc.status_code,
                "message": str(exc.detail),
            })

        except Exception as exc:
            err_msg = str(exc).lower()
            if any(tok in err_msg for tok in ["invalid_grant", "token", "unauthorized", "expired", "401", "credentials"]):
                session_manager.update_session(session_id, {"authenticated": False, "credentials": None})
                progress_queue.put({
                    "type": "error",
                    "status": 401,
                    "message": "Gmail session expired. Please reconnect Gmail.",
                })
            else:
                import traceback
                tb = traceback.format_exc()
                logger.exception(
                    "Streaming email analysis failed for %s",
                    message_id,
                )

                progress_queue.put({
                    "type": "error",
                    "status": 500,
                    "message": f"Email analysis failed: {str(exc)}",
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


# --------------------------------------------------------------------
# Regex for validating ISO-8601 date strings: YYYY-MM-DD
# --------------------------------------------------------------------
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _gmail_date(iso_date: str) -> str:
    """Convert 'YYYY-MM-DD' to Gmail's 'YYYY/MM/DD' search format."""
    return iso_date.replace("-", "/")


@router.get("/messages")
def list_messages(
    request: Request,
    limit: int = 10,
    period: str = "recent",
    page_token: str | None = None,
    sender: str | None = None,
    subject: str | None = None,
    keyword: str | None = None,
    domain: str | None = None,
    after: str | None = None,
    before: str | None = None,
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

    # Validate preset period (fallback to "recent" if unrecognized)
    if period not in PERIOD_QUERY_MAP:
        period = "recent"

    # Clamp limit to valid bounds [1, 100]
    limit = max(1, min(100, limit))

    # ----------------------------------------------------------------
    # Build advanced server-side search query (Gmail search operators)
    # ----------------------------------------------------------------
    query_parts = []
    use_custom_query = any([sender, subject, keyword, domain, after, before])

    if use_custom_query:
        if sender:
            # Strip dangerous characters
            safe_sender = re.sub(r'[\r\n"]', "", sender).strip()
            if safe_sender:
                query_parts.append(f"from:{safe_sender}")
        if subject:
            safe_subject = re.sub(r'[\r\n"]', "", subject).strip()
            if safe_subject:
                query_parts.append(f'subject:"{safe_subject}"')
        if keyword:
            safe_kw = re.sub(r'[\r\n"]', "", keyword).strip()
            if safe_kw:
                query_parts.append(safe_kw)
        if domain:
            safe_domain = re.sub(r'[\r\n"]', "", domain).strip()
            if safe_domain:
                query_parts.append(f"from:{safe_domain} OR to:{safe_domain}")
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
    try:
        response = connector.list_messages(
            period=period,
            max_results=limit,
            page_token=page_token if page_token else None,
            query=constructed_query,
        )
    except Exception as exc:
        err_msg = str(exc).lower()
        if any(tok in err_msg for tok in ["invalid_grant", "token", "unauthorized", "expired", "401"]):
            session_manager.update_session(session_id, {"authenticated": False, "credentials": None})
            raise HTTPException(status_code=401, detail="Gmail session expired. Please reconnect Gmail.")
        logger.error(f"Failed to fetch messages from Gmail: {exc}", exc_info=True)
        raise HTTPException(status_code=502, detail=f"Gmail API error: {exc}")

    raw_messages = response.get("messages", [])
    next_page_token = response.get("next_page_token")

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
            headers = {}
            for h in meta.get("payload", {}).get("headers", []):
                headers[h["name"].lower()] = h["value"]

            # Check if this email has already been analyzed in cache
            cached_result = analysis_cache.get_by_message_id(msg_id)

            if cached_result:
                dec = cached_result.get("analysis", {}).get("decision") or cached_result.get("decision") or {}
                verdict = dec.get("verdict", "UNANALYZED")
                risk_score = dec.get("risk_score", 0)
                analysis_status = "ANALYZED"
            else:
                verdict = "UNANALYZED"
                risk_score = 0
                analysis_status = "UNANALYZED"

            # Category from cache if available, else primary
            category = "primary"
            if cached_result and cached_result.get("categories"):
                cats = cached_result["categories"]
                category = cats[0] if isinstance(cats, list) and cats else str(cats)

            results.append({
                "id": msg_id,
                "thread_id": msg.get("threadId"),
                "from": headers.get("from") or headers.get("sender") or "",
                "to": headers.get("to", ""),
                "subject": headers.get("subject") or meta.get("snippet", "")[:60] or "(No Subject)",
                "date": headers.get("date", ""),
                "snippet": meta.get("snippet", ""),
                "verdict": verdict,
                "risk_score": risk_score,
                "analysis_status": analysis_status,
                "category": category,
            })
        except Exception as meta_err:
            logger.warning(f"Failed to fetch metadata for msg {msg_id}: {meta_err}")
            results.append({
                "id": msg_id,
                "thread_id": msg.get("threadId"),
                "from": msg.get("from") or "",
                "subject": msg.get("snippet", "")[:60] or "(No Subject)",
                "date": "",
                "snippet": msg.get("snippet", ""),
                "verdict": "UNANALYZED",
                "risk_score": 0,
                "analysis_status": "UNANALYZED",
                "category": "primary",
            })

    # Optional local sort: Highest Risk first
    if results:
        try:
            results.sort(
                key=lambda m: (
                    0 if m.get("verdict") == "UNANALYZED" else 1,
                    int(m.get("risk_score") or 0)
                ),
                reverse=True
            )
        except Exception:
            pass

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
    
    try:
        return process_single_message(connector, message_id, is_batch=False)
    except HTTPException as exc:
        if exc.status_code == 401:
            session_manager.update_session(session_id, {"authenticated": False, "credentials": None})
        raise
    except Exception as exc:
        err_msg = str(exc).lower()
        if any(tok in err_msg for tok in ["invalid_grant", "token", "unauthorized", "expired", "401", "credentials"]):
            session_manager.update_session(session_id, {"authenticated": False, "credentials": None})
            raise HTTPException(status_code=401, detail="Gmail session expired. Please reconnect Gmail.")
        logger.exception("Failed to process message %s", message_id)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(exc)}")

class UnlockPDFRequest(BaseModel):
    attachment_id: str | None = None
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
    
    attachment_id = payload.attachment_id
    if not attachment_id:
        # 1. Search cached analysis attachments
        from src.services.analysis_cache import analysis_cache, get_analysis_fingerprint
        cached = analysis_cache.get_by_message_id(message_id)
        if cached and isinstance(cached, dict):
            files = (
                cached.get("analysis", {}).get("attachment", {}).get("files", [])
                or cached.get("attachments", [])
            )
            for f in files:
                if isinstance(f, dict) and f.get("attachmentId"):
                    fname = (f.get("filename") or "").lower()
                    if fname.endswith(".pdf") or f.get("is_encrypted_pdf"):
                        attachment_id = f["attachmentId"]
                        break
            if not attachment_id:
                for f in files:
                    if isinstance(f, dict) and f.get("attachmentId"):
                        attachment_id = f["attachmentId"]
                        break

        # 2. Fallback to raw Gmail message payload
        if not attachment_id:
            try:
                full_msg = connector.get_message(message_id)
                from src.connectors.gmail_parser import GmailParser
                parser = GmailParser()
                parsed_atts = parser.extract_attachments(full_msg.get("payload", {}))
                for att in parsed_atts:
                    fname = (att.get("filename") or "").lower()
                    mtype = (att.get("mimeType") or "").lower()
                    if att.get("attachmentId") and (fname.endswith(".pdf") or "pdf" in mtype):
                        attachment_id = att["attachmentId"]
                        break
                if not attachment_id and parsed_atts:
                    attachment_id = parsed_atts[0].get("attachmentId")
            except Exception as e:
                logger.warning(f"Failed to inspect message payload for attachments: {e}")

    if not attachment_id:
        raise HTTPException(
            status_code=400,
            detail="No encrypted PDF attachment found in this message to unlock."
        )

    try:
        raw_attachment = connector.get_attachment(message_id, attachment_id)
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

    # Resolve original attachment filename
    original_filename = "attachment.pdf"
    from src.services.analysis_cache import analysis_cache, get_analysis_fingerprint
    cached = analysis_cache.get_by_message_id(message_id)
    if cached and isinstance(cached, dict):
        files_to_check = (
            cached.get("analysis", {}).get("attachment", {}).get("files", [])
            or cached.get("attachments", [])
        )
        for f in files_to_check:
            if isinstance(f, dict):
                f_att_id = f.get("attachmentId")
                f_name = f.get("filename") or ""
                if f_att_id and f_att_id == attachment_id:
                    if f_name and f_name.lower().strip("'\"") != "unlocked.pdf":
                        original_filename = f_name
                        break
                elif f.get("is_encrypted_pdf") or f_name.lower().endswith(".pdf"):
                    if f_name and f_name.lower().strip("'\"") != "unlocked.pdf" and original_filename == "attachment.pdf":
                        original_filename = f_name

    if original_filename == "attachment.pdf":
        try:
            full_msg = connector.get_message(message_id)
            from src.connectors.gmail_parser import GmailParser
            parser = GmailParser()
            parsed_atts = parser.extract_attachments(full_msg.get("payload", {}))
            for att in parsed_atts:
                if att.get("attachmentId") == attachment_id and att.get("filename"):
                    original_filename = att["filename"]
                    break
        except Exception:
            pass

    analyzer = AttachmentAnalyzer()
    result = analyzer.analyze_encrypted_pdf(file_bytes, original_filename, payload.password)
    
    if result.get("status") == "INVALID_PASSWORD":
        raise HTTPException(status_code=400, detail="Incorrect password. Decryption failed.")
    elif result.get("status") == "ERROR":
        raise HTTPException(status_code=400, detail=result.get("message", "Failed to decrypt PDF."))
    elif result.get("status") != "SUCCESS" and result.get("status") != "ALREADY_DECRYPTED":
        raise HTTPException(status_code=400, detail=f"Unable to unlock PDF: {result.get('status', 'Unknown error')}")


    if result.get("status") == "SUCCESS":
        if cached and isinstance(cached, dict) and "analysis" in cached:
            analysis = cached["analysis"]
            attachments = analysis.get("attachment", {})
            
            # Remove PDF_ENCRYPTED and old unlocked.pdf evidence flags now that it's been unlocked
            if "structured_evidence" in attachments:
                attachments["structured_evidence"] = [
                    ev for ev in attachments["structured_evidence"]
                    if ev.get("type") != "PDF_ENCRYPTED"
                    and ev.get("indicator") != "PDF_ENCRYPTED"
                    and "unlocked.pdf" not in str(ev.get("explanation", "")).lower()
                ]
            if "evidence" in attachments:
                attachments["evidence"] = [
                    ev for ev in attachments["evidence"]
                    if "encrypted" not in str(ev).lower()
                    and "unlocked.pdf" not in str(ev).lower()
                ]
                
            # Merge new attachment evidence from decrypted scan
            if "structured_evidence" in attachments and result.get("structured_evidence"):
                attachments["structured_evidence"].extend(result["structured_evidence"])
            if "evidence" in attachments and result.get("evidence"):
                attachments["evidence"].extend(result["evidence"])

            # ----------------------------------------------------------------
            # Keep attachment findings strictly inside the attachment analysis
            # block (do NOT contaminate the main Links & Domains module).
            # ----------------------------------------------------------------
            new_risk = result.get("risk_score", 0)
            attachments["risk_score"] = max(
                attachments.get("risk_score", 0),
                new_risk,
            )

            # Clean out any phantom "unlocked.pdf" entries from previous runs
            raw_target_files = attachments.get("files", [])
            target_files = [
                f for f in raw_target_files
                if isinstance(f, dict) and (f.get("filename") or "").lower().strip("'\"") != "unlocked.pdf"
            ]

            matched = False
            for f in target_files:
                if isinstance(f, dict):
                    fname = (f.get("filename") or "").lower()
                    if (
                        f.get("attachmentId") == payload.attachment_id
                        or f.get("attachmentId") == attachment_id
                        or f.get("is_encrypted_pdf")
                        or (original_filename and fname == original_filename.lower())
                        or fname.endswith(".pdf")
                    ):
                        f["is_encrypted_pdf"] = False
                        f["risk_score"] = new_risk
                        f["unsafe_urls"] = result.get("unsafe_urls", [])
                        f["issues"] = result.get("issues", [])
                        f["malicious"] = result.get("malicious", False)
                        if not f.get("filename") or f.get("filename").lower().strip("'\"") == "unlocked.pdf":
                            f["filename"] = original_filename
                        matched = True
                        break

            if not matched and not target_files:
                target_files.append({
                    "filename": original_filename,
                    "attachmentId": payload.attachment_id or attachment_id,
                    "is_encrypted_pdf": False,
                    "risk_score": new_risk,
                    "unsafe_urls": result.get("unsafe_urls", []),
                    "issues": result.get("issues", []),
                    "malicious": result.get("malicious", False),
                    "mimeType": "application/pdf",
                })

            attachments["files"] = target_files

            # Also purge any phantom unlocked.pdf from top-level cached attachments
            if "attachments" in cached and isinstance(cached["attachments"], list):
                cached["attachments"] = [
                    a for a in cached["attachments"]
                    if not (isinstance(a, dict) and (a.get("filename") or "").lower().strip("'\"") == "unlocked.pdf")
                ]

            # Clean any previous PDF attachment items from url analysis so Links & Domains stays clean
            if "url" in analysis and isinstance(analysis["url"], dict):
                existing_items = analysis["url"].get("analysis", [])
                analysis["url"]["analysis"] = [
                    item for item in existing_items
                    if not (str(item.get("source", "")).lower() == "pdf attachment" or item.get("pdf_source"))
                ]
            if "urls" in analysis and isinstance(analysis["urls"], dict):
                existing_items = analysis["urls"].get("analysis", [])
                analysis["urls"]["analysis"] = [
                    item for item in existing_items
                    if not (str(item.get("source", "")).lower() == "pdf attachment" or item.get("pdf_source"))
                ]

            analysis["attachment"] = attachments
            analysis["attachments"] = attachments
            logger.info(
                "PDF unlock: updated attachment block with %d unsafe URLs (risk_score=%d)",
                len(result.get("unsafe_urls", [])),
                attachments["risk_score"],
            )
            
            # ----------------------------------------------------------------
            # Full decision pipeline re-run with enriched URL + attachment data
            # ----------------------------------------------------------------
            try:
                analyzers = get_analyzers()
                tracker = PerformanceTracker(budget_seconds=15.0)
                
                auth_analysis = analysis.get("authentication", {})
                url_analysis = analysis.get("url") or analysis.get("urls") or {}
                whois_analysis = analysis.get("whois", [])
                content_analysis = analysis.get("content", {})
                attachment_analysis = attachments
                trust_analysis = analysis.get("trust", {})
                ai_analysis = analysis.get("ai", {})
                url_page_intelligence = analysis.get("url_page_intelligence", {})
                historical_evidence = analysis.get("historical_evidence", {})
                
                are_result = safe_analyze(
                    "AnalyticalReasoningEngine", message_id,
                    analyzers["are"].evaluate, tracker,
                    auth_analysis, url_analysis, whois_analysis, content_analysis,
                    attachment_analysis, trust_analysis,
                    ai_analysis=ai_analysis,
                    url_page_intelligence=url_page_intelligence,
                    historical_evidence=historical_evidence,
                )
                
                conflict_result = safe_analyze(
                    "EvidenceConflictEngine", message_id,
                    analyzers["conflict"].evaluate, tracker,
                    cached, auth_analysis, url_analysis, whois_analysis,
                    content_analysis, attachment_analysis, trust_analysis,
                    ai_analysis, url_page_intelligence,
                )
                
                decision_result = safe_analyze(
                    "DecisionFusionEngine", message_id,
                    analyzers["decision"].evaluate, tracker,
                    are_result, conflict_result,
                )
                
                decision_result = analyzers["consistency_validator"].validate(decision_result)
                
                final_analysis = {
                    **analysis,
                    "reasoning": are_result.get("evidence", {}),
                    "are_confidence": are_result.get("confidence", 90),
                    "conflict": conflict_result,
                    "url_page_intelligence": url_page_intelligence,
                }
                
                decision_result = finalize_intelligence(cached, final_analysis, decision_result)
                
                analysis["reasoning"] = are_result.get("evidence", {})
                analysis["conflict"] = conflict_result
                analysis["decision"] = decision_result
                
                logger.info(
                    "PDF unlock re-analysis: verdict=%s risk=%.1f",
                    decision_result.get("verdict"),
                    decision_result.get("risk_score", 0),
                )
            except Exception as _re_exc:
                logger.warning(f"PDF unlock: full re-analysis failed, falling back to guard-only: {_re_exc}")
                decision_result = analysis.get("decision", {})
                from src.engines.decision_fusion_guard import enforce_deterministic_priority
                decision_result = enforce_deterministic_priority(decision_result, analysis)
                decision_result = finalize_intelligence(cached, analysis, decision_result)
                analysis["decision"] = decision_result
            
            cached["decision"] = decision_result
            
            fingerprint = get_analysis_fingerprint(cached)
            analysis_cache.set(message_id, fingerprint, cached)
            
            result["new_decision"] = decision_result
            result["message"] = cached

    return result
