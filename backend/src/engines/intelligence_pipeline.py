from __future__ import annotations

import time
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class IntelligencePipeline:
    """
    Central orchestration layer for TunaMail intelligence.

    Existing analyzers remain authoritative.
    Local AI is evidence only.
    No external LLM/API is required.
    """

    def __init__(
        self,
        authentication_analyzer=None,
        content_analyzer=None,
        url_analyzer=None,
        whois_analyzer=None,
        attachment_analyzer=None,
        trust_analyzer=None,
        ai_orchestrator=None,
        are=None,
        decision_engine=None,
    ):
        self.authentication_analyzer = authentication_analyzer
        self.content_analyzer = content_analyzer
        self.url_analyzer = url_analyzer
        self.whois_analyzer = whois_analyzer
        self.attachment_analyzer = attachment_analyzer
        self.trust_analyzer = trust_analyzer
        self.ai_orchestrator = ai_orchestrator
        self.are = are
        self.decision_engine = decision_engine

    def _run(self, name: str, func, *args, **kwargs):
        started = time.perf_counter()

        try:
            result = func(*args, **kwargs)

            duration = round(
                (time.perf_counter() - started) * 1000,
                2,
            )

            if isinstance(result, dict):
                result["analysis_status"] = "AVAILABLE"

            return result, {
                "analyzer": name,
                "status": "COMPLETED",
                "duration_ms": duration,
                "error": None,
            }

        except Exception:
            duration = round(
                (time.perf_counter() - started) * 1000,
                2,
            )

            logger.exception("%s failed", name)

            return {"analysis_status": "UNAVAILABLE"}, {
                "analyzer": name,
                "status": "FAILED",
                "duration_ms": duration,
                "error": "Analyzer unavailable",
            }

    def analyze_email(self, parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        start_time = time.perf_counter()

        analysis: Dict[str, Any] = {}
        pipeline: List[Dict[str, Any]] = []

        body = parsed_email.get("body") or ""
        sender = parsed_email.get("from") or ""
        headers = parsed_email.get("headers") or {}
        attachments = parsed_email.get("attachments") or []

        # ----------------------------------------------------
        # Authentication
        # ----------------------------------------------------

        if self.authentication_analyzer:

            result, trace = self._run(
                "AuthenticationAnalyzer",
                self.authentication_analyzer.analyze,
                headers,
            )

            analysis["authentication"] = result or {}
            pipeline.append(trace)

        # ----------------------------------------------------
        # Content
        # ----------------------------------------------------

        if self.content_analyzer:

            result, trace = self._run(
                "ContentAnalyzer",
                self.content_analyzer.analyze,
                body=body,
                sender=sender,
            )

            analysis["content"] = result or {}
            pipeline.append(trace)

        # ----------------------------------------------------
        # URL
        # ----------------------------------------------------

        if self.url_analyzer:

            result, trace = self._run(
                "URLAnalyzer",
                self.url_analyzer.analyze,
                body=body,
                headers=headers,
            )

            analysis["urls"] = result or {}
            pipeline.append(trace)

        # ----------------------------------------------------
        # WHOIS
        # ----------------------------------------------------

        if self.whois_analyzer:

            result, trace = self._run(
                "WhoisAnalyzer",
                self.whois_analyzer.analyze,
                analysis.get("urls", {}),
            )

            analysis["whois"] = result or {}
            pipeline.append(trace)

        # ----------------------------------------------------
        # Attachments
        # ----------------------------------------------------

        if self.attachment_analyzer:

            result, trace = self._run(
                "AttachmentAnalyzer",
                self.attachment_analyzer.analyze,
                attachments,
            )

            analysis["attachments"] = result or {}
            pipeline.append(trace)

        # ----------------------------------------------------
        # Trust / Reputation
        # ----------------------------------------------------

        if self.trust_analyzer:

            result, trace = self._run(
                "TrustAnalyzer",
                self.trust_analyzer.analyze,
                parsed_email,
                analysis,
            )

            analysis["trust"] = result or {}
            pipeline.append(trace)

        # ----------------------------------------------------
        # Local AI
        # ----------------------------------------------------

        ai_result = {}

        if self.ai_orchestrator:

            ai_result, trace = self._run(
                "LocalAI",
                self.ai_orchestrator,
                parsed_email,
                analysis,
            )

            analysis["ai"] = ai_result or {}
            pipeline.append(trace)

        # ----------------------------------------------------
        # ARE
        # ----------------------------------------------------

        are_result = {}

        if self.are:

            are_result, trace = self._run(
                "AnalyticalReasoningEngine",
                self.are.evaluate,
                analysis,
                ai_result,
            )

            analysis["reasoning"] = are_result or {}
            pipeline.append(trace)

        # ----------------------------------------------------
        # Decision Fusion
        # ----------------------------------------------------

        decision = {}

        if self.decision_engine:

            decision, trace = self._run(
                "DecisionFusionEngine",
                self.decision_engine.evaluate,
                analysis,
            )

            pipeline.append(trace)

        total_duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        analysis["pipeline"] = {
            "status": self._pipeline_status(pipeline),
            "total_duration_ms": total_duration_ms,
            "analyzers": pipeline,
        }

        return {
            "analysis": analysis,
            "decision": self._normalize_decision(decision),
        }

    @staticmethod
    def _pipeline_status(trace):

        statuses = {item["status"] for item in trace}

        if "FAILED" in statuses:
            return "PARTIAL"

        if "COMPLETED" in statuses:
            return "COMPLETED"

        return "UNAVAILABLE"

    @staticmethod
    def _normalize_decision(decision):

        decision = decision or {}

        risk = decision.get("risk_score", 0)
        confidence = decision.get("confidence", 0)

        try:
            risk = max(0, min(100, int(risk)))
        except (ValueError, TypeError):
            risk = 0

        try:
            confidence = max(0, min(100, int(confidence)))
        except (ValueError, TypeError):
            confidence = 0

        decision["risk_score"] = risk
        decision["confidence"] = confidence

        return decision

    def analyze_batch(self, messages):

        return [
            self.analyze_email(message)
            for message in messages
        ]

    def normalize_analysis(self, analysis):

        if not isinstance(analysis, dict):
            return {}

        return analysis

    def validate_analysis(self, analysis):

        return isinstance(analysis, dict)

    def build_evidence_summary(self, analysis):

        evidence = []

        def walk(value):

            if isinstance(value, dict):

                if "explanation" in value:
                    evidence.append(value)

                for child in value.values():
                    walk(child)

            elif isinstance(value, list):

                for child in value:
                    walk(child)

        walk(analysis)

        return evidence

    def generate_final_decision(self, analysis):

        if self.decision_engine:

            return self.decision_engine.evaluate(analysis)

        return {
            "risk_score": 0,
            "confidence": 0,
            "verdict": "UNKNOWN",
            "detail_verdict": "INSUFFICIENT_EVIDENCE",
        }

# ============================================================
# STAGE 11 FINAL PIPELINE ORDER
# ============================================================

PIPELINE_ORDER = [
    "GmailParser",
    "AuthenticationAnalyzer",
    "ContentAnalyzer",
    "URLAnalyzer",
    "WhoisAnalyzer",
    "AttachmentAnalyzer",
    "TrustAnalyzer",
    "SenderReputation",
    "DomainReputation",
    "TemporalAnalyzer",
    "CampaignDetector",
    "BehavioralAnalyzer",
    "AdversarialAnalyzer",
    "BrandIntelligence",
    "ContradictionEngine",
    "LocalAI",
    "EvidenceIntegrityValidator",
    "EvidenceDeduplicator",
    "ARE",
    "DecisionFusionEngine",
    "DecisionValidator",
]

# ============================================================
# STAGE 11 SECURITY INVARIANTS
# ============================================================

SECURITY_INVARIANTS = {
    "external_llm_required": False,
    "external_ai_api_required": False,
    "ai_can_override_deterministic": False,
    "reputation_can_override_deterministic": False,
    "link_only_can_be_automatically_safe": False,
    "empty_email_can_be_automatically_safe": False,
    "unknown_is_valid_verdict": True,
    "risk_score_min": 0,
    "risk_score_max": 100,
    "confidence_min": 0,
    "confidence_max": 100,
    "soc_investigate_tab": False,
}