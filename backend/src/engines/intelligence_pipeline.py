# ============================================================
# backend/src/engines/intelligence_pipeline.py
# ============================================================

from __future__ import annotations

import inspect
import logging
import time
from typing import Any, Callable, Dict, List, Optional


logger = logging.getLogger(__name__)


class IntelligencePipeline:
    """
    Central orchestration layer for TunaMail intelligence.

    Pipeline principles:
    - Deterministic analyzers run before Local AI.
    - EvidenceConflictEngine runs before ARE when available.
    - Local AI is evidence only.
    - Historical evidence is supporting context only.
    - DecisionFusionEngine consumes ARE output.
    - Deterministic guards run after fusion.
    - DecisionValidator performs final schema/consistency normalization.
    - No external LLM/API is required.
    - Analyzer failures are isolated and never crash the whole pipeline.
    """

    PIPELINE_ORDER = [
        "GmailParser",
        "AuthenticationAnalyzer",
        "ContentAnalyzer",
        "URLAnalyzer",
        "WhoisAnalyzer",
        "AttachmentAnalyzer",
        "TrustAnalyzer",
        "EvidenceConflictEngine",
        "LocalAI",
        "ARE",
        "DecisionFusionEngine",
        "DecisionFusionGuard",
        "DecisionValidator",
    ]

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

    def __init__(
        self,
        authentication_analyzer=None,
        content_analyzer=None,
        url_analyzer=None,
        whois_analyzer=None,
        attachment_analyzer=None,
        trust_analyzer=None,
        evidence_conflict_engine=None,
        ai_orchestrator=None,
        are=None,
        decision_engine=None,
        decision_guard=None,
        decision_validator=None,
        historical_provider=None,
        url_page_intelligence_provider=None,
    ):
        self.authentication_analyzer = authentication_analyzer
        self.content_analyzer = content_analyzer
        self.url_analyzer = url_analyzer
        self.whois_analyzer = whois_analyzer
        self.attachment_analyzer = attachment_analyzer
        self.trust_analyzer = trust_analyzer

        self.evidence_conflict_engine = (
            evidence_conflict_engine
        )

        self.ai_orchestrator = ai_orchestrator
        self.are = are
        self.decision_engine = decision_engine

        self.decision_guard = decision_guard
        self.decision_validator = (
            decision_validator
        )

        self.historical_provider = (
            historical_provider
        )

        self.url_page_intelligence_provider = (
            url_page_intelligence_provider
        )

    # ========================================================
    # Generic analyzer runner
    # ========================================================

    def _run(
        self,
        name: str,
        func: Optional[Callable],
        *args,
        **kwargs,
    ):
        started = time.perf_counter()

        if not callable(func):
            return (
                {
                    "analysis_status": "UNAVAILABLE"
                },
                {
                    "analyzer": name,
                    "status": "FAILED",
                    "duration_ms": 0,
                    "error": "Analyzer not configured",
                },
            )

        try:
            result = func(
                *args,
                **kwargs,
            )

            duration = round(
                (
                    time.perf_counter()
                    - started
                )
                * 1000,
                2,
            )

            if result is None:
                result = {}

            if isinstance(result, dict):
                result.setdefault(
                    "analysis_status",
                    "AVAILABLE",
                )

            return (
                result,
                {
                    "analyzer": name,
                    "status": "COMPLETED",
                    "duration_ms": duration,
                    "error": None,
                },
            )

        except Exception as exc:
            duration = round(
                (
                    time.perf_counter()
                    - started
                )
                * 1000,
                2,
            )

            logger.exception(
                "%s failed",
                name,
            )

            return (
                {
                    "analysis_status": "UNAVAILABLE",
                    "error": "Analyzer unavailable",
                },
                {
                    "analyzer": name,
                    "status": "FAILED",
                    "duration_ms": duration,
                    "error": str(exc),
                },
            )

    # ========================================================
    # Flexible callable helper
    # ========================================================

    @staticmethod
    def _call_flexible(
        target,
        positional_args=None,
        keyword_args=None,
    ):
        """
        Calls a component while tolerating different signatures
        used across previous TunaMail stages.

        This keeps the pipeline compatible with:
            analyze(data)
            analyze(body=..., headers=...)
            evaluate(...)
        """

        if target is None:
            raise ValueError(
                "Target component is not configured"
            )

        positional_args = (
            positional_args
            if positional_args is not None
            else []
        )

        keyword_args = (
            keyword_args
            if keyword_args is not None
            else {}
        )

        callable_target = target

        signature_target = callable_target

        if not callable(callable_target):
            raise TypeError(
                "Configured component is not callable"
            )

        try:
            signature = inspect.signature(
                signature_target
            )
        except (TypeError, ValueError):
            return callable_target(
                *positional_args,
                **keyword_args,
            )

        parameters = signature.parameters

        accepts_kwargs = any(
            parameter.kind
            == inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values()
        )

        accepts_varargs = any(
            parameter.kind
            == inspect.Parameter.VAR_POSITIONAL
            for parameter in parameters.values()
        )

        if accepts_kwargs:
            filtered_kwargs = keyword_args
        else:
            filtered_kwargs = {
                key: value
                for key, value in keyword_args.items()
                if key in parameters
            }

        if accepts_varargs:
            return callable_target(
                *positional_args,
                **filtered_kwargs,
            )

        allowed_positional_count = sum(
            1
            for parameter in parameters.values()
            if parameter.kind
            in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        )

        positional_args = positional_args[
            :allowed_positional_count
        ]

        return callable_target(
            *positional_args,
            **filtered_kwargs,
        )

    # ========================================================
    # Main email analysis
    # ========================================================

    def analyze_email(
        self,
        parsed_email: Dict[str, Any],
    ) -> Dict[str, Any]:
        start_time = time.perf_counter()

        parsed_email = (
            parsed_email
            if isinstance(
                parsed_email,
                dict,
            )
            else {}
        )

        analysis: Dict[str, Any] = {}
        pipeline: List[Dict[str, Any]] = []

        body = parsed_email.get(
            "body"
        ) or ""

        sender = (
            parsed_email.get(
                "from"
            )
            or parsed_email.get(
                "sender"
            )
            or ""
        )

        headers = (
            parsed_email.get(
                "headers"
            )
            or {}
        )

        attachments = (
            parsed_email.get(
                "attachments"
            )
            or []
        )

        message_id = (
            parsed_email.get(
                "id"
            )
            or parsed_email.get(
                "message_id"
            )
        )

        # ----------------------------------------------------
        # Authentication
        # ----------------------------------------------------

        if self.authentication_analyzer:

            result, trace = self._run(
                "AuthenticationAnalyzer",
                getattr(
                    self.authentication_analyzer,
                    "analyze",
                    self.authentication_analyzer,
                ),
                headers,
            )

            analysis[
                "authentication"
            ] = result or {}

            pipeline.append(trace)

        else:
            analysis[
                "authentication"
            ] = {
                "analysis_status": "UNAVAILABLE"
            }

        # ----------------------------------------------------
        # Content
        # ----------------------------------------------------

        if self.content_analyzer:

            result, trace = self._run(
                "ContentAnalyzer",
                getattr(
                    self.content_analyzer,
                    "analyze",
                    self.content_analyzer,
                ),
                body=body,
                sender=sender,
            )

            analysis[
                "content"
            ] = result or {}

            pipeline.append(trace)

        else:
            analysis[
                "content"
            ] = {
                "analysis_status": "UNAVAILABLE"
            }

                # ----------------------------------------------------
        # URL
        # ----------------------------------------------------

        if self.url_analyzer:

            url_callable = getattr(
                self.url_analyzer,
                "analyze",
                self.url_analyzer,
            )

            result, trace = self._run(
                "URLAnalyzer",
                self._call_flexible,
                positional_args=[
                    url_callable,
                ],
                keyword_args={
                    "positional_args": [
                        body,
                    ],
                    "keyword_args": {
                        "body": body,
                        "headers": headers,
                    },
                },
            )

            analysis[
                "urls"
            ] = result or {}

            pipeline.append(trace)

        else:
            analysis[
                "urls"
            ] = {
                "analysis_status": "UNAVAILABLE",
                "analysis": [],
            }
               # ----------------------------------------------------
        # WHOIS
        # ----------------------------------------------------

        if self.whois_analyzer:

            whois_callable = getattr(
                self.whois_analyzer,
                "analyze",
                self.whois_analyzer,
            )

            url_analysis = analysis.get(
                "urls",
                {},
            )

            whois_domains = []

            if isinstance(
                url_analysis,
                dict,
            ):

                url_items = (
                    url_analysis.get(
                        "analysis",
                        [],
                    )
                    or []
                )

                if isinstance(
                    url_items,
                    list,
                ):

                    for item in url_items:

                        if not isinstance(
                            item,
                            dict,
                        ):
                            continue

                        domain = (
                            item.get(
                                "domain"
                            )
                            or item.get(
                                "url"
                            )
                        )

                        if domain:
                            whois_domains.append(
                                domain
                            )

            elif isinstance(
                url_analysis,
                list,
            ):

                for item in url_analysis:

                    if not isinstance(
                        item,
                        dict,
                    ):
                        continue

                    domain = (
                        item.get(
                            "domain"
                        )
                        or item.get(
                            "url"
                        )
                    )

                    if domain:
                        whois_domains.append(
                            domain
                        )

            whois_results = []

            seen_domains = set()

            for domain in whois_domains:

                domain_key = str(
                    domain
                ).strip().lower()

                if not domain_key:
                    continue

                if domain_key in seen_domains:
                    continue

                seen_domains.add(
                    domain_key
                )

                result, trace = self._run(
                    "WhoisAnalyzer",
                    whois_callable,
                    domain,
                )

                if isinstance(
                    result,
                    dict,
                ):
                    whois_results.append(
                        result
                    )

                pipeline.append(trace)

            analysis[
                "whois"
            ] = {
                "analysis_status": (
                    "AVAILABLE"
                    if whois_results
                    else "UNAVAILABLE"
                ),
                "analysis": whois_results,
            }

        else:
            analysis[
                "whois"
            ] = {
                "analysis_status": "UNAVAILABLE",
                "analysis": [],
            }
        # ----------------------------------------------------
        # Attachments
        # ----------------------------------------------------

        if self.attachment_analyzer:

            result, trace = self._run(
                "AttachmentAnalyzer",
                getattr(
                    self.attachment_analyzer,
                    "analyze",
                    self.attachment_analyzer,
                ),
                attachments,
            )

            analysis[
                "attachments"
            ] = result or {}

            pipeline.append(trace)

        else:
            analysis[
                "attachments"
            ] = {
                "analysis_status": "UNAVAILABLE"
            }

        # ----------------------------------------------------
        # Trust / reputation
        # ----------------------------------------------------

        if self.trust_analyzer:

            result, trace = self._run(
                "TrustAnalyzer",
                getattr(
                    self.trust_analyzer,
                    "analyze",
                    self.trust_analyzer,
                ),
                parsed_email,
                analysis,
            )

            analysis[
                "trust"
            ] = result or {}

            pipeline.append(trace)

        else:
            analysis[
                "trust"
            ] = {
                "analysis_status": "UNAVAILABLE",
                "trust_score": 0,
            }

        # ----------------------------------------------------
        # Deep URL page intelligence
        # ----------------------------------------------------

        if (
            self.url_page_intelligence_provider
        ):

            result, trace = self._run(
                "URLPageIntelligence",
                self.url_page_intelligence_provider,
                parsed_email,
                analysis,
            )

            analysis[
                "url_page_intelligence"
            ] = result or {}

            pipeline.append(trace)

        else:
            analysis[
                "url_page_intelligence"
            ] = {}

        # ----------------------------------------------------
        # Historical evidence
        # ----------------------------------------------------

        historical_evidence = {}

        if self.historical_provider:

            try:

                historical_callable = getattr(
                    self.historical_provider,
                    "get",
                    self.historical_provider,
                )

                historical_evidence = (
                    historical_callable(
                        parsed_email,
                        analysis,
                    )
                    or {}
                )

            except Exception:

                logger.exception(
                    "Historical evidence provider failed"
                )

                historical_evidence = {
                    "status": "UNAVAILABLE"
                }

        analysis[
            "historical_evidence"
        ] = historical_evidence

        # ----------------------------------------------------
        # Evidence Conflict Engine
        #
        # Runs before Local AI so the Local AI receives the
        # deterministic context already assembled.
        # ----------------------------------------------------

        conflict_result = {}

        if self.evidence_conflict_engine:

            result, trace = self._run(
                "EvidenceConflictEngine",
                getattr(
                    self.evidence_conflict_engine,
                    "evaluate",
                    self.evidence_conflict_engine,
                ),
                parsed_email,
                analysis.get(
                    "authentication",
                    {},
                ),
                analysis.get(
                    "urls",
                    {},
                ),
                analysis.get(
                    "whois",
                    [],
                ),
                analysis.get(
                    "content",
                    {},
                ),
                analysis.get(
                    "attachments",
                    {},
                ),
                analysis.get(
                    "trust",
                    {},
                ),
                {},
                analysis.get(
                    "url_page_intelligence",
                    {},
                ),
                historical_evidence,
            )

            conflict_result = (
                result or {}
            )

            analysis[
                "conflict_engine"
            ] = conflict_result

            pipeline.append(trace)

        # ----------------------------------------------------
        # Local AI
        # ----------------------------------------------------

        ai_result = {}

        if self.ai_orchestrator:

            result, trace = self._run(
                "LocalAI",
                self.ai_orchestrator,
                parsed_email,
                analysis,
            )

            ai_result = (
                result or {}
            )

            analysis[
                "ai"
            ] = ai_result

            pipeline.append(trace)

        else:

            analysis[
                "ai"
            ] = {}

        # ----------------------------------------------------
        # Evidence Conflict Engine second pass
        #
        # Needed because AI-dependent contradictions such as:
        #   AI SAFE + malicious URL
        #   AI PHISHING + no malicious evidence
        # can only be evaluated after Local AI exists.
        # ----------------------------------------------------

        if self.evidence_conflict_engine:

            result, trace = self._run(
                "EvidenceConflictEngineFinal",
                getattr(
                    self.evidence_conflict_engine,
                    "evaluate",
                    self.evidence_conflict_engine,
                ),
                parsed_email,
                analysis.get(
                    "authentication",
                    {},
                ),
                analysis.get(
                    "urls",
                    {},
                ),
                analysis.get(
                    "whois",
                    [],
                ),
                analysis.get(
                    "content",
                    {},
                ),
                analysis.get(
                    "attachments",
                    {},
                ),
                analysis.get(
                    "trust",
                    {},
                ),
                ai_result,
                analysis.get(
                    "url_page_intelligence",
                    {},
                ),
                historical_evidence,
            )

            conflict_result = (
                result or conflict_result
            )

            analysis[
                "conflict_engine"
            ] = conflict_result

            pipeline.append(trace)

        # ----------------------------------------------------
        # Merge conflict evidence into a normalized structure
        # ----------------------------------------------------

        if conflict_result:

            existing_structured = (
                analysis.get(
                    "structured_evidence",
                    [],
                )
                or []
            )

            conflict_structured = (
                conflict_result.get(
                    "structured_evidence",
                    [],
                )
                or []
            )

            analysis[
                "structured_evidence"
            ] = self._deduplicate_evidence(
                existing_structured
                + conflict_structured
            )

            analysis[
                "contradictions"
            ] = (
                conflict_result.get(
                    "contradictions",
                    [],
                )
                or []
            )

            analysis[
                "conflict_state"
            ] = conflict_result.get(
                "conflict_state",
                "UNKNOWN",
            )

        # ----------------------------------------------------
        # Attach structured evidence generated by Local AI
        # ----------------------------------------------------

        ai_structured = (
            ai_result.get(
                "structured_evidence",
                [],
            )
            if isinstance(
                ai_result,
                dict,
            )
            else []
        )

        if ai_structured:

            current = (
                analysis.get(
                    "structured_evidence",
                    [],
                )
                or []
            )

            analysis[
                "structured_evidence"
            ] = self._deduplicate_evidence(
                current + ai_structured
            )

        # ----------------------------------------------------
        # ARE
        # ----------------------------------------------------

        are_result = {}

        if self.are:

            are_callable = getattr(
                self.are,
                "evaluate",
                self.are,
            )

            are_arguments = {
                "authentication": analysis.get(
                    "authentication",
                    {},
                ),
                "url_analysis": analysis.get(
                    "urls",
                    {},
                ),
                "whois_analysis": analysis.get(
                    "whois",
                    [],
                ),
                "content_analysis": analysis.get(
                    "content",
                    {},
                ),
                "attachment_analysis": analysis.get(
                    "attachments",
                    {},
                ),
                "trust_analysis": analysis.get(
                    "trust",
                    {},
                ),
                "ai_analysis": ai_result,
                "url_page_intelligence": analysis.get(
                    "url_page_intelligence",
                    {},
                ),
                "historical_evidence": historical_evidence,
            }

            # Also prepare a compact fallback signature for older
            # ARE implementations.
            legacy_arguments = [
                analysis,
                ai_result,
            ]

            result, trace = self._run_flexible_evaluate(
                "AnalyticalReasoningEngine",
                are_callable,
                are_arguments,
                legacy_arguments,
            )

            are_result = (
                result or {}
            )

            analysis[
                "reasoning"
            ] = are_result

            pipeline.append(trace)

        else:

            analysis[
                "reasoning"
            ] = {
                "risk_score": 0,
                "confidence": 0,
                "verdict": "UNKNOWN",
                "detail_verdict": (
                    "INSUFFICIENT_EVIDENCE"
                ),
            }

        # ----------------------------------------------------
        # Preserve structured evidence into ARE result
        # ----------------------------------------------------

        if isinstance(
            are_result,
            dict,
        ):

            merged_evidence = self._deduplicate_evidence(
                (
                    are_result.get(
                        "structured_evidence",
                        [],
                    )
                    or []
                )
                + (
                    analysis.get(
                        "structured_evidence",
                        [],
                    )
                    or []
                )
            )

            are_result[
                "structured_evidence"
            ] = merged_evidence

            analysis[
                "reasoning"
            ] = are_result

        # ----------------------------------------------------
        # Decision Fusion
        # ----------------------------------------------------

        decision = {}

        if self.decision_engine:

            decision_callable = getattr(
                self.decision_engine,
                "evaluate",
                self.decision_engine,
            )

            fusion_arguments = {
                "are_result": are_result,
                "conflict_result": conflict_result,
                "evidence_graph": analysis,
            }

            legacy_fusion_arguments = [
                are_result,
                conflict_result,
            ]

            result, trace = self._run_flexible_evaluate(
                "DecisionFusionEngine",
                decision_callable,
                fusion_arguments,
                legacy_fusion_arguments,
            )

            decision = (
                result or {}
            )

            pipeline.append(trace)

        else:

            decision = self._fallback_decision(
                are_result
            )

        # ----------------------------------------------------
        # Pass trusted sender signal through
        # ----------------------------------------------------

        if isinstance(
            are_result,
            dict,
        ):
            if (
                "is_trusted_sender"
                not in decision
            ):
                decision[
                    "is_trusted_sender"
                ] = bool(
                    are_result.get(
                        "is_trusted_sender",
                        False,
                    )
                )

        # ----------------------------------------------------
        # Decision deterministic guard
        # ----------------------------------------------------

        if self.decision_guard:

            guard_callable = (
                getattr(
                    self.decision_guard,
                    "enforce_deterministic_priority",
                    None,
                )
                or getattr(
                    self.decision_guard,
                    "enforce",
                    None,
                )
                or self.decision_guard
            )

            result, trace = self._run_flexible_guard(
                "DecisionFusionGuard",
                guard_callable,
                decision,
                analysis,
            )

            decision = (
                result or decision
            )

            pipeline.append(trace)

            # Optional insufficient-context guard.
            insufficient_guard = getattr(
                self.decision_guard,
                "enforce_unknown_when_insufficient",
                None,
            )

            if insufficient_guard:

                result, trace = self._run(
                    "DecisionFusionContextGuard",
                    insufficient_guard,
                    decision,
                    analysis,
                )

                decision = (
                    result or decision
                )

                pipeline.append(trace)

        # ----------------------------------------------------
        # Decision Validator
        # ----------------------------------------------------

        if self.decision_validator:

            validator_callable = getattr(
                self.decision_validator,
                "validate",
                self.decision_validator,
            )

            result, trace = self._run(
                "DecisionValidator",
                validator_callable,
                decision,
            )

            decision = (
                result or decision
            )

            pipeline.append(trace)

        # ----------------------------------------------------
        # Final normalization
        # ----------------------------------------------------

        decision = self._normalize_decision(
            decision
        )

        analysis[
            "final_decision"
        ] = decision

        # ----------------------------------------------------
        # Pipeline metadata
        # ----------------------------------------------------

        total_duration_ms = round(
            (
                time.perf_counter()
                - start_time
            )
            * 1000,
            2,
        )

        analysis[
            "pipeline"
        ] = {
            "status": self._pipeline_status(
                pipeline
            ),
            "total_duration_ms": total_duration_ms,
            "analyzers": pipeline,
            "order": [
                item["analyzer"]
                for item in pipeline
            ],
        }

        # ----------------------------------------------------
        # Output
        # ----------------------------------------------------

        return {
            "message_id": message_id,
            "analysis": analysis,
            "decision": decision,
        }

    # ========================================================
    # Flexible ARE executor
    # ========================================================

    def _run_flexible_evaluate(
        self,
        name: str,
        callable_target,
        keyword_arguments: Dict[str, Any],
        legacy_arguments: List[Any],
    ):
        started = time.perf_counter()

        try:

            result = self._call_component(
                callable_target,
                keyword_arguments,
                legacy_arguments,
            )

            duration = round(
                (
                    time.perf_counter()
                    - started
                )
                * 1000,
                2,
            )

            return (
                result or {},
                {
                    "analyzer": name,
                    "status": "COMPLETED",
                    "duration_ms": duration,
                    "error": None,
                },
            )

        except Exception as exc:

            duration = round(
                (
                    time.perf_counter()
                    - started
                )
                * 1000,
                2,
            )

            logger.exception(
                "%s failed",
                name,
            )

            return (
                {
                    "analysis_status": "UNAVAILABLE",
                    "risk_score": 0,
                    "confidence": 0,
                    "verdict": "UNKNOWN",
                    "detail_verdict": (
                        "INSUFFICIENT_EVIDENCE"
                    ),
                },
                {
                    "analyzer": name,
                    "status": "FAILED",
                    "duration_ms": duration,
                    "error": str(exc),
                },
            )

    # ========================================================
    # Flexible guard executor
    # ========================================================

    def _run_flexible_guard(
        self,
        name: str,
        callable_target,
        decision: Dict[str, Any],
        analysis: Dict[str, Any],
    ):
        started = time.perf_counter()

        try:

            signature_target = callable_target

            try:
                signature = inspect.signature(
                    signature_target
                )
                parameters = signature.parameters
            except (
                TypeError,
                ValueError,
            ):
                parameters = {}

            if len(parameters) >= 2:
                result = callable_target(
                    decision,
                    analysis,
                )

            else:
                result = callable_target(
                    decision
                )

            duration = round(
                (
                    time.perf_counter()
                    - started
                )
                * 1000,
                2,
            )

            return (
                result or decision,
                {
                    "analyzer": name,
                    "status": "COMPLETED",
                    "duration_ms": duration,
                    "error": None,
                },
            )

        except Exception as exc:

            duration = round(
                (
                    time.perf_counter()
                    - started
                )
                * 1000,
                2,
            )

            logger.exception(
                "%s failed",
                name,
            )

            return (
                decision,
                {
                    "analyzer": name,
                    "status": "FAILED",
                    "duration_ms": duration,
                    "error": str(exc),
                },
            )

    # ========================================================
    # Component caller
    # ========================================================

    def _call_component(
        self,
        callable_target,
        keyword_arguments,
        legacy_arguments,
    ):
        if callable_target is None:
            raise ValueError(
                "Component is not configured"
            )

        if not callable(
            callable_target
        ):
            raise TypeError(
                "Component is not callable"
            )

        try:
            signature = inspect.signature(
                callable_target
            )
        except (
            TypeError,
            ValueError,
        ):
            return callable_target(
                *legacy_arguments
            )

        parameters = signature.parameters

        # ----------------------------------------------------
        # VAR_KWARGS
        # ----------------------------------------------------

        accepts_kwargs = any(
            parameter.kind
            == inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values()
        )

        if accepts_kwargs:

            return callable_target(
                **keyword_arguments
            )

        # ----------------------------------------------------
        # Filter named parameters
        # ----------------------------------------------------

        filtered_kwargs = {
            key: value
            for key, value in keyword_arguments.items()
            if key in parameters
        }

        required_parameters = [
            parameter
            for parameter in parameters.values()
            if parameter.default
            == inspect.Parameter.empty
            and parameter.kind
            in {
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            }
        ]

        if all(
            parameter.name
            in filtered_kwargs
            for parameter in required_parameters
        ):

            return callable_target(
                **filtered_kwargs
            )

        # ----------------------------------------------------
        # Fallback to legacy positional signature
        # ----------------------------------------------------

        positional_parameters = [
            parameter
            for parameter in parameters.values()
            if parameter.kind
            in {
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            }
        ]

        if len(positional_parameters) <= len(
            legacy_arguments
        ):

            return callable_target(
                *legacy_arguments[
                    :len(
                        positional_parameters
                    )
                ]
            )

        # ----------------------------------------------------
        # Last resort: filtered kwargs
        # ----------------------------------------------------

        return callable_target(
            **filtered_kwargs
        )

    # ========================================================
    # Batch analysis
    # ========================================================

    def analyze_batch(
        self,
        messages,
    ):
        results = []

        for message in (
            messages or []
        ):
            try:
                results.append(
                    self.analyze_email(
                        message
                    )
                )
            except Exception as exc:
                logger.exception(
                    "Batch analysis item failed"
                )

                results.append({
                    "message_id": (
                        message.get("id")
                        if isinstance(
                            message,
                            dict,
                        )
                        else None
                    ),
                    "analysis": {
                        "pipeline": {
                            "status": "FAILED",
                            "analyzers": [],
                            "total_duration_ms": 0,
                        }
                    },
                    "decision": self._fallback_decision(
                        {}
                    ),
                    "error": str(exc),
                })

        return results

    # ========================================================
    # Evidence deduplication
    # ========================================================

    @staticmethod
    def _deduplicate_evidence(
        evidence,
    ):
        if not isinstance(
            evidence,
            list,
        ):
            return []

        output = []
        seen = set()

        for item in evidence:

            if not isinstance(
                item,
                dict,
            ):
                continue

            key = (
                str(
                    item.get(
                        "type",
                        "",
                    )
                ),
                str(
                    item.get(
                        "severity",
                        "",
                    )
                ),
                str(
                    item.get(
                        "direction",
                        item.get(
                            "supports",
                            "",
                        ),
                    )
                ),
                str(
                    item.get(
                        "source",
                        "",
                    )
                ),
                str(
                    item.get(
                        "explanation",
                        "",
                    )
                ),
            )

            if key in seen:
                continue

            seen.add(key)
            output.append(
                item
            )

        return output

    # ========================================================
    # Pipeline status
    # ========================================================

    @staticmethod
    def _pipeline_status(
        trace,
    ):
        if not trace:
            return "UNAVAILABLE"

        statuses = {
            item.get(
                "status"
            )
            for item in trace
        }

        if (
            "FAILED" in statuses
            and "COMPLETED" in statuses
        ):
            return "PARTIAL"

        if "FAILED" in statuses:
            return "FAILED"

        if "COMPLETED" in statuses:
            return "COMPLETED"

        return "UNAVAILABLE"

    # ========================================================
    # Decision normalization
    # ========================================================

    @staticmethod
    def _normalize_decision(
        decision,
    ):
        decision = dict(
            decision or {}
        )

        risk = decision.get(
            "risk_score",
            0,
        )

        confidence = decision.get(
            "confidence",
            0,
        )

        try:
            risk = max(
                0,
                min(
                    100,
                    int(
                        round(
                            float(
                                risk
                            )
                        )
                    ),
                ),
            )
        except (
            ValueError,
            TypeError,
        ):
            risk = 0

        try:
            confidence = max(
                0,
                min(
                    100,
                    int(
                        round(
                            float(
                                confidence
                            )
                        )
                    ),
                ),
            )
        except (
            ValueError,
            TypeError,
        ):
            confidence = 0

        verdict = str(
            decision.get(
                "verdict",
                "UNKNOWN",
            )
        ).strip().upper()

        allowed_verdicts = {
            "SAFE",
            "VERIFIED LEGITIMATE",
            "LIKELY LEGITIMATE",
            "LOW RISK",
            "SUSPICIOUS",
            "HIGH RISK",
            "PHISHING",
            "UNKNOWN",
        }

        if verdict not in allowed_verdicts:
            verdict = "UNKNOWN"

        detail = str(
            decision.get(
                "detail_verdict",
                "INSUFFICIENT_EVIDENCE",
            )
        ).strip().upper()

        decision[
            "risk_score"
        ] = risk

        decision[
            "confidence"
        ] = confidence

        decision[
            "verdict"
        ] = verdict

        decision[
            "detail_verdict"
        ] = detail

        if not decision.get(
            "recommendation"
        ):
            decision[
                "recommendation"
            ] = (
                IntelligencePipeline
                ._recommendation(
                    verdict
                )
            )

        return decision

    # ========================================================
    # Fallback decision
    # ========================================================

    @staticmethod
    def _fallback_decision(
        are_result,
    ):
        are_result = (
            are_result or {}
        )

        return {
            "risk_score": 0,
            "confidence": 0,
            "verdict": "UNKNOWN",
            "detail_verdict": (
                "INSUFFICIENT_EVIDENCE"
            ),
            "recommendation": (
                "Insufficient evidence to determine "
                "whether this email is legitimate."
            ),
            "reasoning": (
                are_result.get(
                    "evidence",
                    {},
                )
                if isinstance(
                    are_result,
                    dict,
                )
                else {}
            ),
        }

    # ========================================================
    # Recommendation
    # ========================================================

    @staticmethod
    def _recommendation(
        verdict,
    ):
        recommendations = {
            "VERIFIED LEGITIMATE": (
                "Strong evidence indicates this email "
                "is legitimate."
            ),
            "LIKELY LEGITIMATE": (
                "Appears likely legitimate, but verify "
                "unexpected requests."
            ),
            "LOW RISK": (
                "No significant threats detected, "
                "but sender is not fully verified."
            ),
            "SAFE": (
                "No immediate threats were detected "
                "and sufficient positive evidence exists."
            ),
            "UNKNOWN": (
                "Insufficient evidence to verify this sender. "
                "Exercise caution."
            ),
            "SUSPICIOUS": (
                "Exercise caution before clicking links "
                "or downloading files."
            ),
            "HIGH RISK": (
                "Multiple risk factors detected. "
                "Do not interact until verified."
            ),
            "PHISHING": (
                "Do not interact with this email. "
                "Report or delete it immediately."
            ),
        }

        return recommendations.get(
            verdict,
            "Exercise caution.",
        )

    # ========================================================
    # Utility methods retained for compatibility
    # ========================================================

    def normalize_analysis(
        self,
        analysis,
    ):
        if not isinstance(
            analysis,
            dict,
        ):
            return {}

        return analysis

    def validate_analysis(
        self,
        analysis,
    ):
        return isinstance(
            analysis,
            dict,
        )

    def build_evidence_summary(
        self,
        analysis,
    ):
        evidence = []

        def walk(value):

            if isinstance(
                value,
                dict,
            ):

                if (
                    "explanation"
                    in value
                ):
                    evidence.append(
                        value
                    )

                for child in value.values():
                    walk(child)

            elif isinstance(
                value,
                list,
            ):

                for child in value:
                    walk(child)

        walk(
            analysis
        )

        return evidence

    def generate_final_decision(
        self,
        analysis,
    ):

        if self.decision_engine:

            callable_target = getattr(
                self.decision_engine,
                "evaluate",
                self.decision_engine,
            )

            return self._call_component(
                callable_target,
                {
                    "are_result": analysis.get(
                        "reasoning",
                        analysis,
                    ),
                    "conflict_result": analysis.get(
                        "conflict_engine",
                        {},
                    ),
                    "evidence_graph": analysis,
                },
                [
                    analysis.get(
                        "reasoning",
                        analysis,
                    ),
                    analysis.get(
                        "conflict_engine",
                        {},
                    ),
                ],
            )

        return self._fallback_decision(
            analysis
        )


# ============================================================
# Public pipeline constants
# ============================================================

PIPELINE_ORDER = (
    IntelligencePipeline.PIPELINE_ORDER
)

SECURITY_INVARIANTS = (
    IntelligencePipeline.SECURITY_INVARIANTS
)