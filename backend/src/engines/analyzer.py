from __future__ import annotations

import logging
from typing import Any, Dict

# pyrefly: ignore [missing-import]
from src.connectors.eml_parser import EmailParser
# pyrefly: ignore [missing-import]
from src.engines.are import AnalyticalReasoningEngine


logger = logging.getLogger(__name__)


class EmailAnalyzer:
    """
    Backward-compatible email analysis entry point.

    Uses the existing parser and AnalyticalReasoningEngine while
    normalizing failures into a safe UNKNOWN result.
    """

    def __init__(self):
        self.parser = EmailParser()
        self.are = AnalyticalReasoningEngine()

    def analyze(
        self,
        email_path: str,
    ) -> Dict[str, Any]:
        """
        Parse and analyze an EML file.

        The method supports the newer ARE signature when available
        and falls back to the legacy parsed-email signature.
        """

        try:
            parsed = self.parser.parse(
                email_path
            )

        except Exception as exc:
            logger.exception(
                "Email parsing failed for %s",
                email_path,
            )

            return {
                "parsed_email": {},
                "reasoning": {
                    "risk_score": 0,
                    "confidence": 0,
                    "verdict": "UNKNOWN",
                    "detail_verdict": (
                        "INSUFFICIENT_EVIDENCE"
                    ),
                    "explanation": (
                        "The email could not be parsed."
                    ),
                    "error": str(exc),
                },
            }

        parsed = (
            parsed
            if isinstance(
                parsed,
                dict,
            )
            else {}
        )

        try:
            reasoning = self._evaluate(
                parsed
            )

        except Exception as exc:
            logger.exception(
                "Email reasoning failed for %s",
                email_path,
            )

            reasoning = {
                "risk_score": 0,
                "confidence": 0,
                "verdict": "UNKNOWN",
                "detail_verdict": (
                    "INSUFFICIENT_EVIDENCE"
                ),
                "explanation": (
                    "Insufficient evidence to analyze "
                    "this email."
                ),
                "error": str(exc),
            }

        return {
            "parsed_email": parsed,
            "reasoning": reasoning,
        }

    def _evaluate(
        self,
        parsed: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Supports both:

            ARE.evaluate(parsed_email)

        and the newer evidence-oriented ARE signature.
        """

        # ----------------------------------------------------
        # Newer ARE interface
        # ----------------------------------------------------

        authentication = (
            parsed.get(
                "authentication",
                parsed.get(
                    "auth",
                    {},
                ),
            )
            or {}
        )

        url_analysis = (
            parsed.get(
                "urls",
                parsed.get(
                    "url_analysis",
                    {},
                ),
            )
            or {}
        )

        whois_analysis = (
            parsed.get(
                "whois",
                parsed.get(
                    "whois_analysis",
                    [],
                ),
            )
            or []
        )

        content_analysis = (
            parsed.get(
                "content",
                parsed.get(
                    "content_analysis",
                    {},
                ),
            )
            or {}
        )

        attachment_analysis = (
            parsed.get(
                "attachments",
                parsed.get(
                    "attachment_analysis",
                    {},
                ),
            )
            or {}
        )

        trust_analysis = (
            parsed.get(
                "trust",
                parsed.get(
                    "trust_analysis",
                    {},
                ),
            )
            or {}
        )

        ai_analysis = (
            parsed.get(
                "ai",
                parsed.get(
                    "ai_analysis",
                    {},
                ),
            )
            or {}
        )

        url_page_intelligence = (
            parsed.get(
                "url_page_intelligence",
                {},
            )
            or {}
        )

        historical_evidence = (
            parsed.get(
                "historical_evidence",
                {},
            )
            or {}
        )

        try:
            return self.are.evaluate(
                authentication=authentication,
                url_analysis=url_analysis,
                whois_analysis=whois_analysis,
                content_analysis=content_analysis,
                attachment_analysis=attachment_analysis,
                trust_analysis=trust_analysis,
                ai_analysis=ai_analysis,
                url_page_intelligence=url_page_intelligence,
                historical_evidence=historical_evidence,
            )

        except TypeError:
            # ------------------------------------------------
            # Legacy ARE interface
            # ------------------------------------------------
            return self.are.evaluate(
                parsed
            )