# ============================================================
# backend/src/analyzers/authentication_analyzer.py
# ============================================================

from __future__ import annotations

import logging
import re
from typing import Any, Dict


logger = logging.getLogger(__name__)


class AuthenticationAnalyzer:
    """
    Defensive SPF / DKIM / DMARC analyzer.

    Important:
    - A DKIM-Signature header means a signature is present, not that
      DKIM verification passed.
    - Full authentication requires SPF + DKIM + DMARC to pass.
    - Authentication failures and unavailable/missing evidence are
      kept separate.
    - Authentication is evidence only and never creates a final verdict.
    - ARC results are treated as supporting context rather than being
      allowed to silently replace the primary Authentication-Results.
    """

    AUTH_METHODS = (
        "spf",
        "dkim",
        "dmarc",
    )

    FAILURE_RESULTS = {
        "fail",
        "softfail",
        "permerror",
        "temperror",
        "neutral",
        "policy",
    }

    PASS_RESULT = "pass"

    def analyze(
        self,
        headers: Dict[str, Any] | None,
    ) -> Dict[str, Any]:
        """
        Analyze authentication-related email headers.

        Supported sources include:
        - Authentication-Results
        - Authentication-Results-Original
        - ARC-Authentication-Results
        - Received-SPF
        - DKIM-Signature presence

        The analyzer intentionally does not treat a DKIM-Signature
        header as a successful DKIM verification.
        """

        headers = (
            headers
            if isinstance(headers, dict)
            else {}
        )

        authentication_results = self._header_text(
            headers,
            "Authentication-Results",
        )

        authentication_results_original = self._header_text(
            headers,
            "Authentication-Results-Original",
        )

        arc_authentication_results = self._header_text(
            headers,
            "ARC-Authentication-Results",
        )

        received_spf = self._header_text(
            headers,
            "Received-SPF",
        )

        # ----------------------------------------------------
        # Primary Authentication-Results
        # ----------------------------------------------------

        primary_text = (
            f"{authentication_results} "
            f"{authentication_results_original}"
        ).strip()

        spf = self.extract(
            primary_text,
            "spf",
        )

        dkim = self.extract(
            primary_text,
            "dkim",
        )

        dmarc = self.extract(
            primary_text,
            "dmarc",
        )

        # ----------------------------------------------------
        # SPF fallback
        # ----------------------------------------------------

        if spf == "unknown":
            spf = self._extract_received_spf(
                received_spf
            )

        # ----------------------------------------------------
        # DKIM fallback
        #
        # Presence != verification.
        # Keep this as a separate field instead of changing
        # dkim="unknown" into dkim="pass".
        # ----------------------------------------------------

        dkim_signature_present = bool(
            self._header_text(
                headers,
                "DKIM-Signature",
            )
        )

        # ----------------------------------------------------
        # ARC as supporting evidence
        # ----------------------------------------------------

        arc_spf = self.extract(
            arc_authentication_results,
            "spf",
        )

        arc_dkim = self.extract(
            arc_authentication_results,
            "dkim",
        )

        arc_dmarc = self.extract(
            arc_authentication_results,
            "dmarc",
        )

        # ARC must not silently convert an unknown primary result
        # into a verified primary authentication result.
        arc_evidence = {
            "spf": arc_spf,
            "dkim": arc_dkim,
            "dmarc": arc_dmarc,
        }

        # ----------------------------------------------------
        # Authentication states
        # ----------------------------------------------------

        primary_pass = {
            "spf": spf == self.PASS_RESULT,
            "dkim": dkim == self.PASS_RESULT,
            "dmarc": dmarc == self.PASS_RESULT,
        }

        failed_methods = [
            method
            for method, passed in primary_pass.items()
            if self._is_failure(
                {
                    "spf": spf,
                    "dkim": dkim,
                    "dmarc": dmarc,
                }.get(method)
            )
        ]

        unknown_methods = [
            method
            for method, value in {
                "spf": spf,
                "dkim": dkim,
                "dmarc": dmarc,
            }.items()
            if value == "unknown"
        ]

        full_pass = all(
            primary_pass.values()
        )

        any_pass = any(
            primary_pass.values()
        )

        any_failure = bool(
            failed_methods
        )

        any_known = any(
            value != "unknown"
            for value in (
                spf,
                dkim,
                dmarc,
            )
        )

        if full_pass:
            analysis_status = "AVAILABLE"
            authentication_state = "PASSED"

        elif any_failure:
            analysis_status = "AVAILABLE"
            authentication_state = "FAILED"

        elif any_known or dkim_signature_present:
            analysis_status = "AVAILABLE"
            authentication_state = "PARTIAL"

        else:
            analysis_status = "UNAVAILABLE"
            authentication_state = "UNAVAILABLE"

        # ----------------------------------------------------
        # Trust score
        #
        # This is a supporting authentication score only.
        # It must not be confused with final email trust.
        # ----------------------------------------------------

        trust_score = self._calculate_trust_score(
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            authentication_state=authentication_state,
        )

        # ----------------------------------------------------
        # Issues
        # ----------------------------------------------------

        issues = []

        if spf != "pass":
            issues.append(
                f"SPF check did not pass (result: {spf})"
            )

        if dkim != "pass":
            if dkim_signature_present and dkim == "unknown":
                issues.append(
                    "DKIM signature is present, but verification result is unavailable"
                )
            else:
                issues.append(
                    f"DKIM check did not pass (result: {dkim})"
                )

        if dmarc != "pass":
            issues.append(
                f"DMARC check did not pass (result: {dmarc})"
            )

        if unknown_methods:
            issues.append(
                "Authentication evidence is incomplete for: "
                + ", ".join(
                    unknown_methods
                )
            )

        # ----------------------------------------------------
        # Structured evidence
        # ----------------------------------------------------

        structured_evidence = []

        if full_pass:

            structured_evidence.append(
                self._evidence(
                    type_="AUTHENTICATION_PASS",
                    severity="LOW",
                    direction="POSITIVE",
                    source="AuthenticationAnalyzer",
                    explanation=(
                        "SPF, DKIM and DMARC all passed."
                    ),
                    confidence=0.96,
                )
            )

        if any_failure:

            structured_evidence.append(
                self._evidence(
                    type_="AUTHENTICATION_FAILURE",
                    severity="HIGH",
                    direction="NEGATIVE",
                    source="AuthenticationAnalyzer",
                    explanation=(
                        "One or more email authentication "
                        "checks failed."
                    ),
                    confidence=0.95,
                )
            )

        if (
            authentication_state
            == "UNAVAILABLE"
        ):

            structured_evidence.append(
                self._evidence(
                    type_="AUTHENTICATION_UNAVAILABLE",
                    severity="LOW",
                    direction="NEUTRAL",
                    source="AuthenticationAnalyzer",
                    explanation=(
                        "No usable SPF, DKIM or DMARC "
                        "verification result was available."
                    ),
                    confidence=0.0,
                )
            )

        if (
            dkim_signature_present
            and dkim == "unknown"
        ):

            structured_evidence.append(
                self._evidence(
                    type_="DKIM_SIGNATURE_UNVERIFIED",
                    severity="INFO",
                    direction="NEUTRAL",
                    source="AuthenticationAnalyzer",
                    explanation=(
                        "A DKIM signature is present, "
                        "but the available headers do not "
                        "contain a verified DKIM result."
                    ),
                    confidence=0.60,
                )
            )

        # ARC is contextual evidence only.
        if any(
            value != "unknown"
            for value in arc_evidence.values()
        ):

            structured_evidence.append(
                self._evidence(
                    type_="ARC_AUTHENTICATION_CONTEXT",
                    severity="INFO",
                    direction="NEUTRAL",
                    source="AuthenticationAnalyzer",
                    explanation=(
                        "ARC authentication results were "
                        "available as additional context."
                    ),
                    confidence=0.70,
                )
            )

        return {
            "analysis_status": analysis_status,
            "authentication_state": authentication_state,

            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,

            "spf_result": spf,
            "dkim_result": dkim,
            "dmarc_result": dmarc,

            "spf_pass": spf == "pass",
            "dkim_pass": dkim == "pass",
            "dmarc_pass": dmarc == "pass",

            "authentication_passed": full_pass,
            "authentication_failed": any_failure,
            "authentication_partial": (
                authentication_state
                == "PARTIAL"
            ),

            "dkim_signature_present": (
                dkim_signature_present
            ),

            "arc": arc_evidence,

            "failed_methods": failed_methods,
            "unknown_methods": unknown_methods,

            "trust_score": trust_score,
            "issues": issues,

            "structured_evidence": (
                structured_evidence
            ),
        }

    # ========================================================
    # Authentication-Results parser
    # ========================================================

    def extract(
        self,
        text: str | None,
        method: str,
    ) -> str:
        """
        Extract a method result from Authentication-Results.

        Handles common forms such as:

            spf=pass
            dkim=fail
            dmarc=pass

        and avoids accepting values containing invalid
        punctuation/characters.
        """

        text = str(
            text or ""
        )

        method = str(
            method or ""
        ).strip().lower()

        if not text or not method:
            return "unknown"

        pattern = (
            rf"(?:^|[;\s])"
            rf"{re.escape(method)}"
            rf"\s*=\s*"
            rf"([a-zA-Z]+)"
            rf"(?=\s|;|$)"
        )

        matches = re.findall(
            pattern,
            text,
            flags=re.IGNORECASE,
        )

        if not matches:
            return "unknown"

        # If multiple results exist, prefer a real result over
        # an earlier "none"/unknown-style result.
        normalized = [
            match.lower()
            for match in matches
        ]

        for preferred in (
            "pass",
            "fail",
            "softfail",
            "permerror",
            "temperror",
            "neutral",
            "policy",
        ):
            if preferred in normalized:
                return preferred

        return normalized[0]

    # ========================================================
    # Received-SPF parser
    # ========================================================

    @staticmethod
    def _extract_received_spf(
        value: str | None,
    ) -> str:
        value = str(
            value or ""
        ).strip()

        if not value:
            return "unknown"

        match = re.match(
            r"^([a-zA-Z]+)"
            r"(?=\s|$|\()",
            value,
            flags=re.IGNORECASE,
        )

        if not match:
            return "unknown"

        result = match.group(
            1
        ).lower()

        allowed = {
            "pass",
            "fail",
            "softfail",
            "neutral",
            "none",
            "temperror",
            "permerror",
            "policy",
        }

        return (
            result
            if result in allowed
            else "unknown"
        )

    # ========================================================
    # Header helper
    # ========================================================

    @staticmethod
    def _header_text(
        headers: Dict[str, Any],
        name: str,
    ) -> str:
        """
        Safely normalize a possibly-multivalue header.

        Python email parsers may expose duplicate headers as lists.
        """

        value = headers.get(
            name,
            "",
        )

        if isinstance(
            value,
            (list, tuple),
        ):
            return " ".join(
                str(item)
                for item in value
                if item is not None
            )

        return str(
            value or ""
        )

    # ========================================================
    # Result classification helpers
    # ========================================================

    def _is_failure(
        self,
        value: str,
    ) -> bool:

        return str(
            value or ""
        ).lower() in self.FAILURE_RESULTS

    @staticmethod
    def _calculate_trust_score(
        spf: str,
        dkim: str,
        dmarc: str,
        authentication_state: str,
    ) -> int:
        """
        Authentication-only trust signal.

        This score is intentionally conservative and is NOT a final
        sender reputation score.

        Full SPF + DKIM + DMARC pass = 100.
        A DKIM signature merely being present does not receive the
        same value as verified DKIM.
        """

        if (
            authentication_state
            == "PASSED"
        ):
            return 100

        score = 0

        if spf == "pass":
            score += 30
        elif spf in {
            "softfail",
            "neutral",
        }:
            score += 10

        if dkim == "pass":
            score += 30

        if dmarc == "pass":
            score += 40

        return max(
            0,
            min(
                100,
                score,
            ),
        )

    # ========================================================
    # Structured evidence helper
    # ========================================================

    @staticmethod
    def _evidence(
        type_: str,
        severity: str,
        direction: str,
        source: str,
        explanation: str,
        confidence: float,
    ) -> Dict[str, Any]:

        try:
            confidence = float(
                confidence
            )
        except (
            TypeError,
            ValueError,
        ):
            confidence = 0.0

        return {
            "type": (
                str(
                    type_
                )
                .strip()
                .upper()
                .replace(
                    "-",
                    "_",
                )
                .replace(
                    " ",
                    "_",
                )
            ),
            "severity": str(
                severity
            ).upper(),
            "direction": str(
                direction
            ).upper(),
            "source": source,
            "explanation": explanation,
            "confidence": max(
                0.0,
                min(
                    1.0,
                    confidence,
                ),
            ),
        }