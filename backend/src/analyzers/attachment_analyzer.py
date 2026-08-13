from __future__ import annotations

import logging
import os
from typing import Any, Dict, Iterable, List


logger = logging.getLogger(__name__)


class AttachmentAnalyzer:
    """
    Defensive attachment security analyzer.

    Produces deterministic attachment evidence without opening or
    executing attachment contents.

    Risk categories:
    - Executable files
    - Script files
    - Macro-enabled Office documents
    - Archives
    - Double extensions
    - Large files
    """

    EXECUTABLE_EXTENSIONS = {
        ".exe",
        ".msi",
        ".bat",
        ".cmd",
        ".scr",
        ".com",
    }

    SCRIPT_EXTENSIONS = {
        ".js",
        ".jse",
        ".vbs",
        ".vbe",
        ".ps1",
        ".psm1",
        ".hta",
    }

    MACRO_EXTENSIONS = {
        ".docm",
        ".xlsm",
        ".pptm",
    }

    ARCHIVE_EXTENSIONS = {
        ".zip",
        ".rar",
        ".7z",
        ".iso",
    }

    DOUBLE_EXTENSION_RISK = 15
    LARGE_FILE_RISK = 5

    EXECUTABLE_RISK = 40
    SCRIPT_RISK = 35
    MACRO_RISK = 30
    ARCHIVE_RISK = 15

    LARGE_FILE_BYTES = 10 * 1024 * 1024

    def analyze(
        self,
        attachments: Iterable[Dict[str, Any]] | None,
    ) -> Dict[str, Any]:
        """
        Analyze attachment metadata only.

        Invalid attachment entries are ignored safely.
        The method never opens, executes, extracts, or scans
        attachment contents.
        """

        if attachments is None:
            attachments = []

        if not isinstance(
            attachments,
            (list, tuple),
        ):
            logger.warning(
                "Attachment analyzer received invalid collection type: %s",
                type(attachments).__name__,
            )
            attachments = []

        score = 0
        evidence: List[str] = []
        structured_evidence: List[Dict[str, Any]] = []

        analyzed_count = 0

        for attachment in attachments:

            if not isinstance(
                attachment,
                dict,
            ):
                continue

            filename = self._normalize_filename(
                attachment.get(
                    "filename"
                )
            )

            if not filename:
                # Missing filenames are not automatically malicious.
                # Keep the event visible as metadata-quality information.
                continue

            size = self._safe_size(
                attachment.get(
                    "size",
                    0,
                )
            )

            analyzed_count += 1

            filename_lower = filename.lower()

            _, extension = os.path.splitext(
                filename_lower
            )

            # -------------------------------------------------
            # Executable
            # -------------------------------------------------

            if (
                extension
                in self.EXECUTABLE_EXTENSIONS
            ):

                score += self.EXECUTABLE_RISK

                message = (
                    f"Executable attachment: {filename}"
                )

                evidence.append(
                    message
                )

                structured_evidence.append(
                    self._evidence(
                        type_="EXECUTABLE_ATTACHMENT",
                        severity="CRITICAL",
                        explanation=message,
                        confidence=0.98,
                    )
                )

            # -------------------------------------------------
            # Script
            # -------------------------------------------------

            if (
                extension
                in self.SCRIPT_EXTENSIONS
            ):

                score += self.SCRIPT_RISK

                message = (
                    f"Script attachment: {filename}"
                )

                evidence.append(
                    message
                )

                structured_evidence.append(
                    self._evidence(
                        type_="SCRIPT_ATTACHMENT",
                        severity="CRITICAL",
                        explanation=message,
                        confidence=0.97,
                    )
                )

            # -------------------------------------------------
            # Macro-enabled Office document
            # -------------------------------------------------

            if (
                extension
                in self.MACRO_EXTENSIONS
            ):

                score += self.MACRO_RISK

                message = (
                    "Macro-enabled Office document: "
                    f"{filename}"
                )

                evidence.append(
                    message
                )

                structured_evidence.append(
                    self._evidence(
                        type_="MACRO_ATTACHMENT",
                        severity="HIGH",
                        explanation=message,
                        confidence=0.95,
                    )
                )

            # -------------------------------------------------
            # Archive
            # -------------------------------------------------

            if (
                extension
                in self.ARCHIVE_EXTENSIONS
            ):

                score += self.ARCHIVE_RISK

                message = (
                    f"Archive attachment: {filename}"
                )

                evidence.append(
                    message
                )

                structured_evidence.append(
                    self._evidence(
                        type_="ARCHIVE_ATTACHMENT",
                        severity="MEDIUM",
                        explanation=message,
                        confidence=0.80,
                    )
                )

            # -------------------------------------------------
            # Multiple extensions
            #
            # invoice.pdf.exe
            # document.docx.js
            # -------------------------------------------------

            if filename.count(".") >= 2:

                score += (
                    self.DOUBLE_EXTENSION_RISK
                )

                message = (
                    f"Multiple extensions: {filename}"
                )

                evidence.append(
                    message
                )

                structured_evidence.append(
                    self._evidence(
                        type_="DOUBLE_EXTENSION",
                        severity="HIGH",
                        explanation=message,
                        confidence=0.90,
                    )
                )

            # -------------------------------------------------
            # Large attachment
            # -------------------------------------------------

            if (
                size
                > self.LARGE_FILE_BYTES
            ):

                score += (
                    self.LARGE_FILE_RISK
                )

                message = (
                    f"Large attachment: {filename}"
                )

                evidence.append(
                    message
                )

                structured_evidence.append(
                    self._evidence(
                        type_="LARGE_ATTACHMENT",
                        severity="LOW",
                        explanation=message,
                        confidence=0.70,
                    )
                )

        score = max(
            0,
            min(
                int(score),
                100,
            ),
        )

        if evidence:
            analysis_status = "AVAILABLE"
        else:
            analysis_status = "AVAILABLE"

        return {
            "analysis_status": analysis_status,
            "attachment_count": len(
                attachments
            ),
            "analyzed_attachment_count": analyzed_count,
            "risk_score": score,
            "evidence": evidence,
            "structured_evidence": (
                structured_evidence
            ),
        }

    # =========================================================
    # Helpers
    # =========================================================

    @staticmethod
    def _normalize_filename(
        filename: Any,
    ) -> str:
        if filename is None:
            return ""

        try:
            filename = str(
                filename
            ).strip()
        except Exception:
            return ""

        return filename

    @staticmethod
    def _safe_size(
        size: Any,
    ) -> int:
        try:
            return max(
                0,
                int(size or 0),
            )
        except (
            TypeError,
            ValueError,
        ):
            return 0

    @staticmethod
    def _evidence(
        type_: str,
        severity: str,
        explanation: str,
        confidence: float,
    ) -> Dict[str, Any]:
        return {
            "type": (
                str(type_)
                .strip()
                .upper()
                .replace("-", "_")
                .replace(" ", "_")
            ),
            "severity": (
                str(severity)
                .strip()
                .upper()
            ),
            "direction": "NEGATIVE",
            "source": "AttachmentAnalyzer",
            "explanation": explanation,
            "confidence": max(
                0.0,
                min(
                    1.0,
                    float(confidence),
                ),
            ),
        }