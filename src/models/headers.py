from src.entities.metadata import EmailMetadata
from src.analysis.evidence import Evidence


class HeaderEvidenceExtractor:
    """Extracts useful evidence from email headers."""

    def extract(self, metadata: EmailMetadata) -> list[Evidence]:
        evidence = []

        # Return-Path
        return_path = metadata.headers.get("return-path")
        if return_path:
            evidence.append(
                Evidence(
                    evidence_type="return_path",
                    value=return_path[0],
                    confidence=0.8,
                )
            )

        # Message-ID
        if metadata.message_id:
            evidence.append(
                Evidence(
                    evidence_type="message_id",
                    value=metadata.message_id,
                    confidence=0.8,
                )
            )

        # X-Mailer
        x_mailer = metadata.headers.get("x-mailer")
        if x_mailer:
            evidence.append(
                Evidence(
                    evidence_type="x_mailer",
                    value=x_mailer[0],
                    confidence=0.7,
                )
            )

        # MIME-Version
        mime_version = metadata.headers.get("mime-version")
        if mime_version:
            evidence.append(
                Evidence(
                    evidence_type="mime_version",
                    value=mime_version[0],
                    confidence=0.7,
                )
            )

        # Content-Type
        content_type = metadata.headers.get("content-type", ["text/plain"])
        ct_value = content_type[0].split(";")[0].strip()
        evidence.append(
            Evidence(
                evidence_type="content_type",
                value=ct_value,
                confidence=0.7,
            )
        )

        # Reply-To
        if metadata.reply_to:
            evidence.append(
                Evidence(
                    evidence_type="reply_to",
                    value=metadata.reply_to,
                    confidence=0.8,
                )
            )

        # Date
        if metadata.date:
            evidence.append(
                Evidence(
                    evidence_type="date",
                    value=metadata.date,
                    confidence=0.7,
                )
            )

        # Count Received headers
        received_headers = metadata.headers.get("received", [])

        evidence.append(
            Evidence(
                evidence_type="received_count",
                value=len(received_headers),
                confidence=0.8,
            )
        )

        return evidence