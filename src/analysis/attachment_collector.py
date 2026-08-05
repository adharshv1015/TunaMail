import os

from analysis.collector import EvidenceCollector
from analysis.evidence import Evidence


class AttachmentEvidenceCollector(EvidenceCollector):
    """
    Collects attachment-related email evidence.
    """

    name = "attachment_evidence_collector"


    def collect(self, email_data):

        evidences = []

        attachments = email_data.get(
            "attachments",
            []
        )


        for attachment in attachments:

            filename = attachment.get(
                "filename"
            )

            mime_type = attachment.get(
                "mime_type"
            )

            size = attachment.get(
                "size"
            )


            extension = None

            if filename:
                extension = os.path.splitext(
                    filename
                )[1].lower()


            evidences.append(
                Evidence(
                    evidence_type="attachment",
                    value=filename,
                    source=self.name,
                    confidence=1.0,
                    metadata={
                        "filename": filename,
                        "extension": extension,
                        "mime_type": mime_type,
                        "size": size
                    }
                )
            )


        return evidences