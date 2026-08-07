from src.entities.metadata import EmailMetadata
from src.analysis.evidence import Evidence

class AttachmentEvidenceExtractor:
    def extract(self, metadata: EmailMetadata) -> list[Evidence]:
        evidences = []
        
        for att in metadata.attachments:
            evidences.append(
                Evidence(
                    evidence_type="attachment",
                    value=att["filename"],
                    confidence=1.0,
                    metadata={
                        "filename": att["filename"],
                        "extension": att["extension"],
                        "mime_type": att["mime_type"],
                        "size": att["size"]
                    }
                )
            )

        return evidences
