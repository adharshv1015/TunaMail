from src.entities.metadata import EmailMetadata
from src.analysis.evidence import Evidence

class URLEvidenceExtractor:
    def extract(self, metadata: EmailMetadata) -> list[Evidence]:
        evidences = []
        
        for u in metadata.urls:
            evidences.append(
                Evidence(
                    evidence_type="url",
                    value=u["url"],
                    confidence=0.8,
                    metadata={
                        "domain": u["domain"],
                        "location": u["location"]
                    }
                )
            )

        return evidences
