import re
from src.entities.metadata import EmailMetadata
from src.analysis.evidence import Evidence

class AuthenticationEvidenceExtractor:
    def extract(self, metadata: EmailMetadata) -> list[Evidence]:
        evidences = []
        
        auth_headers = metadata.headers.get("authentication-results", [])
        
        if auth_headers:
            auth_results = auth_headers[0].lower()
            checks = [
                ("spf", "spf"),
                ("dkim", "dkim"),
                ("dmarc", "dmarc")
            ]
            
            for name, keyword in checks:
                match = re.search(rf"{keyword}=([a-z]+)", auth_results)
                if match:
                    result = match.group(1)
                    evidences.append(
                        Evidence(
                            evidence_type=f"{name}_result",
                            value=result,
                            confidence=0.9,
                            metadata={"header": "Authentication-Results"}
                        )
                    )
        else:
            evidences.append(
                Evidence(
                    evidence_type="authentication_header",
                    value="missing",
                    confidence=0.5
                )
            )

        return evidences
