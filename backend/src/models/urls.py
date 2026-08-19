from typing import Any, Dict, List

from src.models.evidence import Evidence


class URLEvidenceExtractor:
    @staticmethod
    def extract(metadata: Any) -> List[Evidence]:
        evidence = []

        urls = getattr(metadata, "urls", []) or []

        for url_data in urls:
            if not isinstance(url_data, dict):
                continue

            url = url_data.get("url")

            if not url:
                continue

            evidence.append(
                Evidence(
                    evidence_type="url",
                    value=url,
                    confidence=0.8,
                    metadata={
                        "domain": url_data.get("domain"),
                        "location": url_data.get("location"),
                    },
                )
            )

        return evidence