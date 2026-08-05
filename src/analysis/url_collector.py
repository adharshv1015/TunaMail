import re
from urllib.parse import urlparse

from analysis.collector import EvidenceCollector
from analysis.evidence import Evidence


class URLEvidenceCollector(EvidenceCollector):
    """
    Extracts URLs from email content and creates evidence.
    """

    name = "url_evidence_collector"


    URL_PATTERN = re.compile(
        r"https?://[^\s<>\"']+",
        re.IGNORECASE
    )


    def collect(self, email_data):

        evidences = []

        sources = [
            (
                "text_body",
                email_data.get("text_body", "")
            ),
            (
                "html_body",
                email_data.get("html_body", "")
            )
        ]


        for location, content in sources:

            if not content:
                continue


            urls = self.URL_PATTERN.findall(content)


            for url in urls:

                parsed = urlparse(url)

                domain = parsed.netloc.lower()


                evidences.append(
                    Evidence(
                        evidence_type="url",
                        value=url,
                        source=self.name,
                        confidence=0.8,
                        metadata={
                            "domain": domain,
                            "location": location
                        }
                    )
                )


        return evidences
