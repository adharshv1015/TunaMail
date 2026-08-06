import re

from src.analysis.collector import EvidenceCollector
from src.analysis.evidence import Evidence


class HeaderAuthEvidenceCollector(EvidenceCollector):
    """
    Extracts email authentication evidence
    from headers.
    """

    name = "header_auth_evidence_collector"


    def collect(self, email_data):

        evidences = []

        headers = email_data.get(
            "headers",
            {}
        )


        auth_header = None

        for key, value in headers.items():

            if key.lower() == "authentication-results":
                auth_header = value
                break


        if auth_header:

            auth_results = (
                auth_header
                .lower()
            )


            checks = [
                ("spf", "spf"),
                ("dkim", "dkim"),
                ("dmarc", "dmarc")
            ]


            for name, keyword in checks:

                match = re.search(
                    rf"{keyword}=([a-z]+)",
                    auth_results
                )


                if match:

                    result = match.group(1)


                    evidences.append(
                        Evidence(
                            evidence_type=f"{name}_result",
                            value=result,
                            source=self.name,
                            confidence=0.9,
                            metadata={
                                "header":
                                "Authentication-Results"
                            }
                        )
                    )


        else:

            evidences.append(
                Evidence(
                    evidence_type="authentication_header",
                    value="missing",
                    source=self.name,
                    confidence=0.5
                )
            )


        return evidences