from src.analysis.collector import EvidenceCollector
from src.analysis.evidence import Evidence


class SenderEvidenceCollector(EvidenceCollector):
    """
    Collects sender-related security evidence.
    """

    name = "sender_evidence_collector"

    def _get_base_domain(self, domain: str) -> str:
        # Simplistic base domain extraction for relaxed alignment.
        parts = domain.lower().split('.')
        if len(parts) > 2:
            return ".".join(parts[-2:])
        return domain.lower()

    def collect(self, email_data):
        evidences = []

        sender = email_data.get("sender")
        reply_to = email_data.get("reply_to")


        if sender:
            sender_email = sender.get("email")
            sender_domain = sender.get("domain")


            evidences.append(
                Evidence(
                    evidence_type="sender_address",
                    value=sender_email,
                    source=self.name,
                    confidence=1.0,
                    metadata={
                        "domain": sender_domain
                    }
                )
            )


            evidences.append(
                Evidence(
                    evidence_type="sender_domain",
                    value=sender_domain,
                    source=self.name,
                    confidence=0.8
                )
            )


        if reply_to:
            reply_domain = reply_to.split("@")[-1]


            evidences.append(
                Evidence(
                    evidence_type="reply_to_domain",
                    value=reply_domain,
                    source=self.name,
                    confidence=0.8
                )
            )


            if sender and sender.get("domain"):

                s_domain = sender.get("domain")
                r_domain = reply_domain

                aligned = (
                    self._get_base_domain(s_domain)
                    ==
                    self._get_base_domain(r_domain)
                )


                evidences.append(
                    Evidence(
                        evidence_type="domain_alignment",
                        value=aligned,
                        source=self.name,
                        confidence=0.9,
                        metadata={
                            "sender_domain":
                                sender.get("domain"),
                            "reply_domain":
                                reply_domain
                        }
                    )
                )


        return evidences
