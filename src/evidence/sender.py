from src.entities.metadata import EmailMetadata
from email.utils import parseaddr
from src.analysis.evidence import Evidence

class SenderEvidenceExtractor:
    def _get_base_domain(self, domain: str) -> str:
        parts = domain.lower().split('.')
        if len(parts) > 2:
            return ".".join(parts[-2:])
        return domain.lower()

    def extract(self, metadata: EmailMetadata) -> list[Evidence]:
        evidences = []
        
        from_header = metadata.sender
        reply_to_header = metadata.reply_to
        
        sender_email = ""
        sender_domain = ""
        if from_header:
            _, sender_email = parseaddr(from_header)
            if "@" in sender_email:
                sender_domain = sender_email.split("@")[1]

        if sender_email:
            evidences.append(
                Evidence(
                    evidence_type="sender_address",
                    value=sender_email,
                    confidence=1.0,
                    metadata={"domain": sender_domain}
                )
            )
            evidences.append(
                Evidence(
                    evidence_type="sender_domain",
                    value=sender_domain,
                    confidence=0.8
                )
            )

        if reply_to_header:
            _, reply_email = parseaddr(reply_to_header)
            reply_domain = ""
            if "@" in reply_email:
                reply_domain = reply_email.split("@")[1]
            
            if reply_domain:
                evidences.append(
                    Evidence(
                        evidence_type="reply_to_domain",
                        value=reply_domain,
                        confidence=0.8
                    )
                )

                if sender_domain:
                    aligned = (
                        self._get_base_domain(sender_domain)
                        ==
                        self._get_base_domain(reply_domain)
                    )
                    evidences.append(
                        Evidence(
                            evidence_type="domain_alignment",
                            value=aligned,
                            confidence=0.9,
                            metadata={
                                "sender_domain": sender_domain,
                                "reply_domain": reply_domain
                            }
                        )
                    )

        return evidences
