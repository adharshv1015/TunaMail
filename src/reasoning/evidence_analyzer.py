from src.reasoning.hypothesis import Hypothesis


class EvidenceAnalyzer:
    """
    Associates evidence with a hypothesis by determining whether
    it supports or contradicts that hypothesis.
    """

    def analyze(self, hypothesis: Hypothesis, evidence_store):

        for evidence in evidence_store.get_all():

            # Authentication passes support legitimacy
            if evidence.evidence_type in (
                "spf_result",
                "dkim_result",
                "dmarc_result",
            ) and evidence.value == "pass":

                hypothesis.add_support(evidence)

            # Matching sender domain supports legitimacy
            elif evidence.evidence_type == "sender_domain":
                hypothesis.add_support(evidence)

            # Domain mismatch contradicts legitimacy
            elif (
                evidence.evidence_type == "domain_alignment"
                and evidence.value is False
            ):
                hypothesis.add_contradiction(evidence)

        return hypothesis