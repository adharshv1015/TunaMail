from analysis.url_normalizer import URLNormalizer


class EvidenceNormalizer:

    def __init__(self):
        self.url_normalizer = URLNormalizer()

    def normalize(self, evidence):

        if evidence.evidence_type == "url":
            evidence.value = self.url_normalizer.normalize(
                evidence.value
            )

        return evidence