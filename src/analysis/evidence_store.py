from typing import List

from .evidence import Evidence


class EvidenceStore:
    """
    Central storage for collected email evidence.
    """

    def __init__(self):
        self._evidence: List[Evidence] = []


    def add(self, evidence: Evidence):

        key = (
            evidence.evidence_type,
            str(evidence.value)
        )

        existing = {
            (
                e.evidence_type,
                str(e.value)
            )
            for e in self._evidence
        }

        if key not in existing:
            self._evidence.append(evidence)


    def add_many(self, evidences):

        for evidence in evidences:
            self.add(evidence)


    def get_all(self):
        return self._evidence


    def count(self):
        return len(self._evidence)


    def clear(self):
        self._evidence.clear()