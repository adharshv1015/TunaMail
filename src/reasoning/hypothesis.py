from dataclasses import dataclass, field
from typing import List

from src.analysis.evidence import Evidence


@dataclass
class Hypothesis:
    """
    Represents one possible explanation for an email.
    """

    name: str
    display_name: str = ""
    category: str = "unknown"
    description: str = ""

    required: List[tuple] = field(default_factory=list)
    forbidden: List[tuple] = field(default_factory=list)

    supporting: List[Evidence] = field(default_factory=list)
    conflicting: List[Evidence] = field(default_factory=list)

    confidence: float = 0.0

    @property
    def support(self):
        return len(self.supporting)

    @property
    def contradictions(self):
        return len(self.conflicting)

    def add_support(self, evidence: Evidence):
        self.supporting.append(evidence)

    def add_contradiction(self, evidence: Evidence):
        self.conflicting.append(evidence)

    def evaluate(self, all_evidence: List[Evidence]):
        self.supporting.clear()
        self.conflicting.clear()

        # Find required evidence matches
        for req_type, req_val in self.required:
            for ev in all_evidence:
                if ev.evidence_type == req_type and ev.value == req_val:
                    self.add_support(ev)
        
        # Find forbidden evidence matches
        for forb_type, forb_val in self.forbidden:
            for ev in all_evidence:
                if ev.evidence_type == forb_type and ev.value == forb_val:
                    self.add_contradiction(ev)

        # Calculate confidence
        total = self.support + self.contradictions
        if total == 0:
            self.confidence = 0.0
        else:
            self.confidence = round(self.support / total, 2)

    def __repr__(self):
        return (
            f"<Hypothesis "
            f"name={self.name}, "
            f"support={self.support}, "
            f"contradictions={self.contradictions}, "
            f"confidence={self.confidence}>"
        )