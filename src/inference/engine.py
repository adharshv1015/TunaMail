from typing import List, Optional

from analysis.evidence import Evidence
from reasoning.hypothesis import Hypothesis


class InferenceEngine:
    def __init__(self):
        self.hypotheses: List[Hypothesis] = []

    def add(self, hypothesis: Hypothesis):
        self.hypotheses.append(hypothesis)

    def evaluate(self, evidence: List[Evidence]) -> List[Hypothesis]:
        for hypothesis in self.hypotheses:
            hypothesis.evaluate(evidence)

        return sorted(
            self.hypotheses,
            key=lambda h: h.confidence,
            reverse=True,
        )

    def best(self, evidence: List[Evidence]) -> Optional[Hypothesis]:
        ranked = self.evaluate(evidence)

        if not ranked:
            return None

        return ranked[0]