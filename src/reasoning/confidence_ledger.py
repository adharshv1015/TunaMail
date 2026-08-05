from reasoning.hypothesis import Hypothesis


class ConfidenceLedger:
    """
    Computes a confidence score for a hypothesis
    based on supporting and contradicting evidence.
    """

    def calculate(self, hypothesis: Hypothesis) -> Hypothesis:

        support = len(hypothesis.supporting_evidence)
        contradiction = len(hypothesis.contradicting_evidence)

        total = support + contradiction

        if total == 0:
            hypothesis.confidence = 0.0
            return hypothesis

        hypothesis.confidence = round(support / total, 2)

        return hypothesis