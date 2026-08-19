from dataclasses import dataclass
from src.models.metadata import EmailMetadata
from src.models.evidence import Evidence
from src.reasoning.hypothesis import Hypothesis # Keep this import unchanged only if src.reasoning.hypothesis exists.

@dataclass
class AnalysisResult:
    metadata: EmailMetadata
    evidence: list[Evidence]
    hypotheses: list[Hypothesis]
    best_hypothesis: Hypothesis | None
    explanation: str
