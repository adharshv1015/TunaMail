from dataclasses import dataclass
from src.entities.metadata import EmailMetadata
from src.analysis.evidence import Evidence
from src.reasoning.hypothesis import Hypothesis

@dataclass
class AnalysisResult:
    metadata: EmailMetadata
    evidence: list[Evidence]
    hypotheses: list[Hypothesis]
    best_hypothesis: Hypothesis | None
    explanation: str
