from dataclasses import dataclass, field
from typing import Any


@dataclass
class Evidence:
    evidence_type: str
    value: Any
    confidence: float
    metadata: dict = field(default_factory=dict)