from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class Evidence:

    supporting: List[str] = field(default_factory=list)

    contradicting: List[str] = field(default_factory=list)

    indicators: Dict = field(default_factory=dict)

    risk_score: int = 0