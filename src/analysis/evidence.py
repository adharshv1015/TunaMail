from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict


@dataclass
class Evidence:
    """
    Represents a single piece of evidence extracted from an email.
    """

    evidence_type: str
    value: Any
    source: str = ""

    confidence: float = 0.0

    metadata: Dict[str, Any] = field(default_factory=dict)

    created_at: datetime = field(
        default_factory=datetime.utcnow
    )

    def to_dict(self):
        return {
            "type": self.evidence_type,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat()
        }

    def __repr__(self):
        return (
            f"<Evidence "
            f"type={self.evidence_type}, "
            f"value={self.value}, "
            f"confidence={self.confidence}>"
        )
