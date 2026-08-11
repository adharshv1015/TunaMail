import uuid
from typing import Dict, List, Any, Optional
from enum import Enum

class EvidenceCategory(str, Enum):
    AUTHENTICATION = "authentication"
    URL = "url"
    DOMAIN = "domain"
    CONTENT = "content"
    SENDER = "sender"
    ATTACHMENT = "attachment"
    BRAND = "brand"
    BEHAVIOR = "behavior"
    NETWORK = "network"
    AI = "ai"

class EvidenceSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class EvidenceReliability(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class EvidenceDirection(str, Enum):
    POSITIVE = "POSITIVE"
    NEGATIVE = "NEGATIVE"
    NEUTRAL = "NEUTRAL"

class EvidenceItem:
    def __init__(
        self,
        category: EvidenceCategory,
        type: str,
        severity: EvidenceSeverity,
        direction: EvidenceDirection,
        source: str,
        explanation: str,
        observation: str = "",
        impact: str = "",
        reliability: EvidenceReliability = EvidenceReliability.MEDIUM,
        confidence: int = 0,
        value: Optional[Dict[str, Any]] = None,
        related_entities: Optional[List[str]] = None,
        weight: int = 0
    ):
        self.id = f"EV-{str(uuid.uuid4())[:8].upper()}"
        self.category = category
        self.type = type
        self.severity = severity
        self.direction = direction
        self.source = source
        self.explanation = explanation
        self.observation = observation or explanation
        self.impact = impact
        self.reliability = reliability
        self.confidence = confidence
        self.value = value or {}
        self.related_entities = related_entities or []
        self.weight = weight

    @property
    def supports(self) -> str:
        if self.direction == EvidenceDirection.POSITIVE:
            return "BENIGN"
        elif self.direction == EvidenceDirection.NEGATIVE:
            return "MALICIOUS"
        return "NEUTRAL"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category.value,
            "type": self.type,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "reliability": self.reliability.value,
            "direction": self.direction.value,
            "supports": self.supports,
            "source": self.source,
            "observation": self.observation,
            "explanation": self.explanation,
            "impact": self.impact,
            "value": self.value,
            "related_entities": self.related_entities,
            "weight": self.weight
        }
