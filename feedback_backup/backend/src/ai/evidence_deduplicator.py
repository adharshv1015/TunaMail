# ============================================================
# backend/src/ai/evidence_deduplicator.py
# ============================================================

from .evidence_integrity import EvidenceIntegrityValidator


class EvidenceDeduplicator:

    def __init__(self):

        self.validator = EvidenceIntegrityValidator()

    def deduplicate(self, evidence):

        validated = self.validator.validate_many(
            evidence or []
        )

        unique = {}
        priority = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
        }

        for item in validated:

            fingerprint = item["fingerprint"]

            existing = unique.get(fingerprint)

            if not existing:
                unique[fingerprint] = item
                continue

            current_priority = priority.get(
                item["severity"],
                1,
            )

            existing_priority = priority.get(
                existing["severity"],
                1,
            )

            if current_priority > existing_priority:
                unique[fingerprint] = item

        return list(unique.values())
