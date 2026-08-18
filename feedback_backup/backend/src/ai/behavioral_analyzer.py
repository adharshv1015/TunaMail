from ..storage.behavior_store import get_behavior_store
from ..storage.reputation_store import get_reputation_store
from .evidence_model import EvidenceItem, EvidenceDirection


class BehavioralAnalyzer:
    def __init__(self):
        self.store = get_behavior_store()
        self.reputation_store = get_reputation_store()

    def analyze(self, sender_email: str, current_auth: dict, current_urls: list) -> list:
        evidence = []
        history = self.store.get_sender_behavior(sender_email)

        if not history:
            return evidence

        # 1. URL Domain changes
        hist_urls = history.get("url_domains", [])
        curr_domains = [u.get("domain", "") for u in current_urls if u.get("domain")]

        if hist_urls and curr_domains:
            new_domains = [d for d in curr_domains if d not in hist_urls]
            if new_domains:
                evidence.append(EvidenceItem(
                    category="behavior",
                    type="BEHAVIORAL_DOMAIN_CHANGE",
                    severity="MEDIUM",
                    confidence=75,
                    direction=EvidenceDirection.NEGATIVE,
                    source="behavioral_analyzer",
                    value={"new_domains": new_domains},
                    explanation=(
                        f"Sender is using new URL domains "
                        f"({', '.join(new_domains)}) not previously observed for them."
                    )
                ))

        # 2. Authentication behavior changes
        hist_auth = history.get("auth_summary", [])

        curr_auth_str = (
            f"SPF:{current_auth.get('spf', 'none')} "
            f"DKIM:{current_auth.get('dkim', 'none')} "
            f"DMARC:{current_auth.get('dmarc', 'none')}"
        )

        if hist_auth and curr_auth_str not in hist_auth:
            evidence.append(EvidenceItem(
                category="behavior",
                type="AUTHENTICATION_BEHAVIOR_CHANGE",
                severity="MEDIUM",
                confidence=60,
                direction=EvidenceDirection.NEUTRAL,  # We let decision engine judge if it's malicious
                source="behavioral_analyzer",
                value={"historical": hist_auth, "current": curr_auth_str},
                explanation="Authentication pattern has changed from historical norms for this sender."
            ))

        return evidence
