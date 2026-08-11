"""
Intelligence Pipeline Orchestrator for TunaMail Stage 5.

Runs the complete Stage 5 intelligence pipeline on an analyzed email.
Called from the existing gmail.py after the Stage 1-4 pipeline completes.
AI failure is isolated — deterministic analysis continues regardless.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any

from src.intelligence.db import init_db
from src.intelligence.ioc_extractor import IOCExtractor
from src.intelligence.entity_extractor import EntityExtractor
from src.intelligence.knowledge_base import get_knowledge_base
from src.intelligence.threat_graph import ThreatGraph
from src.intelligence.correlation_engine import CorrelationEngine
from src.intelligence.campaign_detector import CampaignDetector
from src.intelligence.pattern_engine import PatternEngine
from src.intelligence.trust_scores import TrustScoreEngine
from src.intelligence.temporal_tracker import TemporalTracker
from src.intelligence.audit_log import AuditLog

logger = logging.getLogger(__name__)

# Ensure DB is initialized when module is imported
try:
    init_db()
except Exception as _e:
    logger.warning(f"Intelligence DB init warning: {_e}")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class IntelligencePipeline:
    """
    Runs the Stage 5 local intelligence pipeline.
    All components are isolated — failures don't cascade.
    """

    def __init__(self):
        self.ioc_extractor = IOCExtractor()
        self.entity_extractor = EntityExtractor()
        self.threat_graph = ThreatGraph()
        self.correlation_engine = CorrelationEngine()
        self.campaign_detector = CampaignDetector()
        self.pattern_engine = PatternEngine()
        self.trust_engine = TrustScoreEngine()
        self.temporal_tracker = TemporalTracker()
        self.audit_log = AuditLog()

    def run(
        self,
        parsed_email: dict,
        existing_analysis: dict
    ) -> Dict[str, Any]:
        """
        Run the full Stage 5 intelligence pipeline.

        Args:
            parsed_email: GmailParser output
            existing_analysis: Full Stage 1-4 analysis output

        Returns:
            intelligence dict — additive to existing analysis
        """
        message_id = parsed_email.get("id", "unknown")
        timeline = []

        def ts():
            return datetime.now(timezone.utc).strftime("%H:%M:%S")

        def add_event(event: str):
            timeline.append({"time": ts(), "event": event})

        add_event("Email received by intelligence pipeline")

        # ---- 1. IOC Extraction ----
        iocs = []
        try:
            iocs = self.ioc_extractor.extract(parsed_email, existing_analysis)
            add_event(f"IOC extraction complete ({len(iocs)} indicators found)")
        except Exception as e:
            logger.error(f"IOC extraction failed: {e}")
            add_event("IOC extraction failed (non-critical)")

        # ---- 2. Entity Extraction ----
        entities = {}
        try:
            entities = self.entity_extractor.extract(parsed_email, existing_analysis)
            add_event("Entity extraction complete")
        except Exception as e:
            logger.error(f"Entity extraction failed: {e}")
            add_event("Entity extraction failed (non-critical)")

        # ---- 3. Temporal Tracking ----
        temporal_data = {}
        first_seen_flags = {}
        try:
            temporal_data = self.temporal_tracker.batch_record(iocs)
            first_seen_flags = self.temporal_tracker.get_first_seen_flags(iocs)
            add_event(f"Temporal tracking updated ({len(first_seen_flags)} first-seen indicators)")
        except Exception as e:
            logger.error(f"Temporal tracking failed: {e}")
            add_event("Temporal tracking failed (non-critical)")

        # ---- 4. Threat Graph ----
        threat_graph = {}
        try:
            threat_graph = self.threat_graph.build(
                parsed_email, entities, existing_analysis, iocs
            )
            add_event(f"Threat graph built ({len(threat_graph.get('nodes', []))} nodes, {len(threat_graph.get('edges', []))} edges)")
        except Exception as e:
            logger.error(f"Threat graph failed: {e}")
            add_event("Threat graph failed (non-critical)")

        # ---- 5. IOC Correlation ----
        correlation_result = {"related_messages": [], "shared_indicators": [], "infrastructure_overlap": False, "relationship_summary": "No correlations found."}
        try:
            correlation_result = self.correlation_engine.correlate(
                message_id, iocs, entities, existing_analysis
            )
            n = len(correlation_result.get("related_messages", []))
            add_event(f"Correlation complete ({n} related message(s) found)")
        except Exception as e:
            logger.error(f"Correlation failed: {e}")
            add_event("Correlation failed (non-critical)")

        # ---- 6. Campaign Detection ----
        campaign_result = {"campaign_detected": False, "campaign_id": None, "confidence": 0}
        try:
            campaign_result = self.campaign_detector.detect(
                message_id, correlation_result, entities, existing_analysis
            )
            if campaign_result.get("campaign_detected"):
                add_event(f"Campaign detected: {campaign_result.get('campaign_id')} (confidence: {campaign_result.get('confidence')}%)")
            else:
                add_event("No campaign detected")
        except Exception as e:
            logger.error(f"Campaign detection failed: {e}")
            add_event("Campaign detection failed (non-critical)")

        # ---- 7. Attack Pattern Detection ----
        attack_patterns = []
        try:
            attack_patterns = self.pattern_engine.detect(
                parsed_email, existing_analysis, entities
            )
            if attack_patterns:
                add_event(f"Attack pattern(s) detected: {', '.join(p['name'] for p in attack_patterns[:2])}")
            else:
                add_event("No attack patterns detected")
        except Exception as e:
            logger.error(f"Pattern detection failed: {e}")
            add_event("Attack pattern detection failed (non-critical)")

        # ---- 8. Trust Scores ----
        trust_scores = {}
        try:
            trust_scores = self.trust_engine.compute(
                entities, existing_analysis, campaign_result, correlation_result
            )
            add_event("Trust scores computed")
        except Exception as e:
            logger.error(f"Trust score computation failed: {e}")
            add_event("Trust score computation failed (non-critical)")

        add_event("Intelligence pipeline complete")

        # ---- 9. Audit: email viewed ----
        try:
            self.audit_log.log("email_analyzed", {
                "message_id": message_id,
                "ioc_count": len(iocs),
                "campaign_detected": campaign_result.get("campaign_detected", False),
                "pattern_count": len(attack_patterns)
            })
        except Exception as e:
            logger.error(f"Audit log failed: {e}")

        return {
            "iocs": iocs,
            "entities": entities,
            "related_messages": correlation_result.get("related_messages", []),
            "shared_indicators": correlation_result.get("shared_indicators", []),
            "infrastructure_overlap": correlation_result.get("infrastructure_overlap", False),
            "relationship_summary": correlation_result.get("relationship_summary", ""),
            "campaign": campaign_result,
            "attack_patterns": attack_patterns,
            "trust_scores": trust_scores,
            "threat_graph": threat_graph,
            "first_seen": first_seen_flags,
            "temporal": temporal_data,
            "timeline": timeline
        }


# Module-level singleton
_pipeline = None


def get_intelligence_pipeline() -> IntelligencePipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = IntelligencePipeline()
    return _pipeline


def run_intelligence(parsed_email: dict, existing_analysis: dict) -> dict:
    """
    Module-level entry point. Returns an empty dict on complete failure
    so deterministic analysis always continues.
    """
    try:
        pipeline = get_intelligence_pipeline()
        return pipeline.run(parsed_email, existing_analysis)
    except Exception as e:
        logger.error(f"Intelligence pipeline complete failure: {e}")
        return {
            "iocs": [],
            "entities": {},
            "related_messages": [],
            "shared_indicators": [],
            "campaign": {"campaign_detected": False},
            "attack_patterns": [],
            "trust_scores": {},
            "timeline": [{"time": "N/A", "event": "Intelligence pipeline unavailable"}],
            "error": "Intelligence pipeline unavailable"
        }
