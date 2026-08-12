import copy
import logging

logger = logging.getLogger(__name__)
from .inference import analyze_email
from .reasoning import AIReasoningEngine
from .adversarial_analyzer import AdversarialAnalyzer
from .brand_intelligence import BrandIntelligence
from .homoglyph_detector import HomoglyphDetector
from .contradiction_engine import ContradictionEngine
from .evidence_collector import EvidenceCollector
from .evidence_graph import EvidenceGraph
from .confidence_calibrator import ConfidenceCalibrator
from .evidence_model import EvidenceDirection

from .sender_reputation import SenderReputation
from .domain_reputation import DomainReputation
from .campaign_detector import CampaignDetector
from .behavioral_analyzer import BehavioralAnalyzer
from .temporal_analyzer import TemporalAnalyzer
from .adaptive_intelligence import AdaptiveIntelligenceEngine

class AIOrchestrator:
    def __init__(self):
        self.reasoning_engine = AIReasoningEngine()
        self.adversarial_analyzer = AdversarialAnalyzer()
        self.brand_intelligence = BrandIntelligence()
        self.homoglyph_detector = HomoglyphDetector()
        self.contradiction_engine = ContradictionEngine()
        self.evidence_collector = EvidenceCollector()
        self.evidence_graph = EvidenceGraph()
        self.confidence_calibrator = ConfidenceCalibrator()
        
        # Stage 8
        self.sender_reputation = SenderReputation()
        self.domain_reputation = DomainReputation()
        self.campaign_detector = CampaignDetector()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.temporal_analyzer = TemporalAnalyzer()
        self.adaptive_intelligence = AdaptiveIntelligenceEngine()
        
    def analyze_email_with_ai(self, parsed_email: dict, existing_analysis: dict) -> dict:
        """
        Orchestrates the AI layer by consuming deterministic evidence 
        and passing it to the local Stage 1 model.
        """
        # Ensure we have defaults
        if not existing_analysis:
            existing_analysis = {}
            
        auth_analysis = existing_analysis.get("authentication", {})
        url_analysis = existing_analysis.get("url", {})
        content_analysis = existing_analysis.get("content", {})
        attachment_analysis = existing_analysis.get("attachment", {})
        trust_analysis = existing_analysis.get("trust", {})
        
        # 1. Base inference (Tokenization + Model + Base feature extraction)
        base_ai_result = analyze_email(parsed_email, existing_analysis)
        
        predicted_class = base_ai_result.get("predicted_class", "UNKNOWN")
        confidence = base_ai_result.get("confidence", 0.0)
        link_only = base_ai_result.get("link_only", False)
        limited_context = base_ai_result.get("limited_context", False)
        reasoning_state = base_ai_result.get("reasoning_state", "SUFFICIENT_EVIDENCE")
        
        # We will build positive and negative evidence explicitly
        positive_evidence = []
        negative_evidence = []
        contradictions = base_ai_result.get("evidence", [])
        
        spf_pass = auth_analysis.get("spf") == "pass"
        dkim_pass = auth_analysis.get("dkim") == "pass"
        dmarc_pass = auth_analysis.get("dmarc") == "pass"
        has_strong_auth = spf_pass and dkim_pass and dmarc_pass
        
        sender_email = parsed_email.get("from", "")
        if "<" in sender_email and ">" in sender_email:
            sender_email_clean = sender_email.split("<")[1].split(">")[0]
        else:
            sender_email_clean = sender_email
            
        sender_domain = sender_email_clean.split("@")[-1] if "@" in sender_email_clean else ""
        
        # Stage 8: Behavioral Intelligence
        rep_profile = self.sender_reputation.get_profile(sender_email_clean)
        campaign_evidence = self.campaign_detector.detect(parsed_email, [u.get("domain") for u in url_analysis.get("analysis", [])])
        temporal_evidence = self.temporal_analyzer.analyze(sender_email_clean)
        behavioral_evidence = self.behavioral_analyzer.analyze(sender_email_clean, auth_analysis, url_analysis.get("analysis", []))
        
        # Stage 6 Enhancements
        homoglyph_evidence = []
        urls = url_analysis.get("analysis", [])
        for u in urls:
            domain = u.get("domain", "")
            h_det = self.homoglyph_detector.analyze_domain(domain)
            if h_det:
                homoglyph_evidence.append(h_det)
                
        sender_h_det = self.homoglyph_detector.analyze_domain(sender_domain)
        if sender_h_det:
            homoglyph_evidence.append(sender_h_det)

        brand_evidence = self.brand_intelligence.analyze(parsed_email.get("body", ""), urls, sender_domain)
        adversarial_evidence = self.adversarial_analyzer.analyze(parsed_email.get("body", ""), urls, sender_domain, parsed_email.get("is_html", False))
        
        contradiction_evidence = self.contradiction_engine.analyze(
            authentication=auth_analysis,
            url_analysis=urls,
            content_analysis=content_analysis,
            attachment_analysis=attachment_analysis,
            trust_analysis=trust_analysis,
            brand_evidence=brand_evidence,
            reputation_profile=rep_profile
        )
        
        # Collect Evidence via the new structured Model
        evidence_items = self.evidence_collector.collect_evidence(
            parsed_email=parsed_email,
            analysis=existing_analysis,
            ai_analysis={
                "brand_intelligence": brand_evidence,
                "adversarial": adversarial_evidence,
                "contradictions_engine": contradiction_evidence,
                "homoglyph": homoglyph_evidence,
                "context": {
                    "link_only": link_only,
                    "limited_context": limited_context
                }
            }
        )
        
        evidence_items.extend(campaign_evidence)
        evidence_items.extend(temporal_evidence)
        evidence_items.extend(behavioral_evidence)
        
        # Stage 10: Adaptive Intelligence
        adaptive_evidence = self.adaptive_intelligence.generate_adaptive_evidence(
            sender=sender_email_clean,
            domain=sender_domain,
            current_auth=auth_analysis,
            current_verdict="UNKNOWN", # At this stage, orchestrator runs before final verdict
            current_score=0,
            urls=[u.get("url") for u in urls]
        )

        # Build Graph
        graph = self.evidence_graph.build_graph(
            evidence_items=evidence_items,
            parsed_email=parsed_email,
            url_data=url_analysis,
            brand_data=brand_evidence
        )

        # Calibrate Confidence
        confidence, reasoning_state = self.confidence_calibrator.calibrate(
            evidence_items=evidence_items,
            graph=graph,
            initial_risk=0,
            reputation_profile=rep_profile
        )

        evidence_summary = [e.to_dict() for e in evidence_items]
        pos_ev = [e.explanation for e in evidence_items if e.direction == EvidenceDirection.POSITIVE]
        neg_ev = [e.explanation for e in evidence_items if e.direction == EvidenceDirection.NEGATIVE]

        return {
            "enabled": True,
            "model_type": "local-mlp-v1",
            "reasoning_state": reasoning_state,
            "confidence": confidence,
            "signals": list(set(pos_ev + neg_ev)),
            "positive_evidence": pos_ev,
            "negative_evidence": neg_ev,
            "contradictions": contradictions,
            "evidence_summary": evidence_summary,
            "evidence_graph": graph,
            "confidence_calibration": {
                "confidence": confidence,
                "reasoning_state": reasoning_state
            },
            "context_quality": {
                "link_only": link_only,
                "limited_context": limited_context,
                "has_meaningful_body": not (link_only or limited_context)
            },
            "reasoning_state": reasoning_state,
            "recommended_classification": predicted_class,
            "adversarial": adversarial_evidence,
            "brand_intelligence": brand_evidence,
            "homoglyph": homoglyph_evidence,
            "contradictions_engine": contradiction_evidence,
            "behavioral": behavioral_evidence,
            "sender_reputation": rep_profile,
            "campaign": campaign_evidence,
            "temporal": temporal_evidence,
            "adaptive": adaptive_evidence,
            "structured_evidence": evidence_items
        }

_ai_orchestrator = None

def analyze_email_with_ai(parsed_email: dict, existing_analysis: dict) -> dict:
    from .inference_cache import InferenceCache
    cache = InferenceCache()
    
    cache_key, lock = cache.get_lock(parsed_email, existing_analysis)
    
    with lock:
        cached_result = cache.get(cache_key)
        if cached_result:
            return cached_result
            
        global _ai_orchestrator
        if _ai_orchestrator is None:
            _ai_orchestrator = AIOrchestrator()
            
        try:
            result = _ai_orchestrator.analyze_email_with_ai(parsed_email, existing_analysis)
            # Remove objects that cannot be serialized or deep-copied trivially if necessary
            # For safety, let's keep it as is, but we might want to pop `structured_evidence` or `evidence_graph` if they are complex objects, 
            # though they are currently passed to the frontend or later stages.
            # In Python, dictionaries containing objects can be cached in memory perfectly fine.
            cache.set(cache_key, result)
            return result
        except Exception as e:
            import logging
            import traceback
            err_msg = f"Local AI analysis failed: {e}\n{traceback.format_exc()}"
            logging.getLogger(__name__).error(err_msg)
            logger.error(f"ORCHESTRATOR EXCEPTION: {err_msg}")
            return {
                "enabled": False,
                "model_type": "local-mlp-v1",
                "reasoning_state": "INSUFFICIENT_EVIDENCE",
                "confidence": 0.0,
                "signals": [],
                "positive_evidence": [],
                "negative_evidence": [],
                "contradictions": [],
                "context": {
                    "link_only": False,
                    "limited_context": False,
                    "has_meaningful_body": False
                },
                "reasoning_summary": "Local AI analysis unavailable.",
                "recommended_classification": "UNKNOWN"
            }
