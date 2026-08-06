from email import message_from_bytes

from src.core.logger import get_logger

from src.evidence.sender import SenderEvidenceExtractor
from src.evidence.urls import URLEvidenceExtractor
from src.evidence.attachments import AttachmentEvidenceExtractor
from src.evidence.authentication import AuthenticationEvidenceExtractor
from src.evidence.headers import HeaderEvidenceExtractor

from src.entities.metadata import EmailMetadata
from src.entities.result import AnalysisResult
from src.analysis.evidence_store import EvidenceStore
from src.analysis.normalizer import EvidenceNormalizer
from src.inference.engine import InferenceEngine
from src.inference.default_hypotheses import load_default_hypotheses
from src.inference.explainer import ExplanationGenerator

logger = get_logger(__name__)

class Analyzer:
    def __init__(self):
        self.normalizer = EvidenceNormalizer()
        
        self.sender_extractor = SenderEvidenceExtractor()
        self.url_extractor = URLEvidenceExtractor()
        self.attachment_extractor = AttachmentEvidenceExtractor()
        self.authentication_extractor = AuthenticationEvidenceExtractor()
        self.header_extractor = HeaderEvidenceExtractor()
        
        self.engine = InferenceEngine()
        for hypothesis in load_default_hypotheses():
            self.engine.add(hypothesis)
            
        self.explainer = ExplanationGenerator()

    def analyze(self, file_path: str) -> AnalysisResult:
        logger.info("Loading EML file...")
        with open(file_path, "rb") as f:
            email = message_from_bytes(f.read())
            metadata = EmailMetadata.from_message(email)
        logger.info("EML loaded successfully.")

        store = EvidenceStore()
        
        sender_evidence = self.sender_extractor.extract(metadata)
        for e in sender_evidence:
            e.source = "Sender Evidence"
        logger.info("Sender evidence collected: %d", len(sender_evidence))
        for item in sender_evidence:
            logger.info("Evidence: %s", item)

        url_evidence = self.url_extractor.extract(metadata)
        for e in url_evidence:
            e.source = "URL Evidence"
        logger.info("URL evidence collected: %d", len(url_evidence))
        if url_evidence:
            unique_domains = set()
            for item in url_evidence:
                if "domain" in item.metadata:
                    unique_domains.add(item.metadata["domain"])
            
            if unique_domains:
                logger.info("Unique Domains:")
                for domain in sorted(unique_domains):
                    logger.info(" \u2022 %s", domain)

        attachment_evidence = self.attachment_extractor.extract(metadata)
        for e in attachment_evidence:
            e.source = "Attachments"
        logger.info("Attachment evidence collected: %d", len(attachment_evidence))
        for item in attachment_evidence:
            logger.info("Evidence: %s", item)

        authentication_evidence = self.authentication_extractor.extract(metadata)
        for e in authentication_evidence:
            e.source = "Authentication"
        logger.info("Authentication evidence collected: %d", len(authentication_evidence))
        for item in authentication_evidence:
            logger.info("Evidence: %s", item)

        header_evidence = self.header_extractor.extract(metadata)
        for e in header_evidence:
            e.source = "Header Evidence"
        logger.info("Header evidence collected: %d", len(header_evidence))
        for item in header_evidence:
            logger.info("Evidence: %s", item)

        all_evidence = (
            sender_evidence
            + url_evidence
            + attachment_evidence
            + authentication_evidence
            + header_evidence
        )
        
        normalized_evidence = []
        for evidence in all_evidence:
            normalized_evidence.append(self.normalizer.normalize(evidence))
            
        store.add_many(normalized_evidence)
        logger.info(f"Total normalized evidence collected: {len(normalized_evidence)}")

        ranked = self.engine.evaluate(store.get_all())
        
        logger.info("Hypothesis Ranking:")
        for h in ranked:
            logger.info(
                "%s | confidence=%.2f | support=%d | contradictions=%d",
                h.name,
                h.confidence,
                h.support,
                h.contradictions,
            )

        best = ranked[0] if ranked else None
        explanation = ""
        if best:
            logger.info("Best hypothesis: %s", best.name)
            logger.info("")
            logger.info("Explanation")
            logger.info("--------------------------------")
            explanation = self.explainer.generate(best, store.get_all())
            print(explanation)
            
        return AnalysisResult(
            metadata=metadata,
            evidence=store.get_all(),
            hypotheses=ranked,
            best_hypothesis=best,
            explanation=explanation
        )
