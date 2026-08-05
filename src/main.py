import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from core.config import Config
from core.logger import get_logger
from artifacts.eml_extractor import EMLExtractor

from analysis.evidence import Evidence
from analysis.evidence_store import EvidenceStore
from analysis.sender_collector import SenderEvidenceCollector
from analysis.url_collector import URLEvidenceCollector
from analysis.attachment_collector import AttachmentEvidenceCollector
from analysis.header_auth_collector import HeaderAuthEvidenceCollector
from analysis.normalizer import EvidenceNormalizer
from reasoning.hypothesis import Hypothesis
from reasoning.evidence_analyzer import EvidenceAnalyzer
from reasoning.confidence_ledger import ConfidenceLedger
from inference.engine import InferenceEngine
from inference.default_hypotheses import load_default_hypotheses
from inference.explainer import ExplanationGenerator
from plugins.plugin_manager import PluginManager
from plugins.example_plugin import ExamplePlugin

from entities.artifact import Artifact

logger = get_logger(__name__)
config = Config()


def main() -> None:
    logger.info(
        f"{config.get('application', 'name')} "
        f"v{config.get('application', 'version')} Started"
    )

    manager = PluginManager()
    manager.register(ExamplePlugin())

    extractor = EMLExtractor()
    email_path = r"C:\Users\Asus\Downloads\[A-Kalleri_Post-Deployment-Refinement] Update_gui (PR #12).eml"
    logger.info("Loading EML file...")
    artifact = extractor.extract(email_path)
    logger.info(f"Headers: {len(artifact.headers)}")
    logger.info(f"Text Body: {len(artifact.text_body)} characters")
    logger.info(f"HTML Body: {len(artifact.html_body)} characters")

    logger.info("EML loaded successfully.")

    # Phase 2.1.1 Evidence Framework Test

    store = EvidenceStore()
    normalizer = EvidenceNormalizer()

    sender_email = artifact.sender.address if artifact.sender else ""
    sender_domain = artifact.sender.domain if artifact.sender else ""
    reply_to = artifact.reply_to.address if artifact.reply_to else ""

    sender_data = {
        "email": sender_email,
        "domain": sender_domain
    }

    email_analysis_data = {
        "sender": sender_data,
        "reply_to": reply_to
    }

    collector = SenderEvidenceCollector()

    sender_evidence = collector.collect(
        email_analysis_data
    )

    normalized_sender_evidence = []
    for evidence in sender_evidence:
        normalized_sender_evidence.append(
            normalizer.normalize(evidence)
        )
    store.add_many(normalized_sender_evidence)

    logger.info(
        f"Sender evidence collected: {len(sender_evidence)}"
    )

    for evidence in sender_evidence:
        logger.info(
            f"Evidence: {evidence}"
        )

    text_body = artifact.text_body
    html_body = artifact.html_body

    url_collector = URLEvidenceCollector()

    url_analysis_data = {
        "text_body": text_body,
        "html_body": html_body
    }

    url_evidence = url_collector.collect(
        url_analysis_data
    )

    normalized_url_evidence = []
    for evidence in url_evidence:
        normalized_url_evidence.append(
            normalizer.normalize(evidence)
        )
    store.add_many(normalized_url_evidence)

    logger.info(
        f"URL evidence collected: {len(url_evidence)}"
    )

    for evidence in url_evidence:
        logger.info(
            f"Evidence: {evidence}"
        )

    attachments = artifact.attachments

    attachment_collector = AttachmentEvidenceCollector()

    attachment_analysis_data = {
        "attachments": attachments
    }

    attachment_evidence = attachment_collector.collect(
        attachment_analysis_data
    )

    normalized_attachment_evidence = []
    for evidence in attachment_evidence:
        normalized_attachment_evidence.append(
            normalizer.normalize(evidence)
        )
    store.add_many(normalized_attachment_evidence)

    logger.info(
        f"Attachment evidence collected: {len(attachment_evidence)}"
    )

    for evidence in attachment_evidence:
        logger.info(
            f"Evidence: {evidence}"
        )

    headers = artifact.headers

    auth_collector = HeaderAuthEvidenceCollector()

    auth_analysis_data = {
        "headers": headers
    }

    auth_evidence = auth_collector.collect(
        auth_analysis_data
    )

    normalized_auth_evidence = []
    for evidence in auth_evidence:
        normalized_auth_evidence.append(
            normalizer.normalize(evidence)
        )
    store.add_many(normalized_auth_evidence)

    logger.info(
        f"Authentication evidence collected: {len(auth_evidence)}"
    )

    for evidence in auth_evidence:
        logger.info(
            f"Evidence: {evidence}"
        )
    logger.info(f"Subject      : {artifact.subject}")
    logger.info(
        f"Sender       : {artifact.sender.address} "
        f"({artifact.sender.domain})"
    )

    logger.info(
        f"Recipients   : "
        f"{[recipient.address for recipient in artifact.recipients]}"
    )

    logger.info(
        f"Reply-To     : {artifact.reply_to.address}"
    )
    logger.info(f"Message-ID   : {artifact.message_id}")
    logger.info(f"Date         : {artifact.date}")

    logger.info(f"Headers      : {len(artifact.headers)}")
    logger.info(f"Text Length  : {len(artifact.text_body)}")
    logger.info(f"HTML Length  : {len(artifact.html_body)}")

    engine = InferenceEngine()

    for hypothesis in load_default_hypotheses():
        engine.add(hypothesis)

    all_evidence = store.get_all()
    ranked = engine.evaluate(all_evidence)

    logger.info("Hypothesis Ranking:")

    for h in ranked:
        logger.info(
            "%s | confidence=%.2f | support=%d | contradictions=%d",
            h.name,
            h.confidence,
            h.support,
            h.contradictions,
        )

    if ranked:
        best = ranked[0]
        logger.info("Best hypothesis: %s", best.name)
        
        explainer = ExplanationGenerator()

        logger.info("")
        logger.info("Explanation")
        logger.info("--------------------------------")

        print(explainer.generate(best))

    manager.run_all()


if __name__ == "__main__":
    main()