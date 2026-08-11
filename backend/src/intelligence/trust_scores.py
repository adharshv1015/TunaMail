"""
Trust Score Engine for TunaMail Stage 5.

Computes separate evidence-level trust scores for:
  sender_trust, domain_trust, url_trust, brand_trust, attachment_trust, campaign_trust

These scores are EVIDENCE SIGNALS only — they do NOT directly determine the final verdict.
They feed into the explanation and are visible to analysts.
"""

import logging
from typing import Dict

from src.intelligence.knowledge_base import get_knowledge_base

logger = logging.getLogger(__name__)

_SCORE_RANGE = (0, 100)


def _clamp(val: float) -> int:
    return int(max(_SCORE_RANGE[0], min(_SCORE_RANGE[1], val)))


class TrustScoreEngine:
    """
    Computes evidence-based trust scores from existing analysis + knowledge base.
    """

    def compute(
        self,
        entities: dict,
        existing_analysis: dict,
        campaign_result: dict = None,
        correlation_result: dict = None
    ) -> Dict[str, int]:
        """
        Returns a dict of trust scores (0–100, where 100 = highest trust).
        """
        kb = get_knowledge_base()
        if existing_analysis is None:
            existing_analysis = {}

        auth = existing_analysis.get("authentication", {})
        url_analysis = existing_analysis.get("url", {})
        attachment = existing_analysis.get("attachment", {})

        spf_pass = auth.get("spf") == "pass"
        dkim_pass = auth.get("dkim") == "pass"
        dmarc_pass = auth.get("dmarc") == "pass"

        # ---- Sender Trust ----
        sender = entities.get("sender", "")
        sender_domain = entities.get("sender_domain", "")
        sender_trust = 50  # neutral starting point

        if spf_pass:
            sender_trust += 15
        if dkim_pass:
            sender_trust += 15
        if dmarc_pass:
            sender_trust += 10
        if sender_domain and kb.is_trusted_domain(sender_domain):
            sender_trust += 15
        # Penalize auth failure
        if not spf_pass:
            sender_trust -= 20
        if not dkim_pass:
            sender_trust -= 15
        # Apply analyst adjustment
        sender_trust += int(kb.get_sender_trust_adjustment(sender) * 30)

        # ---- Domain Trust ----
        domain_trust = 50
        if sender_domain:
            if kb.is_trusted_domain(sender_domain):
                domain_trust += 30
            if kb.has_suspicious_tld(sender_domain):
                domain_trust -= 30
            if kb.has_suspicious_pattern(sender_domain):
                domain_trust -= 20
            domain_trust += int(kb.get_domain_trust_adjustment(sender_domain) * 30)

        # ---- URL Trust ----
        url_trust = 50
        url_items = url_analysis.get("analysis", [])
        if url_items:
            url_scores = []
            for item in url_items:
                score = 50
                br = item.get("brand_relationship", "UNKNOWN")
                if br in ["OFFICIAL", "SUBDOMAIN_OF_OFFICIAL"]:
                    score += 30
                elif br in ["IMPERSONATION", "LOOKALIKE"]:
                    score -= 40
                if item.get("email_alignment") == "aligned":
                    score += 15
                elif item.get("email_alignment") == "misaligned":
                    score -= 20
                if item.get("dns", {}).get("private_ip_detected"):
                    score -= 50
                if item.get("tls", {}).get("certificate_valid"):
                    score += 10
                url_scores.append(score)
            url_trust = int(sum(url_scores) / len(url_scores)) if url_scores else 50
        else:
            url_trust = 50  # no URLs = neutral

        # ---- Brand Trust ----
        brand_trust = 50
        brands = entities.get("brands", [])
        if brands:
            # If any brand is marked as impersonated, brand trust drops
            impersonated = [b for b in brands if b.startswith("(impersonated)")]
            official = [b for b in brands if not b.startswith("(impersonated)")]
            if impersonated:
                brand_trust -= 40
            if official and not impersonated:
                brand_trust += 30

        # ---- Attachment Trust ----
        attachment_trust = 80  # assume clean unless evidence says otherwise
        att_risk = attachment.get("risk_score", 0)
        if att_risk > 0:
            attachment_trust = max(0, 80 - att_risk)
        if attachment.get("attachment_count", 0) == 0:
            attachment_trust = 80  # no attachments = neutral-high

        # ---- Campaign Trust ----
        campaign_trust = 70  # default unknown/neutral
        if campaign_result and campaign_result.get("campaign_detected"):
            confidence = campaign_result.get("confidence", 0)
            campaign_trust = max(0, 70 - confidence)
        elif correlation_result and correlation_result.get("related_messages"):
            n = len(correlation_result["related_messages"])
            campaign_trust = max(30, 70 - (n * 10))

        return {
            "sender_trust": _clamp(sender_trust),
            "domain_trust": _clamp(domain_trust),
            "url_trust": _clamp(url_trust),
            "brand_trust": _clamp(brand_trust),
            "attachment_trust": _clamp(attachment_trust),
            "campaign_trust": _clamp(campaign_trust)
        }
