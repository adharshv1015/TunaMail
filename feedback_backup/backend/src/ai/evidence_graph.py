from typing import List, Dict, Any
from .evidence_model import EvidenceItem, EvidenceCategory

class EvidenceGraph:
    def __init__(self):
        pass

    def build_graph(self, evidence_items: List[EvidenceItem], parsed_email: dict, url_data: dict, brand_data: List[dict]) -> Dict[str, Any]:
        """
        Builds a structured relationship graph from the collected evidence.
        """
        graph = {
            "entities": {
                "sender": parsed_email.get("from", ""),
                "urls": [u.get("domain", "") for u in url_data.get("analysis", [])],
                "brands_detected": [b.get("brand", "") for b in brand_data if b.get("brand_mentioned")]
            },
            "relationships": []
        }

        auth_pass = False
        has_auth_evidence = False

        for item in evidence_items:
            if item.category == EvidenceCategory.AUTHENTICATION:
                has_auth_evidence = True
                if item.type in ["spf_pass", "dkim_pass", "dmarc_pass"]:
                    auth_pass = True

        for u in url_data.get("analysis", []):
            url_domain = u.get("domain", "")
            
            # SENDER_DOMAIN_MATCH / MISMATCH
            if u.get("email_alignment") == "aligned":
                graph["relationships"].append({
                    "type": "SENDER_DOMAIN_MATCH",
                    "source": "sender",
                    "target": url_domain
                })
            elif u.get("email_alignment") == "misaligned":
                graph["relationships"].append({
                    "type": "SENDER_DOMAIN_MISMATCH",
                    "source": "sender",
                    "target": url_domain
                })

            # AUTHENTICATION_SUPPORTS / CONTRADICTS
            if has_auth_evidence:
                if auth_pass and u.get("email_alignment") == "aligned":
                    graph["relationships"].append({
                        "type": "AUTHENTICATION_SUPPORTS",
                        "source": "authentication",
                        "target": url_domain
                    })
                elif auth_pass and u.get("email_alignment") == "misaligned":
                    # Auth passes for sender, but URL is completely unrelated
                    graph["relationships"].append({
                        "type": "AUTHENTICATION_CONTRADICTS",
                        "source": "authentication",
                        "target": url_domain
                    })

        # BRAND_DOMAIN_MATCH / MISMATCH
        for b in brand_data:
            if b.get("brand_mentioned"):
                if b.get("domain_claimed"):
                    graph["relationships"].append({
                        "type": "BRAND_DOMAIN_MATCH",
                        "source": "brand",
                        "target": b.get("brand", "")
                    })
                elif b.get("impersonation_risk"):
                    graph["relationships"].append({
                        "type": "BRAND_DOMAIN_MISMATCH",
                        "source": "brand",
                        "target": b.get("brand", "")
                    })

        # Content supports / contradicts
        has_credential_req = any(e.type == "credential_request" for e in evidence_items)
        if has_credential_req:
            # If we have credential requests on an official brand domain
            if any(r["type"] == "BRAND_DOMAIN_MATCH" for r in graph["relationships"]):
                graph["relationships"].append({
                    "type": "CONTENT_SUPPORTS_URL",
                    "source": "content",
                    "target": "login_request"
                })
            # If we have credential requests on a mismatched brand domain
            elif any(r["type"] == "BRAND_DOMAIN_MISMATCH" for r in graph["relationships"]):
                graph["relationships"].append({
                    "type": "CONTENT_CONTRADICTS_URL",
                    "source": "content",
                    "target": "login_request"
                })

        return graph
