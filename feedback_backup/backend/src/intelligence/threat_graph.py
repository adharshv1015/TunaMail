"""
Threat Relationship Graph for TunaMail Stage 5.

Builds entity relationship graphs from email intelligence.
Uses Python dict/set structures — no external graph DB required.

Relationships modeled:
  sender  --sends-->       email
  sender  --claims-->      brand
  email   --contains-->    url
  email   --contains-->    attachment
  email   --references-->  domain
  url     --resolves-->    ip
  url     --redirects-->   domain
  url     --belongs_to-->  registered_domain
"""

from typing import Dict, List, Any


class ThreatGraph:
    """
    Builds a serializable entity-relationship graph for an email.
    """

    def build(
        self,
        parsed_email: dict,
        entities: dict,
        existing_analysis: dict = None,
        iocs: list = None
    ) -> dict:
        """
        Build the threat relationship graph for a single email.

        Returns:
            {
                "nodes": [...],
                "edges": [...],
                "adjacency": {node_id: [neighbor_ids]}
            }
        """
        if existing_analysis is None:
            existing_analysis = {}
        if iocs is None:
            iocs = []

        nodes = {}
        edges = []

        def add_node(node_id: str, label: str, node_type: str, properties: dict = None):
            if node_id not in nodes:
                nodes[node_id] = {
                    "id": node_id,
                    "label": label,
                    "type": node_type,
                    "properties": properties or {}
                }

        def add_edge(source: str, target: str, relationship: str):
            if source and target:
                edges.append({
                    "source": source,
                    "target": target,
                    "relationship": relationship
                })

        # ---- Email node ----
        msg_id = parsed_email.get("id", "email")
        subject = parsed_email.get("subject", "No Subject")
        add_node(f"email:{msg_id}", subject[:60], "EMAIL", {
            "id": msg_id,
            "subject": subject
        })

        # ---- Sender ----
        sender = entities.get("sender", "")
        sender_domain = entities.get("sender_domain", "")
        if sender:
            add_node(f"sender:{sender}", sender, "SENDER")
            add_edge(f"sender:{sender}", f"email:{msg_id}", "sends")

        if sender_domain:
            add_node(f"domain:{sender_domain}", sender_domain, "DOMAIN")
            if sender:
                add_edge(f"sender:{sender}", f"domain:{sender_domain}", "belongs_to")

        # ---- Return path domain ----
        rp_domain = entities.get("return_path_domain", "")
        if rp_domain and rp_domain != sender_domain:
            add_node(f"domain:{rp_domain}", rp_domain, "DOMAIN", {"role": "return_path"})
            if sender:
                add_edge(f"sender:{sender}", f"domain:{rp_domain}", "return_path")
            add_edge(f"email:{msg_id}", f"domain:{rp_domain}", "references")

        # ---- URLs and domains ----
        url_analysis = existing_analysis.get("url", {})
        for item in url_analysis.get("analysis", []):
            url_val = item.get("url", "")
            url_domain = item.get("domain", "")
            reg_domain = item.get("registered_domain", "")

            if url_val:
                add_node(f"url:{url_val}", url_val[:80], "URL", {
                    "url": url_val,
                    "brand_relationship": item.get("brand_relationship", "UNKNOWN"),
                    "email_alignment": item.get("email_alignment", "unknown"),
                    "brand_impersonation": item.get("brand_impersonation", False)
                })
                add_edge(f"email:{msg_id}", f"url:{url_val}", "contains")

            if url_domain:
                add_node(f"domain:{url_domain}", url_domain, "DOMAIN")
                if url_val:
                    add_edge(f"url:{url_val}", f"domain:{url_domain}", "resolves_to")

            if reg_domain and reg_domain != url_domain:
                add_node(f"domain:{reg_domain}", reg_domain, "REGISTERED_DOMAIN")
                if url_val:
                    add_edge(f"url:{url_val}", f"domain:{reg_domain}", "belongs_to")

            # IPs from DNS
            for ip in item.get("dns", {}).get("a", []):
                add_node(f"ip:{ip}", ip, "IP_ADDRESS")
                if url_domain:
                    add_edge(f"domain:{url_domain}", f"ip:{ip}", "resolves_to")

            # Redirects
            for r_url in item.get("redirects", {}).get("chain", []):
                add_node(f"url:{r_url}", r_url[:80], "URL", {"role": "redirect"})
                if url_val:
                    add_edge(f"url:{url_val}", f"url:{r_url}", "redirects_to")

            # Brand impersonation
            br = item.get("brand_relationship", "")
            if br in ["IMPERSONATION", "LOOKALIKE"]:
                brand_name = item.get("domain", "").split(".")[0].capitalize()
                add_node(f"brand:{brand_name}", brand_name, "BRAND", {"status": "IMPERSONATED"})
                if sender:
                    add_edge(f"sender:{sender}", f"brand:{brand_name}", "impersonates")
            elif br in ["OFFICIAL", "SUBDOMAIN_OF_OFFICIAL"]:
                brand_name = item.get("domain", "").split(".")[0].capitalize()
                add_node(f"brand:{brand_name}", brand_name, "BRAND", {"status": "OFFICIAL"})
                if sender:
                    add_edge(f"sender:{sender}", f"brand:{brand_name}", "claims")

        # ---- Attachments ----
        for att in parsed_email.get("attachments", []):
            filename = att.get("filename", "")
            if filename:
                add_node(f"attachment:{filename}", filename, "ATTACHMENT", {
                    "filename": filename,
                    "size": att.get("size", 0)
                })
                add_edge(f"email:{msg_id}", f"attachment:{filename}", "contains")

        # ---- Build adjacency ----
        adjacency: Dict[str, List[str]] = {}
        for edge in edges:
            src = edge["source"]
            tgt = edge["target"]
            adjacency.setdefault(src, [])
            if tgt not in adjacency[src]:
                adjacency[src].append(tgt)

        return {
            "nodes": list(nodes.values()),
            "edges": edges,
            "adjacency": adjacency
        }
