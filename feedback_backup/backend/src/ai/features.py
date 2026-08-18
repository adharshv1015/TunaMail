import re

class FeatureExtractor:
    def __init__(self):
        pass

    def extract(self, parsed_email: dict, analysis: dict = None):
        """
        Extracts structured security features from the email and its analysis.
        """
        if not analysis:
            analysis = {}
            
        features = {}
        body = parsed_email.get("body", "")
        
        # 1. Content Features
        words = [w for w in body.split() if w.strip()]
        features["word_count"] = len(words)
        features["character_count"] = len(body)
        features["sentence_count"] = len(re.split(r'[.!?]+', body)) if body else 0
        features["has_body"] = features["character_count"] > 0
        
        # Link-Only & Limited Context Logic
        url_regex = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
        urls_in_body = url_regex.findall(body)
        
        # Remove URLs from body to see what text remains
        text_without_urls = url_regex.sub('', body).strip()
        remaining_words = [w for w in text_without_urls.split() if w.strip()]
        
        # If there's basically no text other than the URL (e.g. < 5 words)
        if urls_in_body and len(remaining_words) < 5:
            features["link_only"] = True
            features["limited_context"] = True
        else:
            features["link_only"] = False
            features["limited_context"] = False

        if not urls_in_body and features["word_count"] < 5:
            features["limited_context"] = True
            
        features["url_count"] = len(urls_in_body)
        features["attachment_count"] = len(parsed_email.get("attachments", []))
        
        # 2. Language/Intent Features (if available from previous content analysis, else default to 0)
        content_analysis = analysis.get("content", {})
        features["urgency"] = int(content_analysis.get("urgency", False))
        features["credential_request"] = int(content_analysis.get("credential_request", False))
        features["financial_request"] = int(content_analysis.get("financial_request", False))
        features["threat_language"] = int(content_analysis.get("threat_language", False))
        features["impersonation"] = int(content_analysis.get("impersonation", False))
        
        # Simple heuristics for account verification / password reset
        body_lower = body.lower()
        features["account_verification"] = int("verify" in body_lower and "account" in body_lower)
        features["password_reset"] = int("password" in body_lower and "reset" in body_lower)

        # 3. Sender Features
        sender = parsed_email.get("from", "")
        sender_domain = sender.split('@')[-1] if '@' in sender else ""
        features["sender_domain"] = sender_domain
        
        headers = parsed_email.get("headers", {})
        return_path = headers.get("Return-Path", "")
        return_path_domain = return_path.split('@')[-1].strip('<>') if '@' in return_path else ""
        features["return_path_domain"] = return_path_domain
        
        # 4. Authentication Features
        auth = analysis.get("authentication", {})
        features["spf_pass"] = int(auth.get("spf", "") == "pass")
        features["dkim_pass"] = int(auth.get("dkim", "") == "pass")
        features["dmarc_pass"] = int(auth.get("dmarc", "") == "pass")
        
        # 5. URL Features (Aggregate across URLs in the email)
        url_analysis = analysis.get("url", {}).get("analysis", [])
        
        features["has_ip_address"] = 0
        features["punycode"] = 0
        features["suspicious_port"] = 0
        features["brand_match"] = 0
        features["tls_valid"] = 1  # Assume valid until proven otherwise, or if no URLs
        features["dns_valid"] = 1
        features["redirect_count"] = 0
        features["sender_url_alignment"] = 0 # 1 if aligned
        
        if url_analysis:
            # We take the worst-case for boolean flags
            for item in url_analysis:
                if item.get("ip_based"): features["has_ip_address"] = 1
                if item.get("punycode"): features["punycode"] = 1
                if item.get("suspicious_port"): features["suspicious_port"] = 1
                
                brand_rel = item.get("brand_relationship", "UNKNOWN")
                if brand_rel in ["IMPERSONATION", "LOOKALIKE"]:
                    features["brand_match"] = -1
                elif brand_rel in ["OFFICIAL", "SUBDOMAIN_OF_OFFICIAL"] and features["brand_match"] != -1:
                    features["brand_match"] = 1
                
                tls = item.get("tls", {})
                if not tls.get("certificate_valid", True):
                    features["tls_valid"] = 0
                    
                dns = item.get("dns", {})
                if not dns.get("resolved", True) or dns.get("private_ip_detected"):
                    features["dns_valid"] = 0
                    
                redirects = item.get("redirects", {})
                if redirects.get("detected"):
                    features["redirect_count"] = max(features["redirect_count"], len(redirects.get("chain", [])))
                    
                if item.get("email_alignment") == "aligned":
                    features["sender_url_alignment"] = 1

        return features

    def vector_format(self, features: dict):
        """
        Converts the feature dictionary into a flat numerical list for model consumption.
        """
        # Ensure a fixed order of features
        ordered_keys = [
            "word_count", "character_count", "sentence_count", "has_body",
            "link_only", "limited_context", "url_count", "attachment_count",
            "urgency", "credential_request", "financial_request", 
            "threat_language", "impersonation", "account_verification", "password_reset",
            "spf_pass", "dkim_pass", "dmarc_pass",
            "has_ip_address", "punycode", "suspicious_port", "brand_match",
            "tls_valid", "dns_valid", "redirect_count", "sender_url_alignment"
        ]
        
        return [float(features.get(k, 0)) for k in ordered_keys]
