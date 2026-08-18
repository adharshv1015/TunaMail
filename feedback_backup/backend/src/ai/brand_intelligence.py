class BrandIntelligence:
    """
    Detects brand impersonation attempts by comparing mentioned brands
    or URL keywords against known official domains.
    """

    def __init__(self):
        # Local configurable brand dictionary
        self.brands = {
            "google": {
                "domains": ["google.com", "gmail.com", "googlemail.com", "youtube.com", "googleapis.com", "gstatic.com", "googleusercontent.com"],
                "subdomains": ["accounts.google.com", "mail.google.com", "drive.google.com", "security.google.com"],
            },
            "microsoft": {
                "domains": ["microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "windows.com"],
                "subdomains": ["login.microsoftonline.com", "account.microsoft.com", "support.microsoft.com"],
            },
            "apple": {
                "domains": ["apple.com", "icloud.com"],
                "subdomains": ["appleid.apple.com", "support.apple.com", "iforgot.apple.com"],
            },
            "paypal": {
                "domains": ["paypal.com"],
                "subdomains": ["www.paypal.com", "history.paypal.com"],
            },
            "amazon": {
                "domains": ["amazon.com", "amazon.co.uk", "amazon.ca", "aws.amazon.com"],
                "subdomains": ["sellercentral.amazon.com"],
            },
            "netflix": {
                "domains": ["netflix.com"],
                "subdomains": ["www.netflix.com", "help.netflix.com"],
            },
            "meta": {
                "domains": ["meta.com", "facebook.com", "instagram.com", "whatsapp.com", "fb.com"],
                "subdomains": ["business.facebook.com"],
            },
            "linkedin": {
                "domains": ["linkedin.com"],
                "subdomains": ["www.linkedin.com"],
            }
        }
        
        # Generic banking keywords that usually shouldn't appear in random domains
        self.banking_keywords = ["bank", "chase", "bofa", "wells", "citi", "capitalone", "hsbc", "barclays"]

    def analyze(self, text_content: str, url_analysis: list, sender_domain: str) -> list:
        evidence = []
        text_lower = text_content.lower() if text_content else ""

        # Check for brand mentions in the text or sender
        mentioned_brands = []
        for brand_name in self.brands.keys():
            if brand_name in text_lower or (sender_domain and brand_name in sender_domain):
                mentioned_brands.append(brand_name)

        # Analyze URLs
        for u in url_analysis:
            url_domain = u.get("domain", "").lower()
            if not url_domain:
                continue

            # 1. Does the URL domain contain a brand name?
            for brand_name, brand_info in self.brands.items():
                if brand_name in url_domain:
                    # Is it an official domain?
                    is_official = False
                    for official_domain in brand_info["domains"]:
                        if url_domain == official_domain or url_domain.endswith("." + official_domain):
                            is_official = True
                            break
                    
                    if is_official:
                        evidence.append(self._create_evidence(
                            brand_name, True, True, True, False, 0.95,
                            f"Official {brand_name.capitalize()} domain detected."
                        ))
                    else:
                        evidence.append(self._create_evidence(
                            brand_name, True, True, False, True, 0.98,
                            f"Domain '{url_domain}' resembles {brand_name.capitalize()} but is not official (Impersonation Risk)."
                        ))

            # 2. If a brand was mentioned in the email body, but the URL is unrelated
            for brand_name in mentioned_brands:
                brand_info = self.brands[brand_name]
                is_official = False
                for official_domain in brand_info["domains"]:
                    if url_domain == official_domain or url_domain.endswith("." + official_domain):
                        is_official = True
                        break
                
                if not is_official and brand_name not in url_domain:
                    # A brand is talked about, but the URL doesn't belong to them
                    # Distinguish brand mention from impersonation
                    evidence.append(self._create_evidence(
                        brand_name, True, False, False, False, 0.60,
                        f"Email mentions {brand_name.capitalize()} but contains link to unrelated domain '{url_domain}'."
                    ))
                    
        return evidence

    def _create_evidence(self, brand: str, mentioned: bool, claimed: bool, match: bool, risk: bool, conf: float, explanation: str) -> dict:
        return {
            "type": "BRAND_IMPERSONATION" if risk else "BRAND",
            "severity": "HIGH" if risk else "LOW",
            "confidence": conf,
            "source": "brand_intelligence",
            "brand": brand.capitalize(),
            "brand_mentioned": mentioned,
            "domain_claimed": claimed,
            "official_domain_match": match,
            "impersonation_risk": risk,
            "explanation": explanation
        }
