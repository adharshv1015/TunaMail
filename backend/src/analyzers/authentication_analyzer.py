import re
import logging

logger = logging.getLogger(__name__)
logger.info("Authentication Analyzer Loaded")
class AuthenticationAnalyzer:

    def analyze(self, headers):

        auth_results = headers.get("Authentication-Results", "")
        arc_results = headers.get("ARC-Authentication-Results", "")
        
        # Combine the main result headers
        combined_text = f"{auth_results} {arc_results}"

        spf = self.extract(combined_text, "spf")
        dkim = self.extract(combined_text, "dkim")
        dmarc = self.extract(combined_text, "dmarc")
        
        # Fallbacks if not found in standard auth results
        if spf == "unknown":
            received_spf = headers.get("Received-SPF", "")
            if received_spf:
                spf_match = re.match(r"^([a-z]+)", received_spf.strip(), re.IGNORECASE)
                if spf_match:
                    spf = spf_match.group(1).lower()

        if dkim == "unknown":
            if headers.get("DKIM-Signature"):
                dkim = "present_unverified"

        issues = []
        trust_score = 100

        if spf != "pass":
            trust_score -= 30
            issues.append(f"SPF check did not pass (result: {spf})")
            
        if dkim not in ["pass", "present_unverified"]:
            trust_score -= 30
            issues.append(f"DKIM check did not pass (result: {dkim})")
            
        if dmarc != "pass":
            trust_score -= 40
            issues.append(f"DMARC check did not pass (result: {dmarc})")

        return {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "trust_score": max(0, trust_score),
            "issues": issues
        }

    def extract(
        self,
        text,
        method
    ):

        result = re.search(
            rf"{method}=([a-z]+)",
            text,
            re.IGNORECASE
        )

        if result:
            return result.group(1).lower()

        return "unknown"