import re


class ContentAnalyzer:

    def analyze(self, body: str, sender: str = "", auth_results: dict = None):

        if auth_results is None:
            auth_results = {}

        text = body.lower()
        sender_lower = sender.lower()

        result = {
            "urgency": self.contains(
                text,
                [
                    "urgent",
                    "immediately",
                    "expire",
                    "within 24 hours",
                    "action required",
                    "suspended",
                    "limited time"
                ]
            ),

            "credential_request": self.contains(
                text,
                [
                    "password",
                    "login",
                    "verify account",
                    "confirm account",
                    "sign in",
                    "username"
                ]
            ),

            "financial_request": self.contains(
                text,
                [
                    "payment",
                    "bank",
                    "credit card",
                    "wire transfer",
                    "invoice",
                    "refund"
                ]
            ),

            "impersonation": self.check_impersonation(text, sender_lower, auth_results),

            "threat_language": self.contains(
                text,
                [
                    "suspended",
                    "locked",
                    "disabled",
                    "terminated",
                    "blocked"
                ]
            )
        }

        score = 0

        if result["urgency"]:
            score += 20

        if result["credential_request"]:
            score += 25

        if result["financial_request"]:
            score += 25

        if result["impersonation"]:
            score += 10

        if result["threat_language"]:
            score += 20

        result["risk_score"] = score

        return result

    def contains(self, text, keywords):

        return any(
            keyword in text
            for keyword in keywords
        )

    def check_impersonation(self, text, sender, auth_results):
        brands = {
            "google": "google.com",
            "microsoft": "microsoft.com",
            "paypal": "paypal.com",
            "amazon": "amazon.com",
            "apple": "apple.com"
        }

        for brand, domain in brands.items():
            if brand in text:
                # If brand is in the text, check if it's genuinely from them
                is_legit = (
                    domain in sender and
                    auth_results.get("spf") == "pass" and
                    auth_results.get("dkim") == "pass"
                )
                if not is_legit:
                    return True
        return False