import unittest

from src.analyzers.authentication_analyzer import AuthenticationAnalyzer
from src.analyzers.url_analyzer import URLAnalyzer
from src.analyzers.content_analyzer import ContentAnalyzer
from src.analyzers.attachment_analyzer import AttachmentAnalyzer
from src.analyzers.trust_analyzer import TrustAnalyzer
from src.engines.are import AnalyticalReasoningEngine
from src.engines.decision_fusion_engine import DecisionFusionEngine


class TestTunaMailPipeline(unittest.TestCase):

    def setUp(self):
        self.auth_analyzer = AuthenticationAnalyzer()
        self.url_analyzer = URLAnalyzer()
        self.content_analyzer = ContentAnalyzer()
        self.attachment_analyzer = AttachmentAnalyzer()
        self.trust_analyzer = TrustAnalyzer()
        self.are = AnalyticalReasoningEngine()
        self.decision_engine = DecisionFusionEngine()

    def run_pipeline(self, parsed):
        auth_analysis = self.auth_analyzer.analyze(parsed.get("headers", []))
        url_analysis = self.url_analyzer.analyze(parsed.get("body", ""))
        trust_analysis = self.trust_analyzer.evaluate(parsed_email=parsed, url_analysis=url_analysis)
        content_analysis = self.content_analyzer.analyze(
            body=parsed.get("body", ""),
            sender=parsed.get("from", ""),
            auth_results=auth_analysis
        )
        attachment_analysis = self.attachment_analyzer.analyze(parsed.get("attachments", []))

        are_result = self.are.evaluate(
            auth_analysis,
            url_analysis,
            content_analysis,
            attachment_analysis,
            trust_analysis
        )

        decision = self.decision_engine.evaluate(are_result)
        return decision["verdict"]

    def create_mock(self, sender, body, auth_pass=True, attachments=None):
        auth_value = (
            "spf=pass smtp.mailfrom=domain.com; dkim=pass header.i=@domain.com; dmarc=pass"
            if auth_pass else
            "spf=softfail smtp.mailfrom=domain.com; dkim=fail header.i=@domain.com; dmarc=fail"
        )
        return {
            "from": sender,
            "headers": {
                "Authentication-Results": auth_value
            },
            "body": body,
            "attachments": attachments or []
        }

    # 1. Legitimate Google email
    def test_legitimate_google(self):
        mock = self.create_mock("Google <no-reply@accounts.google.com>", "Your account was updated successfully.")
        self.assertEqual(self.run_pipeline(mock), "SAFE")

    # 2. Microsoft email
    def test_microsoft_email(self):
        mock = self.create_mock("Microsoft Security <security@microsoft.com>", "Your security info was changed.")
        self.assertEqual(self.run_pipeline(mock), "SAFE")

    # 3. GitHub email
    def test_github_email(self):
        mock = self.create_mock("GitHub <notifications@github.com>", "You have a new pull request.")
        self.assertEqual(self.run_pipeline(mock), "SAFE")

    # 4. Amazon OTP
    def test_amazon_otp(self):
        mock = self.create_mock("Amazon <otp@amazon.com>", "Your OTP is 123456.")
        self.assertEqual(self.run_pipeline(mock), "SAFE")

    # 5. PayPal receipt
    def test_paypal_receipt(self):
        mock = self.create_mock("PayPal <service@paypal.com>", "Here is your receipt for your recent transaction of $50.")
        self.assertEqual(self.run_pipeline(mock), "SAFE")

    # 6. Banking OTP
    def test_banking_otp(self):
        mock = self.create_mock("Bank <alerts@genericbank.com>", "Your OTP code is 999999.")
        self.assertEqual(self.run_pipeline(mock), "SAFE")

    # 7. Fake PayPal phishing
    def test_fake_paypal_phishing(self):
        mock = self.create_mock(
            "PayPal Support <service@paypal.com>", 
            "Your transaction of $500 is on hold. Please login at http://paypal-update-account.com immediately to resolve.",
            auth_pass=False
        )
        self.assertEqual(self.run_pipeline(mock), "PHISHING")

    # 8. Fake Microsoft login
    def test_fake_microsoft_login(self):
        mock = self.create_mock(
            "Admin <admin@microsoft.com>", 
            "Action required! Update your login credentials immediately to avoid account suspension.",
            auth_pass=False
        )
        self.assertEqual(self.run_pipeline(mock), "PHISHING")

    # 9. IP-address URL phishing
    def test_ip_address_url_phishing(self):
        mock = self.create_mock(
            "Support <support@domain.com>", 
            "Please login here: http://192.168.1.1/login to view your account.",
            auth_pass=False
        )
        # Auth fail + IP URL (network) -> Rule 2/3 might trigger PHISHING, or high risk.
        verdict = self.run_pipeline(mock)
        self.assertIn(verdict, ["PHISHING", "HIGH RISK"])

    # 10. URL shortener phishing
    def test_url_shortener_phishing(self):
        mock = self.create_mock(
            "Billing <billing@domain.com>", 
            "Urgent: your invoice is due. Click here: http://bit.ly/12345 to pay.",
            auth_pass=False
        )
        # Urgency + shortener + auth fail
        verdict = self.run_pipeline(mock)
        self.assertIn(verdict, ["PHISHING", "HIGH RISK"])

    # 11. Malicious attachment
    def test_malicious_attachment(self):
        mock = self.create_mock(
            "Invoice <invoice@domain.com>", 
            "Please find attached your invoice.",
            auth_pass=True,
            attachments=[{"filename": "invoice.exe", "mimeType": "application/x-msdownload"}]
        )
        self.assertEqual(self.run_pipeline(mock), "PHISHING")

if __name__ == '__main__':
    unittest.main()
