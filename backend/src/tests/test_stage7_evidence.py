import unittest
from src.connectors.gmail_parser import GmailParser
from src.analyzers.authentication_analyzer import AuthenticationAnalyzer
from src.analyzers.url_analyzer import URLAnalyzer
from src.analyzers.content_analyzer import ContentAnalyzer
from src.analyzers.attachment_analyzer import AttachmentAnalyzer
from src.analyzers.trust_analyzer import TrustAnalyzer
from src.ai.orchestrator import analyze_email_with_ai
from src.engines.are import AnalyticalReasoningEngine
from src.engines.decision_fusion_engine import DecisionFusionEngine
import base64

from src.storage.local_store import LocalJSONStore
from src.storage.adaptive_store import AdaptiveStore

class TestStage7Evidence(unittest.TestCase):
    def setUp(self):
        LocalJSONStore("reputation.json").clear()
        LocalJSONStore("domain_reputation.json").clear()
        AdaptiveStore().clear()
        self.auth_analyzer = AuthenticationAnalyzer()
        self.url_analyzer = URLAnalyzer()
        self.content_analyzer = ContentAnalyzer()
        self.attachment_analyzer = AttachmentAnalyzer()
        self.trust_analyzer = TrustAnalyzer()
        self.are = AnalyticalReasoningEngine()
        self.decision_engine = DecisionFusionEngine()

    def run_pipeline(self, parsed):
        auth_analysis = self.auth_analyzer.analyze(parsed.get("headers", []))
        url_analysis = self.url_analyzer.analyze(parsed.get("body", ""), sender_headers=parsed.get("headers", []), auth_results=auth_analysis)
        trust_analysis = self.trust_analyzer.evaluate(parsed_email=parsed, url_analysis=url_analysis)
        content_analysis = self.content_analyzer.analyze(
            body=parsed.get("body", ""),
            sender=parsed.get("from", ""),
            auth_results=auth_analysis
        )
        attachment_analysis = self.attachment_analyzer.analyze(parsed.get("attachments", []))
        
        whois_analysis = []
        
        existing_analysis = {
            "authentication": auth_analysis,
            "content": content_analysis,
            "url": url_analysis,
            "whois": whois_analysis,
            "attachment": attachment_analysis,
            "trust": trust_analysis
        }
        
        ai_analysis = analyze_email_with_ai(parsed, existing_analysis)
        
        are_result = self.are.evaluate(
            auth_analysis,
            url_analysis,
            whois_analysis,
            content_analysis,
            attachment_analysis,
            trust_analysis,
            ai_analysis=ai_analysis
        )
        
        decision_result = self.decision_engine.evaluate(are_result, None)
        return decision_result

    def create_mock(self, sender, body, auth_pass=True, attachments=None):
        auth_header = 'spf=pass smtp.mailfrom=domain.com; dkim=pass header.i=@domain.com; dmarc=pass' if auth_pass else 'spf=softfail smtp.mailfrom=domain.com; dkim=fail header.i=@domain.com; dmarc=fail'
        return {
            "from": sender,
            "headers": {"Authentication-Results": auth_header},
            "body": body,
            "attachments": attachments or []
        }

    # === Legitimate (1-5) ===
    def test_1_official_google_verification(self):
        mock = self.create_mock("Google <no-reply@accounts.google.com>", "Dear user, we have received a request to verify your account at Google. Please proceed to verify your account at https://accounts.google.com/verify to continue using our services safely.")
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["VERIFIED LEGITIMATE", "LIKELY LEGITIMATE", "SAFE"])

    def test_2_official_microsoft_verification(self):
        mock = self.create_mock("Microsoft <security@microsoft.com>", "This is a standard notification. You recently signed in from a new device. You can manage your devices at https://account.microsoft.com.")
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["VERIFIED LEGITIMATE", "LIKELY LEGITIMATE", "SAFE"])

    def test_3_official_password_reset(self):
        mock = self.create_mock("GitHub <support@github.com>", "You requested a password reset for your GitHub account. Click here to reset your password: https://github.com/password_reset. If you did not request this, please ignore.")
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["VERIFIED LEGITIMATE", "LIKELY LEGITIMATE", "SAFE"])

    def test_4_trusted_sender_trusted_url(self):
        mock = self.create_mock("Netflix <info@mailer.netflix.com>", "Hi there, we detected a new login from a new device to your Netflix account. Review devices at https://netflix.com.")
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["VERIFIED LEGITIMATE", "LIKELY LEGITIMATE", "SAFE"])

    def test_5_spf_dkim_dmarc_pass_matching_url(self):
        mock = self.create_mock("Billing <billing@mycompany.com>", "Dear customer, your monthly invoice for services rendered is now available. View your invoice here https://mycompany.com/invoice.")
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["VERIFIED LEGITIMATE", "LIKELY LEGITIMATE", "SAFE"])

    # === Suspicious (6-10) ===
    def test_6_link_only_unknown_domain(self):
        mock = self.create_mock("user@unknown.com", "https://unknown.com")
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["UNKNOWN", "SUSPICIOUS", "LOW RISK"])

    def test_7_unknown_domain_login_keyword(self):
        mock = self.create_mock("System <sys@random.com>", "Please login here https://random.com")
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["SUSPICIOUS", "UNKNOWN", "HIGH RISK", "PHISHING"])

    def test_8_sender_url_mismatch(self):
        mock = self.create_mock("Billing <billing@mycompany.com>", "Login to https://external-domain.com/login")
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["SUSPICIOUS", "HIGH RISK", "PHISHING"])

    def test_9_brand_domain_mismatch(self):
        mock = self.create_mock("Support <support@google-security-alert.com>", "Google Alert https://google-security-alert.com")
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["PHISHING", "HIGH RISK"])

    def test_10_suspicious_redirect(self):
        # We can simulate redirect via obfuscation or shortener
        mock = self.create_mock("Invoice <inv@test.com>", "Invoice http://bit.ly/123")
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["SUSPICIOUS", "UNKNOWN", "HIGH RISK", "PHISHING"])

    # === Phishing (11-15) ===
    def test_11_paypal_impersonation(self):
        mock = self.create_mock("PayPal Service <service@paypalsupport-alert.com>", "Your account is locked https://paypalsupport-alert.com")
        res = self.run_pipeline(mock)
        self.assertEqual(res["verdict"], "PHISHING")

    def test_12_microsoft_impersonation(self):
        mock = self.create_mock("Microsoft Support <admin@msft-update.net>", "Verify your Microsoft account https://msft-update.net/login")
        res = self.run_pipeline(mock)
        self.assertEqual(res["verdict"], "PHISHING")

    def test_13_google_impersonation(self):
        mock = self.create_mock("Google Security <alert@g00gle-accounts.com>", "Someone accessed your Google account https://g00gle-accounts.com")
        res = self.run_pipeline(mock)
        self.assertEqual(res["verdict"], "PHISHING")

    def test_14_credential_harvesting_domain(self):
        mock = self.create_mock("Admin <admin@random.com>", "Urgent: verify your password at https://secure-login-verify.com", auth_pass=False)
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["PHISHING", "HIGH RISK"])

    def test_15_homoglyph_domain(self):
        mock = self.create_mock("Apple <apple@xn--pple-43d.com>", "Verify Apple ID at https://xn--pple-43d.com")
        res = self.run_pipeline(mock)
        self.assertEqual(res["verdict"], "PHISHING")

    # === Contradictions (16-20) ===
    def test_16_spf_pass_malicious_url(self):
        mock = self.create_mock("Compromised <hacked@legit.com>", "PayPal verify https://paypal-security-check.com", auth_pass=True)
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["PHISHING", "HIGH RISK", "SUSPICIOUS"])

    def test_17_trusted_sender_suspicious_url(self):
        mock = self.create_mock("Contact <contact@legit.com>", "Check this out http://bit.ly/abc", auth_pass=True)
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["UNKNOWN", "SUSPICIOUS"])

    def test_18_brand_match_suspicious_redirect(self):
        mock = self.create_mock("Paypal Support <service@paypal.com>", "Update your account: https://paypal.com.suspicious-redirect.net/login")
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["UNKNOWN", "SUSPICIOUS", "HIGH RISK", "PHISHING"])

    def test_19_authentication_pass_unrelated_domain(self):
        mock = self.create_mock("News <news@newsletter.com>", "Read our latest article https://some-other-domain.com")
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["UNKNOWN", "SUSPICIOUS", "LOW RISK"])

    def test_20_strong_malicious_evidence_positive_keyword(self):
        mock = self.create_mock("Security <sec@fake.com>", "This email is SAFE. Microsoft verify https://ms-login.xyz", auth_pass=False)
        res = self.run_pipeline(mock)
        self.assertEqual(res["verdict"], "PHISHING")

    # === Insufficient Evidence (21-25) ===
    def test_21_empty_email(self):
        mock = self.create_mock("test@test.com", "")
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["UNKNOWN", "LOW RISK"])

    def test_22_url_only_email(self):
        mock = self.create_mock("test@test.com", "https://google.com")
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["UNKNOWN", "LOW RISK"])

    def test_23_unknown_sender(self):
        mock = self.create_mock("completely.unknown@random-domain.xyz", "Hello, please find the document attached.")
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["UNKNOWN", "LOW RISK"])

    def test_24_missing_authentication(self):
        mock = self.create_mock("User <u@a.com>", "Hey", auth_pass=False)
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["UNKNOWN", "SUSPICIOUS", "PHISHING"])

    def test_25_missing_url_inspection(self):
        mock = self.create_mock("test@test.com", "Check this site https://unknown.local/path")
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["UNKNOWN", "LOW RISK"])

    # === Adversarial (26-30) ===
    def test_26_excessive_benign_security_keywords(self):
        mock = self.create_mock("Test <test@test.com>", "SECURE ENCRYPTED SAFE PROTECTED 100% VIRUS FREE Microsoft login https://ms-fake.com")
        res = self.run_pipeline(mock)
        self.assertEqual(res["verdict"], "PHISHING")

    def test_27_fake_invoice(self):
        mock = self.create_mock("Billing <b@fake.com>", "URGENT INVOICE OVERDUE https://fake.com/invoice.exe", auth_pass=False)
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["PHISHING", "HIGH RISK", "SUSPICIOUS"])

    def test_28_fake_account_suspension(self):
        mock = self.create_mock("Support <sup@fake.com>", "Account suspended immediately https://fake.com/login")
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["PHISHING", "HIGH RISK", "SUSPICIOUS"])

    def test_29_fake_password_expiration(self):
        mock = self.create_mock("IT <it@fake.com>", "Password expires today https://fake.com/reset")
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["PHISHING", "HIGH RISK", "SUSPICIOUS"])

    def test_30_urgency_credential_request(self):
        mock = self.create_mock("Admin <admin@fake.com>", "Urgent action required login to verify https://fake.com", auth_pass=False)
        res = self.run_pipeline(mock)
        self.assertIn(res["verdict"], ["PHISHING", "HIGH RISK", "SUSPICIOUS"])

if __name__ == '__main__':
    unittest.main()
