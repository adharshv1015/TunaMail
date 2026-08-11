import unittest
from .inference import analyze_email

class TestAILayer(unittest.TestCase):
    
    def test_a_link_only_false(self):
        # "Verify your account: https://example.com"
        email_data = {
            "body": "Verify your account: https://example.com"
        }
        res = analyze_email(email_data, {})
        self.assertFalse(res["link_only"])
        
    def test_b_link_only_true(self):
        # "https://example.com"
        email_data = {
            "body": "https://example.com"
        }
        res = analyze_email(email_data, {})
        self.assertTrue(res["link_only"])
        self.assertTrue(res["limited_context"])
        
    def test_c_empty_body(self):
        # Empty email body -> UNKNOWN / INSUFFICIENT_EVIDENCE
        email_data = {
            "body": ""
        }
        res = analyze_email(email_data, {})
        self.assertEqual(res["predicted_class"], "UNKNOWN")
        self.assertEqual(res["reasoning_state"], "INSUFFICIENT_EVIDENCE")
        
    def test_d_legit_strong_auth(self):
        # Legitimate-looking email with strong positive auth/domain
        email_data = {
            "subject": "Monthly Newsletter",
            "body": "Here is our monthly newsletter. We hope you enjoy reading our updates. Visit our site to learn more.",
            "from": "newsletter@example.com"
        }
        analysis_data = {
            "authentication": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            "url": {"analysis": []} # no malicious URLs
        }
        res = analyze_email(email_data, analysis_data)
        # Model may predict LEGITIMATE (since we bootstrap dev dataset)
        # Even if it predicts LIKELY_LEGITIMATE or SAFE, the reasoning state should be SUFFICIENT_EVIDENCE
        self.assertIn(res["predicted_class"], ["LEGITIMATE", "LIKELY_LEGITIMATE", "SAFE"])
        self.assertEqual(res["reasoning_state"], "SUFFICIENT_EVIDENCE")

    def test_e_brand_mismatch(self):
        # Brand mismatch -> CONFLICTING_EVIDENCE or SUSPICIOUS
        email_data = {
            "body": "This is legitimate! Visit https://google-login-update.com",
            "subject": "Important Google Update"
        }
        analysis_data = {
            # Let's say model thinks it's legit based on body, but brand mismatch
            "authentication": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            "url": {
                "analysis": [
                    {
                        "brand_impersonation": True, # brand match < 0
                        "tls": {"certificate_valid": True},
                        "dns": {"resolved": True}
                    }
                ]
            }
        }
        # Fake a scenario where model MIGHT think it's legit, but the reasoning catches the brand mismatch
        res = analyze_email(email_data, analysis_data)
        # The reasoning engine forces it to SUSPICIOUS if model thought it was benign
        self.assertIn(res["reasoning_state"], ["CONFLICTING_EVIDENCE", "SUFFICIENT_EVIDENCE"])
        if res["reasoning_state"] == "CONFLICTING_EVIDENCE":
            self.assertEqual(res["predicted_class"], "SUSPICIOUS")
            
    def test_f_no_suspicious_keywords_but_unknown_url(self):
        # No suspicious keywords but unknown URL
        # Must NOT automatically produce SAFE.
        email_data = {
            "body": "https://random-unknown-domain.com"
        }
        analysis_data = {
            "authentication": {"spf": "none", "dkim": "none", "dmarc": "none"}
        }
        res = analyze_email(email_data, analysis_data)
        self.assertNotIn(res["predicted_class"], ["LEGITIMATE", "LIKELY_LEGITIMATE", "SAFE"])

if __name__ == '__main__':
    unittest.main()
