import unittest
from unittest.mock import patch
from .orchestrator import analyze_email_with_ai
from src.engines.are import AnalyticalReasoningEngine
from src.engines.decision_fusion_engine import DecisionFusionEngine

class TestStage2(unittest.TestCase):
    def setUp(self):
        self.are = AnalyticalReasoningEngine()
        self.decision_engine = DecisionFusionEngine()
        
    def _run_pipeline(self, parsed_email, auth, url, content, attachment, whois, trust, mock_pred="UNKNOWN", mock_link_only=False, mock_limited_context=False):
        
        existing_analysis = {
            "authentication": auth,
            "url": url,
            "content": content,
            "attachment": attachment,
            "whois": whois,
            "trust": trust
        }
        
        with patch('src.ai.orchestrator.analyze_email') as mock_analyze:
            mock_analyze.return_value = {
                "predicted_class": mock_pred,
                "confidence": 85.0,
                "link_only": mock_link_only,
                "limited_context": mock_limited_context,
                "features": {}
            }
            ai_analysis = analyze_email_with_ai(parsed_email, existing_analysis)
        
        are_result = self.are.evaluate(
            auth, url, whois, content, attachment, trust, ai_analysis=ai_analysis
        )
        
        decision = self.decision_engine.evaluate(are_result)
        return ai_analysis, decision
        
    def test_1_link_only(self):
        parsed = {"body": "https://random-example-domain.com"}
        ai, decision = self._run_pipeline(
            parsed, 
            {"spf": "none", "dkim": "none", "dmarc": "none"},
            {"urls": ["https://random-example-domain.com"], "limited_context": True, "analysis": []},
            {"urgency": False, "credential_request": False, "financial_request": False, "impersonation": False, "threat_language": False},
            {"risk_score": 0, "evidence": []},
            [],
            {"trust_score": 0},
            mock_pred="UNKNOWN",
            mock_link_only=True,
            mock_limited_context=True
        )
        self.assertTrue(ai["link_only"])
        self.assertEqual(ai["reasoning_state"], "LIMITED_CONTEXT")
        self.assertIn(decision["verdict"], ["UNKNOWN", "SUSPICIOUS"])

    def test_2_empty_email(self):
        parsed = {"body": "", "subject": ""}
        ai, decision = self._run_pipeline(
            parsed,
            {"spf": "none", "dkim": "none", "dmarc": "none"},
            {"urls": [], "limited_context": True, "analysis": []},
            {"urgency": False, "credential_request": False, "financial_request": False, "impersonation": False, "threat_language": False},
            {"risk_score": 0, "evidence": []},
            [],
            {"trust_score": 0},
            mock_pred="UNKNOWN",
            mock_link_only=False,
            mock_limited_context=True
        )
        self.assertEqual(ai["reasoning_state"], "INSUFFICIENT_EVIDENCE")
        self.assertIn(decision["verdict"], ["UNKNOWN", "SUSPICIOUS"])
        
    def test_3_legitimate_verification(self):
        parsed = {"from": "security@example.com", "body": "Your security report is ready. https://example.com/report"}
        ai, decision = self._run_pipeline(
            parsed,
            {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            {"urls": ["https://example.com/report"], "limited_context": False, "analysis": [
                {"domain": "example.com", "tls": {"certificate_valid": True}, "email_alignment": "aligned"}
            ]},
            {"urgency": False, "credential_request": False, "financial_request": False, "impersonation": False, "threat_language": False},
            {"risk_score": 0, "evidence": []},
            [],
            {"trust_score": 50},
            mock_pred="LEGITIMATE",
            mock_link_only=False,
            mock_limited_context=False
        )
        # Should be LIKELY or VERIFIED LEGITIMATE
        self.assertIn(decision["verdict"], ["LIKELY LEGITIMATE", "VERIFIED LEGITIMATE"])
        self.assertEqual(ai["reasoning_state"], "SUFFICIENT_EVIDENCE")
        
    def test_4_keyword_only(self):
        parsed = {"body": "Verify your account immediately."}
        ai, decision = self._run_pipeline(
            parsed,
            {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            {"urls": [], "limited_context": False, "analysis": []},
            {"urgency": True, "credential_request": True, "financial_request": False, "impersonation": False, "threat_language": False},
            {"risk_score": 0, "evidence": []},
            [],
            {"trust_score": 0},
            mock_pred="SUSPICIOUS",
            mock_link_only=False,
            mock_limited_context=False
        )
        # Contextual only, risk might be SUSPICIOUS but not automatically PHISHING
        self.assertNotEqual(decision["verdict"], "PHISHING")
        
    def test_5_brand_impersonation(self):
        parsed = {"from": "security@paypal.com", "body": "Verify https://paypal-security.example.com"}
        ai, decision = self._run_pipeline(
            parsed,
            {"spf": "none", "dkim": "none", "dmarc": "none"},
            {"urls": ["https://paypal-security.example.com"], "limited_context": False, "analysis": [
                {"domain": "paypal-security.example.com", "brand_impersonation": True}
            ]},
            {"urgency": False, "credential_request": False, "financial_request": False, "impersonation": False, "threat_language": False},
            {"risk_score": 0, "evidence": []},
            [],
            {"trust_score": 0},
            mock_pred="PHISHING",
            mock_link_only=False,
            mock_limited_context=False
        )
        self.assertIn(decision["verdict"], ["SUSPICIOUS", "HIGH RISK", "PHISHING"])
        
    def test_6_auth_pass_bad_url(self):
        parsed = {"from": "security@example.com", "body": "Verify https://bad-domain.com"}
        ai, decision = self._run_pipeline(
            parsed,
            {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            {"urls": ["https://bad-domain.com"], "limited_context": False, "analysis": [
                {"domain": "bad-domain.com", "email_alignment": "misaligned"}
            ]},
            {"urgency": False, "credential_request": False, "financial_request": False, "impersonation": False, "threat_language": False},
            {"risk_score": 0, "evidence": []},
            [],
            {"trust_score": 0},
            mock_pred="LEGITIMATE",
            mock_link_only=False,
            mock_limited_context=False
        )
        self.assertIn("CONFLICTING_EVIDENCE", ai["reasoning_state"] + str(ai["contradictions"]))
        self.assertNotIn(decision["verdict"], ["VERIFIED LEGITIMATE"])
        
    def test_7_unknown_url(self):
        parsed = {"body": "https://random-new-domain.example"}
        ai, decision = self._run_pipeline(
            parsed,
            {"spf": "none", "dkim": "none", "dmarc": "none"},
            {"urls": ["https://random-new-domain.example"], "limited_context": True, "analysis": []},
            {"urgency": False, "credential_request": False, "financial_request": False, "impersonation": False, "threat_language": False},
            {"risk_score": 0, "evidence": []},
            [],
            {"trust_score": 0},
            mock_pred="UNKNOWN",
            mock_link_only=True,
            mock_limited_context=True
        )
        self.assertIn(decision["verdict"], ["UNKNOWN", "SUSPICIOUS"])
        self.assertEqual(ai["reasoning_state"], "LIMITED_CONTEXT")
        
    def test_8_internal_url(self):
        from src.services.url_inspection_service import URLInspectionService
        service = URLInspectionService()
        res = service.inspect("http://127.0.0.1/")
        self.assertTrue(res["dns"]["private_ip_detected"])
        
    def test_9_cloud_metadata(self):
        from src.services.url_inspection_service import URLInspectionService
        service = URLInspectionService()
        res = service.inspect("http://169.254.169.254/")
        self.assertTrue(res["dns"]["private_ip_detected"])

    def test_10_legitimate_url(self):
        from src.services.url_inspection_service import URLInspectionService
        service = URLInspectionService()
        res = service.inspect("https://accounts.google.com/")
        self.assertFalse(res["dns"]["private_ip_detected"])

if __name__ == '__main__':
    unittest.main()
