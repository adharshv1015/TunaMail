import unittest
import os
import json
from src.ai.evidence_model import EvidenceItem, EvidenceCategory, EvidenceSeverity, EvidenceDirection
from src.engines.decision_fusion_engine import DecisionFusionEngine
from src.ai.analyst_feedback import process_analyst_feedback, get_analyst_feedback
from src.storage.audit_store import get_audit_store

class TestStage9Explainability(unittest.TestCase):
    def setUp(self):
        self.engine = DecisionFusionEngine()
        
    def tearDown(self):
        if os.path.exists("feedback.json"):
            os.remove("feedback.json")
        if os.path.exists("audit.json"):
            os.remove("audit.json")

    def test_01_explanation_generation_phishing(self):
        are_result = {
            "risk_score": 85,
            "confidence": 90,
            "structured_evidence": [
                {
                    "category": "url",
                    "type": "known_malicious",
                    "severity": "CRITICAL",
                    "direction": "NEGATIVE",
                    "explanation": "Known malicious URL detected: http://phish.com",
                    "supports": "MALICIOUS"
                }
            ]
        }
        res = self.engine.evaluate(are_result)
        self.assertEqual(res["verdict"], "PHISHING")
        
        explanation = res["explanation"]
        self.assertEqual(explanation["summary"], "Phishing detected.")
        self.assertTrue("Known malicious URL" in explanation["primary_reason"])
        self.assertEqual(len(explanation["negative_evidence"]), 1)
        self.assertEqual(len(explanation["positive_evidence"]), 0)

    def test_02_explanation_generation_legitimate(self):
        are_result = {
            "risk_score": 10,
            "confidence": 95,
            "structured_evidence": [
                {
                    "category": "authentication",
                    "type": "spf_pass",
                    "severity": "INFO",
                    "direction": "POSITIVE",
                    "explanation": "SPF pass",
                    "supports": "BENIGN"
                }
            ]
        }
        res = self.engine.evaluate(are_result)
        self.assertEqual(res["verdict"], "VERIFIED LEGITIMATE")
        
        explanation = res["explanation"]
        self.assertTrue("Verified legitimate based on" in explanation["primary_reason"])
        self.assertEqual(len(explanation["negative_evidence"]), 0)
        self.assertEqual(len(explanation["positive_evidence"]), 1)

    def test_03_limitations_and_contradictions(self):
        are_result = {
            "risk_score": 65,
            "confidence": 50,
            "detail_verdict": "CONFLICTING_EVIDENCE",
            "structured_evidence": []
        }
        res = self.engine.evaluate(are_result)
        self.assertEqual(res["verdict"], "HIGH RISK")
        explanation = res["explanation"]
        self.assertTrue(len(explanation["limitations"]) > 0)

    def test_04_analyst_feedback_persistence(self):
        process_analyst_feedback(
            message_id="msg_123",
            sender="test@test.com",
            label="CONFIRMED_PHISHING",
            reason="I checked the URL manually",
            previous_verdict="UNKNOWN",
            previous_risk_score=50
        )
        
        fb = get_analyst_feedback("msg_123")
        self.assertIsNotNone(fb)
        self.assertEqual(fb["analyst_label"], "CONFIRMED_PHISHING")
        self.assertEqual(fb["reason"], "I checked the URL manually")
        
        # Check audit store
        logs = get_audit_store().get_events("msg_123")
        self.assertTrue(len(logs) > 0)
        self.assertEqual(logs[0]["event"], "ANALYST_FEEDBACK")

    def test_05_link_only_context(self):
        are_result = {
            "risk_score": 20,
            "confidence": 40,
            "detail_verdict": "LINK_ONLY",
            "structured_evidence": []
        }
        res = self.engine.evaluate(are_result)
        explanation = res["explanation"]
        self.assertTrue("Limited email context" in explanation["primary_reason"])

if __name__ == "__main__":
    unittest.main()
