import unittest
import os
import shutil
from src.ai.adaptive_intelligence import AdaptiveIntelligenceEngine
from src.engines.are import AnalyticalReasoningEngine
from src.storage.adaptive_store import get_adaptive_store

class TestStage10AdaptiveIntelligence(unittest.TestCase):
    def setUp(self):
        get_adaptive_store().clear()
        # Create a fresh store instance by ensuring files don't leak from other tests
        if os.path.exists("sender_baseline.json"): os.remove("sender_baseline.json")
        if os.path.exists("domain_baseline.json"): os.remove("domain_baseline.json")
        if os.path.exists("url_history.json"): os.remove("url_history.json")
        if os.path.exists("trend_history.json"): os.remove("trend_history.json")
        
        self.engine = AdaptiveIntelligenceEngine()
        self.are = AnalyticalReasoningEngine()

    def tearDown(self):
        if os.path.exists("sender_baseline.json"): os.remove("sender_baseline.json")
        if os.path.exists("domain_baseline.json"): os.remove("domain_baseline.json")
        if os.path.exists("url_history.json"): os.remove("url_history.json")
        if os.path.exists("trend_history.json"): os.remove("trend_history.json")

    def test_01_insufficient_history(self):
        # New sender
        result = self.engine.generate_adaptive_evidence(
            sender="new@test.com",
            domain="test.com",
            current_auth={"spf": "pass"},
            current_verdict="UNKNOWN",
            current_score=10,
            urls=[]
        )
        self.assertEqual(result["history_confidence"]["level"], "VERY_LOW")
        self.assertEqual(len(result["behavioral_anomalies"]), 0)

    def test_02_trusted_sender_normal_behavior(self):
        # Build history
        for _ in range(30):
            self.engine.generate_adaptive_evidence(
                sender="trusted@test.com",
                domain="test.com",
                current_auth={"spf": "pass"},
                current_verdict="SAFE",
                current_score=0,
                urls=[]
            )
            
        result = self.engine.generate_adaptive_evidence(
            sender="trusted@test.com",
            domain="test.com",
            current_auth={"spf": "pass"},
            current_verdict="SAFE",
            current_score=0,
            urls=[]
        )
        self.assertEqual(result["history_confidence"]["level"], "HIGH")
        self.assertEqual(len(result["behavioral_anomalies"]), 0)

    def test_03_authentication_drift(self):
        # Build history
        for _ in range(10):
            self.engine.generate_adaptive_evidence(
                sender="auth@test.com",
                domain="test.com",
                current_auth={"spf": "pass"},
                current_verdict="SAFE",
                current_score=0,
                urls=[]
            )
            
        # Auth fails
        result = self.engine.generate_adaptive_evidence(
            sender="auth@test.com",
            domain="test.com",
            current_auth={"spf": "fail"},
            current_verdict="UNKNOWN",
            current_score=40,
            urls=[]
        )
        
        anoms = result["behavioral_anomalies"]
        self.assertTrue(any(a["type"] == "AUTHENTICATION_DRIFT" for a in anoms))

    def test_04_domain_drift(self):
        for _ in range(10):
            self.engine.generate_adaptive_evidence(
                sender="drift@test.com",
                domain="test.com",
                current_auth={"spf": "pass"},
                current_verdict="SAFE",
                current_score=0,
                urls=[]
            )
            
        result = self.engine.generate_adaptive_evidence(
            sender="drift@test.com",
            domain="evil.com",
            current_auth={"spf": "pass"},
            current_verdict="UNKNOWN",
            current_score=20,
            urls=[]
        )
        anoms = result["behavioral_anomalies"]
        self.assertTrue(any(a["type"] == "DOMAIN_DRIFT" for a in anoms))

    def test_05_shared_url_infrastructure(self):
        # Sender 1 uses URL
        self.engine.generate_adaptive_evidence(
            sender="user1@a.com",
            domain="a.com",
            current_auth={"spf": "pass"},
            current_verdict="SAFE",
            current_score=0,
            urls=["http://shared.com/login"]
        )
        
        # Sender 2 uses same URL
        result = self.engine.generate_adaptive_evidence(
            sender="user2@b.com",
            domain="b.com",
            current_auth={"spf": "pass"},
            current_verdict="UNKNOWN",
            current_score=0,
            urls=["http://shared.com/login"]
        )
        
        anoms = result["behavioral_anomalies"]
        self.assertTrue(any(a["type"] == "SHARED_INFRASTRUCTURE" for a in anoms))

    def test_06_are_integration(self):
        # Simulate ARE receiving adaptive anomaly
        are_result = {
            "risk_score": 10,
            "confidence": 90,
            "adaptive": {
                "behavioral_anomalies": [
                    {
                        "type": "AUTHENTICATION_DRIFT",
                        "severity": "HIGH",
                        "explanation": "Test drift"
                    }
                ],
                "risk_trend": {"trend": "STABLE"},
                "history_confidence": {"level": "HIGH"}
            }
        }
        
        # We test how ARE maps it. In real usage `evaluate` processes raw parts. 
        # The adaptive logic is inside evaluate. We mock the required arguments.
        res = self.are.evaluate(
            authentication={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            url_analysis={"analysis": []},
            whois_analysis=[],
            content_analysis={"urgency": False, "credential_request": False, "financial_request": False, "impersonation": False, "threat_language": False},
            attachment_analysis={"risk_score": 0, "evidence": []},
            trust_analysis={"trust_score": 50},
            ai_analysis={"adaptive": are_result["adaptive"]}
        )
        
        # ARE should boost score due to behavioral anomaly
        self.assertTrue(res["risk_score"] >= 20)
        self.assertEqual(res["detail_verdict"], "AUTHENTICATION_DRIFT")

if __name__ == "__main__":
    unittest.main()
