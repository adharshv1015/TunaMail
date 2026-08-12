import os
import pytest
import time
import threading
from unittest.mock import patch, MagicMock

from src.services.url_cache import URLCache
from src.services.whois_cache import WhoisCache
from src.ai.inference_cache import InferenceCache
from src.services.analysis_cache import AnalysisCache, analysis_cache
from src.api.gmail import process_single_message, MAX_URLS_PER_EMAIL, MAX_BODY_BYTES, MAX_EMAIL_ANALYSIS_SECONDS
from src.storage.local_store import LocalJSONStore
from src.storage.store_maintenance import run_maintenance
from src.ai.analyst_feedback import process_analyst_feedback
from src.analyzers.url_analyzer import URLAnalyzer
from src.connectors.gmail_parser import GmailParser
from src.monitoring.performance import PerformanceTracker


# ==============================================================================
# Mocks & Fixtures
# ==============================================================================

class MockConnector:
    def __init__(self, message_data=None):
        self.message_data = message_data or {
            "id": "msg_test_1",
            "payload": {
                "headers": [
                    {"name": "From", "value": "test@example.com"},
                    {"name": "Subject", "value": "Test Subject"}
                ],
                "body": {"data": "SGVsbG8gV29ybGQ="} # Base64 "Hello World"
            }
        }
        
    def get_message(self, message_id):
        if hasattr(self.message_data, "copy"):
            msg = self.message_data.copy()
            msg["id"] = message_id
            return msg
        return self.message_data


@pytest.fixture(autouse=True)
def clean_caches():
    URLCache().clear()
    WhoisCache().clear()
    InferenceCache().clear()
    analysis_cache.clear()
    
    with patch('whois.whois') as mock_whois, patch('src.analyzers.url_analyzer.URLInspectionService.inspect') as mock_inspect:
        mock_data = MagicMock()
        mock_data.creation_date = None
        mock_data.expiration_date = None
        mock_data.registrar = "Test Registrar"
        mock_data.country = "US"
        mock_whois.return_value = mock_data
        
        # Mock URL inspection to avoid real DNS/HTTP/SSL calls
        mock_inspect.return_value = {
            "registered_domain": "example.com",
            "domain": "example.com",
            "dns": {"resolved": True},
            "tls": {"valid": True},
            "http": {"reachable": True},
            "redirects": {"detected": False},
            "threat_intelligence": {"status": "unavailable"}
        }
        
        yield mock_whois
        
    URLCache().clear()
    WhoisCache().clear()
    InferenceCache().clear()
    analysis_cache.clear()


# ==============================================================================
# Test Cases
# ==============================================================================

@pytest.mark.stage14
class TestStage14Performance:

    def test_01_same_url_repeated(self):
        """1. Same URL repeated 10 times."""
        analyzer = URLAnalyzer()
        # Repeated URLs should be deduplicated inside URLAnalyzer
        body = " ".join(["http://example.com/test"] * 10)
        result = analyzer.analyze(body)
        assert len(result["urls"]) == 1
        assert result["urls"][0] == "http://example.com/test"

    def test_02_same_domain_whois_caching(self, clean_caches):
        """2. Same domain across 10 emails."""
        from src.api.gmail import get_analyzers
        analyzers = get_analyzers()
        whois_analyzer = analyzers["whois"]
        
        mock_whois = clean_caches
        
        for _ in range(10):
            whois_analyzer.analyze("example.com")
        
        # Should only actually query once
        assert mock_whois.call_count == 1
            
        stats = WhoisCache().statistics()
        assert stats["hits"] == 9
        assert stats["misses"] == 1

    def test_03_same_message_requested_twice(self):
        """3. Same message requested twice (AnalysisCache hit)."""
        connector = MockConnector()
        msg_id = "msg_double_request"
        
        # First request
        res1 = process_single_message(connector, msg_id)
        assert res1 is not None
        
        # Second request
        res2 = process_single_message(connector, msg_id)
        
        stats = analysis_cache.statistics()
        assert stats["hits"] == 1
        assert stats["misses"] == 1

    def test_04_simultaneous_requests(self):
        """4. Two simultaneous requests for same message (single flight lock)."""
        connector = MockConnector()
        msg_id = "msg_simultaneous"
        
        results = []
        def fetch():
            results.append(process_single_message(connector, msg_id))
            
        t1 = threading.Thread(target=fetch)
        t2 = threading.Thread(target=fetch)
        
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        # One must be a miss, one must be a hit because of the lock
        stats = analysis_cache.statistics()
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert len(results) == 2

    def test_05_large_email_truncation(self):
        """5. Large email handling."""
        large_body = "A" * (MAX_BODY_BYTES + 1000)
        # We need a custom connector to feed the large body properly (base64 encoded)
        import base64
        encoded = base64.b64encode(large_body.encode()).decode()
        
        connector = MockConnector({
            "id": "msg_large",
            "payload": {
                "headers": [
                    {"name": "From", "value": "test@example.com"},
                    {"name": "Subject", "value": "Test Large Body"}
                ],
                "body": {"data": encoded}
            }
        })
        
        res = process_single_message(connector, "msg_large")
        
        assert res["body_truncation"]["truncated"] is True
        assert res["body_truncation"]["original_length"] > MAX_BODY_BYTES
        assert len(res["body"].encode("utf-8")) == MAX_BODY_BYTES

    def test_06_large_url_list(self):
        """6. Large URL list handling."""
        urls = [f"http://example{i}.com/test" for i in range(MAX_URLS_PER_EMAIL + 10)]
        body = " ".join(urls)
        
        import base64
        encoded = base64.b64encode(body.encode()).decode()
        
        connector = MockConnector({
            "id": "msg_many_urls",
            "payload": {
                "headers": [
                    {"name": "From", "value": "test@example.com"},
                    {"name": "Subject", "value": "Test Large URLs"}
                ],
                "body": {"data": encoded}
            }
        })
        
        res = process_single_message(connector, "msg_many_urls")
        url_data = res["analysis"]["url"]
        
        assert url_data["truncated"] is True
        assert url_data["original_url_count"] == MAX_URLS_PER_EMAIL + 10
        assert url_data["processed_url_count"] == MAX_URLS_PER_EMAIL
        assert len(url_data["analysis"]) == MAX_URLS_PER_EMAIL

    def test_07_corrupted_json_store(self, tmp_path):
        """7. Corrupted JSON store resilience."""
        test_file = tmp_path / "corrupt.json"
        with open(test_file, "w") as f:
            f.write("{invalid_json: true,") # broken json
            
        store = LocalJSONStore(str(test_file))
        data = store.get_all()
        assert data == {} # Should initialize empty without crashing

    def test_08_concurrent_reputation_updates(self, tmp_path):
        """8. Concurrent reputation updates."""
        test_file = tmp_path / "rep.json"
        store = LocalJSONStore(str(test_file))
        
        def update():
            with store.lock:
                data = store.get_all()
                count = data.get("count", 0)
                data["count"] = count + 1
                store._atomic_write(data)
                store._cache = data
                
        threads = [threading.Thread(target=update) for _ in range(50)]
        for t in threads: t.start()
        for t in threads: t.join()
        
        assert store.get_all()["count"] == 50

    def test_09_repeated_feedback_submission(self):
        """9. Repeated feedback submission."""
        process_analyst_feedback("msg_f1", "test@example.com", "MALICIOUS", "Test 1", "UNKNOWN", 0)
        process_analyst_feedback("msg_f1", "test@example.com", "SAFE", "Test 2", "MALICIOUS", 100)
        
        from src.storage.feedback_store import get_feedback_store
        store = get_feedback_store()
        data = store.store.get_all()
        
        assert "msg_f1" in data
        assert data["msg_f1"]["analyst_label"] == "SAFE"
        assert data["msg_f1"]["reason"] == "Test 2"

    def test_10_repeated_local_ai_inference(self):
        """10. Repeated local AI inference."""
        from src.ai.orchestrator import analyze_email_with_ai
        
        parsed = {"from": "test@example.com", "subject": "AI test", "body": "test"}
        existing = {}
        
        with patch('src.ai.orchestrator.AIOrchestrator.analyze_email_with_ai', return_value={"reasoning_state": "TEST"}) as mock_run:
            for _ in range(5):
                analyze_email_with_ai(parsed, existing)
                
            assert mock_run.call_count == 1
            
        stats = InferenceCache().statistics()
        assert stats["hits"] >= 4

    def test_11_campaign_with_large_history(self, tmp_path):
        """11. Campaign with large history & Store Maintenance."""
        # Setup fake campaign data
        from src.storage.campaign_store import get_campaign_store
        store = get_campaign_store()
        store.store._cache = {} # clear
        
        now = time.time()
        
        # 1 recent, 1 old
        store.store._atomic_write({
            "camp_recent": {"last_seen": now},
            "camp_old": {"last_seen": now - (90 * 86400)} # 90 days old
        })
        store.store._cache = None
        store.store._load()
        
        res = run_maintenance()
        assert res["campaign_pruned"] == 1
        
        data = store.store.get_all()
        assert "camp_recent" in data
        assert "camp_old" not in data

    def test_12_cache_eviction(self):
        """12. Cache eviction."""
        # Temporarily mock MAX_CACHE_ENTRIES
        import src.services.url_cache as uc
        orig_max = uc.MAX_CACHE_ENTRIES
        uc.MAX_CACHE_ENTRIES = 5
        
        cache = URLCache()
        cache.clear()
        
        for i in range(10):
            cache.set(f"key_{i}", {"data": "test"})
            time.sleep(0.01) # ensure different last_accessed
            
        stats = cache.statistics()
        # It should evict down to max entries. Note that the logic evicts 10% when full.
        # So it stays around the limit.
        assert stats["entries"] <= 5
        assert stats["evictions"] > 0
        
        uc.MAX_CACHE_ENTRIES = orig_max

    def test_13_cache_ttl_expiry(self):
        """13. Cache TTL expiry."""
        import src.services.url_cache as uc
        orig_ttl = uc.URL_CACHE_TTL_SECONDS
        uc.URL_CACHE_TTL_SECONDS = 0.1
        
        cache = URLCache()
        cache.set("ttl_key", {"data": "val"})
        
        # Immediately available
        assert cache.get("ttl_key") is not None
        
        # Wait for TTL
        time.sleep(0.15)
        
        assert cache.get("ttl_key") is None
        assert cache.statistics()["misses"] >= 1
        
        uc.URL_CACHE_TTL_SECONDS = orig_ttl

    def test_14_analysis_timeout(self):
        """14. Analysis timeout."""
        # If we have a tiny budget, AI should time out
        connector = MockConnector()
        msg_id = "msg_timeout"
        
        with patch('src.api.gmail.MAX_EMAIL_ANALYSIS_SECONDS', 0.0001): # Instant timeout
            # We mock time.monotonic to ensure it takes time if needed, 
            # or just rely on normal execution taking > 0.1ms
            time.sleep(0.01) 
            res = process_single_message(connector, msg_id)
            
        ai = res["analysis"]["ai"]
        assert ai["enabled"] is False
        assert "timeout" in ai["reasoning_summary"].lower()
        
        pipeline = res["analysis"]["pipeline"]
        assert pipeline["timeout_count"] > 0
        timeout_names = [t["analyzer"] for t in pipeline["timeouts"]]
        assert "WhoisAnalyzer" in timeout_names or "LocalAI" in timeout_names

    def test_15_analyzer_failure(self):
        """15. Analyzer failure handling."""
        connector = MockConnector({
            "id": "msg_crash",
            "payload": {
                "headers": [{"name": "From", "value": "test@example.com"}, {"name": "Subject", "value": "Crash"}],
                "body": {"data": "test"}
            }
        })
        
        with patch('src.analyzers.url_analyzer.URLAnalyzer.analyze', side_effect=Exception("Crash")):
            res = process_single_message(connector, "msg_crash")
            
        # Should not bring down the whole pipeline
        assert res["analysis"]["url"] == {"analysis_status": "UNAVAILABLE"}
        
        # Pipeline status should be COMPLETED even if a stage failed inside safe_analyze
        pipeline = res["analysis"]["pipeline"]
        assert pipeline["status"] == "COMPLETED"
