import datetime
from src.storage.adaptive_store import get_adaptive_store
from src.ai.risk_trend import RiskTrendEngine
from src.ai.url_history import URLHistoryTracker


class AdaptiveIntelligenceEngine:
    def __init__(self):
        self.store = get_adaptive_store()
        self.trend_engine = RiskTrendEngine()
        self.url_tracker = URLHistoryTracker()

    def calculate_history_confidence(self, size: int) -> tuple[str, float]:
        if size <= 1:
            return ("VERY_LOW", 0.1)
        elif size <= 5:
            return ("LOW", 0.3)
        elif size <= 20:
            return ("MEDIUM", 0.6)
        elif size <= 100:
            return ("HIGH", 0.85)
        else:
            return ("VERY_HIGH", 0.98)

    def analyze_sender(self, sender: str, current_auth: dict, current_domain: str, risk_score: int):
        if not sender:
            return None, []

        baseline = self.store.get_sender_baseline(sender)
        anomalies = []

        # Check if insufficient history
        history_size = baseline.get("messages_analyzed", 0)
        conf_level, conf_val = self.calculate_history_confidence(history_size)

        if history_size > 0:
            # 1. Authentication Drift
            hist_auth = baseline.get("normal_authentication", {})
            if hist_auth:
                if hist_auth.get("spf") == "pass" and current_auth.get("spf") != "pass":
                    anomalies.append({
                        "type": "AUTHENTICATION_DRIFT",
                        "severity": "HIGH",
                        "confidence": conf_val,
                        "explanation": "Sender historically passed SPF but current message failed."
                    })

            # 2. Domain Drift
            normal_domains = baseline.get("normal_domains", [])
            if current_domain and normal_domains and current_domain not in normal_domains:
                anomalies.append({
                    "type": "DOMAIN_DRIFT",
                    "severity": "HIGH",
                    "confidence": conf_val,
                    "explanation": (
                        f"Sender historically used {', '.join(normal_domains)} "
                        f"but now uses {current_domain}."
                    )
                })

        # Append trend
        self.store.append_trend_history(sender, risk_score)
        trend_history = self.store.get_trend_history(sender)
        trend_data = self.trend_engine.evaluate_trend(trend_history)

        # Update baseline
        if current_domain and current_domain not in baseline.get("normal_domains", []):
            normal_domains = baseline.get("normal_domains", [])
            normal_domains.append(current_domain)
            baseline["normal_domains"] = normal_domains

        if current_auth.get("spf") == "pass":
            hist_auth = baseline.get("normal_authentication", {})
            hist_auth["spf"] = "pass"
            baseline["normal_authentication"] = hist_auth

        baseline["messages_analyzed"] = history_size + 1
        if "first_seen" not in baseline:
            baseline["first_seen"] = datetime.datetime.utcnow().isoformat()
        baseline["last_seen"] = datetime.datetime.utcnow().isoformat()

        self.store.update_sender_baseline(sender, baseline)

        return {
            "baseline": baseline,
            "trend": trend_data,
            "history_confidence": {
                "level": conf_level,
                "score": conf_val
            }
        }, anomalies

    def analyze_domain(self, domain: str, current_auth: dict):
        if not domain:
            return None

        baseline = self.store.get_domain_baseline(domain)
        history_size = baseline.get("messages_analyzed", 0)

        # Simple update
        baseline["messages_analyzed"] = history_size + 1
        if "first_seen" not in baseline:
            baseline["first_seen"] = datetime.datetime.utcnow().isoformat()
        baseline["last_seen"] = datetime.datetime.utcnow().isoformat()

        self.store.update_domain_baseline(domain, baseline)
        return baseline

    def analyze_url_infrastructure(self, urls: list, sender: str):
        if not urls or not sender:
            return [], []

        shared = self.url_tracker.analyze_infrastructure(self.store, urls, sender)

        anomalies = []
        for s in shared:
            anomalies.append({
                "type": "SHARED_INFRASTRUCTURE",
                "severity": "HIGH",
                "confidence": 0.9,
                "explanation": (
                    f"URL infrastructure ({s['url']}) has been observed across "
                    f"{s['previous_senders']} other senders."
                )
            })

        # Update store
        for url in urls:
            sanitized = self.url_tracker.sanitize_url(url)
            hist = self.store.get_url_history(sanitized)
            senders = hist.get("senders", [])
            if sender not in senders:
                senders.append(sender)
            hist["senders"] = senders
            hist["last_seen"] = datetime.datetime.utcnow().isoformat()
            self.store.update_url_history(sanitized, hist)

        return shared, anomalies

    def generate_adaptive_evidence(
        self, sender: str, domain: str, current_auth: dict,
        current_verdict: str, current_score: int, urls: list
    ):
        sender_data, sender_anomalies = self.analyze_sender(sender, current_auth, domain, current_score)
        domain_baseline = self.analyze_domain(domain, current_auth)
        url_shared, url_anomalies = self.analyze_url_infrastructure(urls, sender)

        all_anomalies = sender_anomalies + url_anomalies

        adaptive_result = {
            "sender_baseline": sender_data.get("baseline", {}) if sender_data else {},
            "domain_baseline": domain_baseline,
            "risk_trend": sender_data.get("trend", {}) if sender_data else {},
            "history_confidence": (
                sender_data.get("history_confidence", {})
                if sender_data
                else {"level": "VERY_LOW", "score": 0.1}
            ),
            "behavioral_anomalies": all_anomalies,
            "evidence": []
        }

        return adaptive_result
