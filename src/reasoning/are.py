from src.collectors.authentication_collector import AuthenticationCollector
from src.collectors.sender_collector import SenderCollector
from src.collectors.url_collector import URLCollector
from src.collectors.header_collector import HeaderCollector


class AnalyticalReasoningEngine:

    def __init__(self):

        self.collectors = [
            AuthenticationCollector(),
            SenderCollector(),
            URLCollector(),
            HeaderCollector(),
        ]


    def evaluate(self, parsed_email):

        supporting = []
        contradicting = []
        indicators = {}

        total_risk = 0
        total_confidence = 0.0

        collector_results = []

        for collector in self.collectors:

            result = collector.collect(parsed_email)

            collector_results.append(result)

            supporting.extend(result["supporting"])
            contradicting.extend(result["contradicting"])

            indicators[result["collector"]] = result["indicators"]

            total_risk += result["risk"]
            total_confidence += result.get("confidence", 0.0)


        # Calculate average confidence
        avg_confidence = total_confidence / len(self.collectors) if self.collectors else 0.0


        if total_risk == 0:
            verdict = "BENIGN"
        elif total_risk < 50:
            verdict = "SUSPICIOUS"
        else:
            verdict = "PHISHING"


        return {
            "classification": verdict,
            "confidence": round(avg_confidence, 2),
            "risk_score": total_risk,
            "supporting_evidence": supporting,
            "contradicting_evidence": contradicting,
            "collector_results": collector_results,
            "indicators": indicators
        }