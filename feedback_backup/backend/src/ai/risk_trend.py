import datetime

class RiskTrendEngine:
    def __init__(self):
        pass

    def evaluate_trend(self, history: list) -> dict:
        """
        history: list of dicts with 'timestamp' and 'score'
        """
        if not history or len(history) < 3:
            return {
                "trend": "INSUFFICIENT_HISTORY",
                "explanation": "Insufficient history to determine risk trend."
            }
            
        scores = [item["score"] for item in history]
        
        # Calculate moving average or simple linear regression slope
        # For simplicity, compare first half and second half
        mid = len(scores) // 2
        first_half_avg = sum(scores[:mid]) / len(scores[:mid])
        second_half_avg = sum(scores[mid:]) / len(scores[mid:])
        
        diff = second_half_avg - first_half_avg
        
        if abs(diff) < 10:
            trend = "STABLE"
        elif diff >= 10:
            trend = "DEGRADING"
        else:
            trend = "IMPROVING"
            
        # Check volatility
        variance = sum((x - (sum(scores) / len(scores))) ** 2 for x in scores) / len(scores)
        if variance > 400: # Standard dev > 20
            trend = "VOLATILE"
            
        explanation_map = {
            "STABLE": "Sender risk profile is stable over time.",
            "DEGRADING": "Sender risk profile is degrading (becoming more suspicious).",
            "IMPROVING": "Sender risk profile is improving.",
            "VOLATILE": "Sender risk profile is highly volatile.",
        }
        
        return {
            "trend": trend,
            "explanation": explanation_map.get(trend, "Unknown trend.")
        }
