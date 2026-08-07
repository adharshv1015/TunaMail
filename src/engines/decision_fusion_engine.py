class DecisionFusionEngine:

    def evaluate(self, are_result):

        risk_score = are_result["risk_score"]
        confidence = are_result["confidence"]
        evidence = are_result["evidence"]

        technical = len(evidence["technical"])
        behavioral = len(evidence["behavioral"])
        network = len(evidence["network"])

        # -----------------------------
        # Rule 1
        # Strong behavioral indicators
        # -----------------------------
        if behavioral >= 2 and risk_score >= 40:

            verdict = "PHISHING"

        # -----------------------------
        # Rule 2
        # Multiple technical failures
        # -----------------------------
        elif technical >= 2 and risk_score >= 40:

            verdict = "PHISHING"

        # -----------------------------
        # Rule 3
        # Malicious attachments
        # -----------------------------
        elif any("Executable attachment" in e for e in evidence["technical"]) or any("Script attachment" in e for e in evidence["technical"]):
            verdict = "PHISHING"

        # -----------------------------
        # Rule 4
        # Network + behavioral
        # -----------------------------
        elif network >= 1 and behavioral >= 1:

            verdict = "PHISHING"

        # -----------------------------
        # Rule 4
        # Score thresholds
        # -----------------------------
        elif risk_score >= 80:
            verdict = "PHISHING"
        elif risk_score >= 60:
            verdict = "HIGH RISK"
        elif risk_score >= 40:
            verdict = "SUSPICIOUS"
        elif risk_score >= 20:
            verdict = "LOW RISK"
        else:
            verdict = "SAFE"

        # Align risk_score mathematically with the rule-based verdict
        if verdict == "PHISHING" and risk_score < 80:
            risk_score = 80
        elif verdict == "HIGH RISK" and risk_score < 60:
            risk_score = 60
        elif verdict == "SUSPICIOUS" and risk_score < 40:
            risk_score = 40
        elif verdict == "LOW RISK" and risk_score < 20:
            risk_score = 20

        # Update the ARE dictionary in-place to ensure no disagreement
        are_result["risk_score"] = risk_score
        are_result["verdict"] = verdict
        if "explanation" in are_result:
            lines = are_result["explanation"].split("\n")
            if lines and lines[0].startswith("Overall Verdict:"):
                lines[0] = f"Overall Verdict: {verdict}"
                are_result["explanation"] = "\n".join(lines)

        recommendation = self.get_recommendation(
            verdict
        )

        return {

            "risk_score": risk_score,

            "confidence": confidence,

            "verdict": verdict,

            "recommendation": recommendation,

            "reasoning": evidence

        }

    def get_recommendation(
        self,
        verdict
    ):

        recommendations = {
            "SAFE": "No immediate threats detected.",
            "LOW RISK": "Appears safe, but always verify unexpected requests.",
            "SUSPICIOUS": "Exercise caution before clicking links or downloading files.",
            "HIGH RISK": "Multiple risk factors detected. Do not click links unless verified.",
            "PHISHING": "Do not interact with this email. Report or delete it immediately."
        }

        return recommendations.get(
            verdict,
            ""
        )