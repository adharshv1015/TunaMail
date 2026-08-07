from src.config.scoring import SCORING


class AnalyticalReasoningEngine:

    def __init__(self):

        self.rules = SCORING

    def evaluate(

        self,

        authentication,

        url_analysis,

        content_analysis,
        
        attachment_analysis,

        trust_analysis

    ):

        score = 0

        evidence = {

            "technical": [],

            "behavioral": [],

            "network": []

        }

        auth = self.rules["authentication"]

        if authentication["spf"] != "pass":

            score += auth["spf_fail"]

            evidence["technical"].append(
                "SPF validation failed"
            )

        if authentication["dkim"] != "pass":

            score += auth["dkim_fail"]

            evidence["technical"].append(
                "DKIM validation failed"
            )

        if authentication["dmarc"] != "pass":

            score += auth["dmarc_fail"]

            evidence["technical"].append(
                "DMARC validation failed"
            )

        url_rules = self.rules["url"]

        for url in url_analysis["analysis"]:

            if url["ip_based"]:

                score += url_rules["ip_url"]

                evidence["network"].append(
                    f"IP URL: {url['url']}"
                )

            if url["shortener"]:

                score += url_rules["shortener"]

                evidence["network"].append(
                    f"Shortened URL: {url['url']}"
                )

            if url["keywords"]:

                score += (

                    len(url["keywords"])

                    * url_rules["keyword"]

                )

                evidence["network"].append(

                    "Suspicious URL keywords: "

                    + ", ".join(url["keywords"])

                )

        content = self.rules["content"]

        if content_analysis["urgency"]:

            score += content["urgency"]

            evidence["behavioral"].append(
                "Urgency language detected"
            )

        if content_analysis["credential_request"]:

            score += content["credential_request"]

            evidence["behavioral"].append(
                "Credential harvesting attempt"
            )

        if content_analysis["financial_request"]:

            score += content["financial_request"]

            evidence["behavioral"].append(
                "Financial request detected"
            )

        if content_analysis["impersonation"]:

            score += content["impersonation"]

            evidence["behavioral"].append(
                "Possible impersonation"
            )

        if content_analysis["threat_language"]:

            score += content["threat_language"]

            evidence["behavioral"].append(
                "Threat language detected"
            )

        attachment = self.rules["attachment"]

        score += (
            attachment_analysis["risk_score"] *
            attachment["risk_multiplier"]
        )

        for item in attachment_analysis["evidence"]:
            evidence["technical"].append(item)

        score = min(score, 100)

        # -----------------------------
        # Consistency-Based Confidence
        # -----------------------------
        auth_failed = len(evidence["technical"]) > 0
        has_network_risk = len(evidence["network"]) > 0
        has_behavioral_risk = len(evidence["behavioral"]) > 0
        has_trust = trust_analysis.get("trust_score", 0) >= 20

        # Base confidence
        confidence = 50

        if score < 40:
            # Benign case
            if not auth_failed and has_trust and not has_behavioral_risk and not has_network_risk:
                confidence = 95
            elif not auth_failed and not has_behavioral_risk:
                confidence = 80
            elif not auth_failed and (has_behavioral_risk or has_network_risk):
                confidence = 55 # Mixed signals
            else:
                confidence = 65
        else:
            # Malicious case
            if auth_failed and has_network_risk and has_behavioral_risk:
                confidence = 95
            elif auth_failed and (has_network_risk or has_behavioral_risk):
                confidence = 85
            elif not auth_failed and has_network_risk and has_behavioral_risk:
                confidence = 80
            elif not auth_failed and has_trust and score >= 60:
                confidence = 45 # Strong mixed signals (trusted but malicious score)
            else:
                confidence = 70

        if score >= 80:
            verdict = "PHISHING"
        elif score >= 60:
            verdict = "HIGH RISK"
        elif score >= 40:
            verdict = "SUSPICIOUS"
        elif score >= 20:
            verdict = "LOW RISK"
        else:
            verdict = "SAFE"

        explanation = self.generate_explanation(

            verdict,

            evidence

        )

        return {

            "risk_score": score,

            "confidence": confidence,

            "verdict": verdict,

            "evidence": evidence,

            "explanation": explanation

        }

    def generate_explanation(

        self,

        verdict,

        evidence

    ):

        lines = [

            f"Overall Verdict: {verdict}",

            ""

        ]

        for category, values in evidence.items():

            if values:

                lines.append(

                    category.capitalize() + ":"

                )

                for item in values:

                    lines.append(

                        f"- {item}"

                    )

                lines.append("")

        if len(lines) == 2:

            lines.append(

                "No suspicious indicators detected."

            )

        return "\n".join(lines)