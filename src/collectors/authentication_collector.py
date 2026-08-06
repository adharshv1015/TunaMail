class AuthenticationCollector:

    def collect(self, parsed_email):

        auth = parsed_email.get("authentication", {})

        evidence = {
            "collector": "authentication",
            "supporting": [],
            "contradicting": [],
            "risk": 0,
            "confidence": 1.0 if auth else 0.5,
            "indicators": auth
        }

        if auth.get("spf") == "pass":
            evidence["supporting"].append("SPF authentication passed")
        else:
            evidence["contradicting"].append("SPF failed")
            evidence["risk"] += 25

        if auth.get("dkim") == "pass":
            evidence["supporting"].append("DKIM signature valid")
        else:
            evidence["contradicting"].append("DKIM failed")
            evidence["risk"] += 25

        if auth.get("dmarc") == "pass":
            evidence["supporting"].append("DMARC validation passed")
        else:
            evidence["contradicting"].append("DMARC failed")
            evidence["risk"] += 25

        return evidence
