class SenderCollector:

    def collect(self, parsed_email):

        sender = parsed_email.get("sender", {})

        domain = sender.get("domain")

        evidence = {
            "collector": "sender",
            "supporting": [],
            "contradicting": [],
            "risk": 0,
            "confidence": 1.0 if domain else 0.5,
            "indicators": sender
        }

        if domain:
            evidence["supporting"].append(
                f"Sender domain detected: {domain}"
            )
        else:
            evidence["contradicting"].append(
                "Missing sender domain"
            )
            evidence["risk"] += 40

        return evidence
