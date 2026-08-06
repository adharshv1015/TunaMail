from urllib.parse import urlparse
import ipaddress


class URLCollector:

    SUSPICIOUS_TLDS = {
        "zip",
        "mov",
        "xyz",
        "top",
        "click",
        "gq",
        "tk",
        "ml",
        "cf",
        "ga"
    }

    def collect(self, parsed_email):

        urls = parsed_email.get("urls", [])

        evidence = {
            "collector": "url",
            "supporting": [],
            "contradicting": [],
            "risk": 0,
            "confidence": 1.0,
            "indicators": []
        }

        if not urls:
            evidence["supporting"].append(
                "No URLs found"
            )
            return evidence

        for url in urls:

            parsed = urlparse(url)

            host = parsed.hostname or ""

            info = {
                "url": url,
                "host": host,
                "flags": []
            }

            # -------------------------
            # Raw IP address
            # -------------------------

            try:
                ipaddress.ip_address(host)

                info["flags"].append(
                    "IP_ADDRESS"
                )

                evidence["contradicting"].append(
                    f"URL uses raw IP address: {host}"
                )

                evidence["risk"] += 30

            except ValueError:
                pass

            # -------------------------
            # Punycode
            # -------------------------

            if host.startswith("xn--"):

                info["flags"].append(
                    "PUNYCODE"
                )

                evidence["contradicting"].append(
                    f"Punycode domain detected: {host}"
                )

                evidence["risk"] += 20

            # -------------------------
            # Suspicious TLD
            # -------------------------

            tld = host.split(".")[-1].lower()

            if tld in self.SUSPICIOUS_TLDS:

                info["flags"].append(
                    "SUSPICIOUS_TLD"
                )

                evidence["contradicting"].append(
                    f"Suspicious TLD: .{tld}"
                )

                evidence["risk"] += 15

            # -------------------------
            # Long URL
            # -------------------------

            if len(url) > 120:

                info["flags"].append(
                    "LONG_URL"
                )

                evidence["contradicting"].append(
                    "Very long URL detected"
                )

                evidence["risk"] += 10

            if not info["flags"]:

                evidence["supporting"].append(
                    f"Normal URL: {host}"
                )

            evidence["indicators"].append(
                info
            )

        return evidence