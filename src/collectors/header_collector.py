from email.utils import parsedate_to_datetime


class HeaderCollector:

    def collect(self, parsed_email):

        headers = parsed_email.get("headers", {})

        evidence = {
            "collector": "header",
            "supporting": [],
            "contradicting": [],
            "risk": 0,
            "confidence": 1.0,
            "indicators": {}
        }

        subject = headers.get("subject")
        date = headers.get("date")
        message_id = headers.get("message_id")

        # --------------------
        # Subject
        # --------------------

        if subject:
            evidence["supporting"].append(
                "Subject present"
            )
        else:
            evidence["contradicting"].append(
                "Missing Subject header"
            )
            evidence["risk"] += 10

        # --------------------
        # Message-ID
        # --------------------

        if message_id:

            evidence["supporting"].append(
                "Message-ID present"
            )

            evidence["indicators"]["message_id"] = message_id

        else:

            evidence["contradicting"].append(
                "Missing Message-ID"
            )

            evidence["risk"] += 20

        # --------------------
        # Date
        # --------------------

        if date:

            try:

                parsed = parsedate_to_datetime(date)

                evidence["supporting"].append(
                    "Valid Date header"
                )

                evidence["indicators"]["date"] = parsed.isoformat()

            except Exception:

                evidence["contradicting"].append(
                    "Invalid Date header"
                )

                evidence["risk"] += 15

        else:

            evidence["contradicting"].append(
                "Missing Date header"
            )

            evidence["risk"] += 20

        return evidence