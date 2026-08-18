from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import re


class EmailParser:

    def parse(self, file_path):

        with open(file_path, "rb") as f:
            msg = BytesParser(
                policy=policy.default
            ).parse(f)

        evidence = {
            "headers": {},
            "routing": {},
            "sender": {},
            "authentication": {},
            "body": {},
            "urls": [],
            "attachments": [],
            "content": {}
        }

        # Basic headers
        evidence["headers"] = {
            "subject": msg.get("Subject"),
            "date": msg.get("Date"),
            "message_id": msg.get("Message-ID"),
            "reply_to": msg.get("Reply-To"),
            "return_path": msg.get("Return-Path"),
            "delivered_to": msg.get("Delivered-To"),
            "mime_version": msg.get("Mime-Version"),
            "content_type": msg.get("Content-Type"),
            "user_agent": msg.get("User-Agent"),
            "x_mailer": msg.get("X-Mailer")
        }

        # Routing Information
        evidence["routing"] = {
            "received": msg.get_all("Received", []),
            "arc_seal": msg.get_all("ARC-Seal", []),
            "arc_message_signature": msg.get_all(
                "ARC-Message-Signature",
                []
            ),
            "authentication_results": msg.get_all(
                "Authentication-Results",
                []
            )
        }

        # Sender information
        sender_name, sender_email = parseaddr(
            msg.get("From", "")
        )

        evidence["sender"] = {
            "name": sender_name,
            "email": sender_email,
            "domain": (
                sender_email.split("@")[-1]
                if "@" in sender_email
                else None
            )
        }

        # Authentication headers
        auth = msg.get("Authentication-Results", "")

        evidence["authentication"] = {
            "spf": self.extract_auth(auth, "spf"),
            "dkim": self.extract_auth(auth, "dkim"),
            "dmarc": self.extract_auth(auth, "dmarc")
        }

        # Body extraction
        body = self.extract_body(msg)

        evidence["body"] = {
            "text": body,
            "length": len(body)
        }

        # URL extraction
        urls = re.findall(
            r"https?://[^\s<>\"']+",
            body
        )

        cleaned = []

        for url in urls:
            cleaned.append(
                url.rstrip(".,;:)>]}\"'")
            )

        evidence["urls"] = cleaned

        # Attachment detection
        for part in msg.walk():

            if part.get_content_disposition() == "attachment":

                payload = part.get_payload(
                    decode=True
                )

                evidence["attachments"].append(
                    {
                        "filename": part.get_filename(),
                        "content_type": part.get_content_type(),
                        "size": (
                            len(payload)
                            if payload
                            else 0
                        )
                    }
                )

        # Content analysis
        body_lower = body.lower()

        urgency_keywords = [
            "urgent",
            "immediately",
            "act now",
            "verify immediately",
            "suspended",
            "suspension",
            "expires",
            "final warning",
        ]

        credential_keywords = [
            "password",
            "username",
            "credentials",
            "login",
            "verify your credentials",
            "account verification",
        ]

        financial_keywords = [
            "payment",
            "invoice",
            "bank",
            "credit card",
            "debit card",
            "transfer",
            "money",
        ]

        threat_keywords = [
            "suspended",
            "terminated",
            "closed",
            "legal action",
            "penalty",
        ]

        evidence["content"] = {
            "analysis_status": "AVAILABLE",

            "urgency": any(
                keyword in body_lower
                for keyword in urgency_keywords
            ),

            "credential_request": any(
                keyword in body_lower
                for keyword in credential_keywords
            ),

            "financial_request": any(
                keyword in body_lower
                for keyword in financial_keywords
            ),

            "impersonation": False,

            "threat_language": any(
                keyword in body_lower
                for keyword in threat_keywords
            ),

            "link_only": (
                len(body.strip()) <= 250
                and len(cleaned) > 0
            ),
        }

        return evidence

    def extract_auth(self, header, method):

        match = re.search(
            method
            + r"=(pass|fail|softfail|neutral|none|temperror|permerror)",
            header,
            re.I
        )

        if match:
            return match.group(1).lower()

        return "unknown"

    def extract_body(self, msg):

        body = ""

        if msg.is_multipart():

            for part in msg.walk():

                if part.get_content_type() == "text/plain":

                    try:
                        body += part.get_content()

                    except Exception:
                        continue

            if not body.strip():

                for part in msg.walk():

                    if part.get_content_type() == "text/html":

                        try:
                            body += part.get_content()

                        except Exception:
                            continue

        else:

            try:
                body = msg.get_content()

            except Exception:
                body = ""

        return body