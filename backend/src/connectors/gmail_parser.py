import base64


class GmailParser:

    def parse_message(self, gmail_message):

        payload = gmail_message.get(
            "payload",
            {}
        )

        headers = self.extract_headers(
            payload
        )

        body_dict = self.extract_body(
            payload
        )

        attachments = self.extract_attachments(
            payload
        )

        return {

            "id": gmail_message.get("id"),

            "thread_id": gmail_message.get(
                "threadId"
            ),

            "from": headers.get(
                "From"
            ),

            "to": headers.get(
                "To"
            ),

            "subject": headers.get(
                "Subject"
            ),

            "date": headers.get(
                "Date"
            ),

            "headers": headers,
            "body": body_dict.get("text/plain", "").strip() or body_dict.get("text/html", "").strip(),
            "html_body": body_dict.get("text/html", "").strip(),
            "attachments": attachments
        }


    def extract_headers(self, payload):

        headers = {}

        for header in payload.get(
            "headers",
            []
        ):

            headers[
                header.get("name")
            ] = header.get(
                "value"
            )

        return headers



    def extract_body(self, payload):
        body_parts = {"text/plain": "", "text/html": ""}

        def traverse_parts(parts):
            for part in parts:
                mime_type = part.get("mimeType", "")
                if mime_type in ["text/plain", "text/html"]:
                    data = part.get("body", {}).get("data")
                    if data:
                        text = base64.urlsafe_b64decode(data).decode(errors="ignore")
                        body_parts[mime_type] += text + "\n"
                elif "parts" in part:
                    traverse_parts(part["parts"])

        if "body" in payload and payload["body"].get("data"):
            data = payload["body"].get("data")
            mime_type = payload.get("mimeType", "text/plain")
            text = base64.urlsafe_b64decode(data).decode(errors="ignore")
            if mime_type in body_parts:
                body_parts[mime_type] += text + "\n"
            else:
                body_parts["text/plain"] += text + "\n"

        if "parts" in payload:
            traverse_parts(payload["parts"])

        return body_parts



    def extract_attachments(self, payload):

        attachments = []

        for part in payload.get(
            "parts",
            []
        ):

            filename = part.get(
                "filename"
            )

            if filename:

                attachments.append(
                    {
                        "filename": filename,

                        "mimeType": part.get(
                            "mimeType"
                        ),

                        "size": part.get(
                            "body",
                            {}
                        ).get(
                            "size"
                        )
                    }
                )

        return attachments