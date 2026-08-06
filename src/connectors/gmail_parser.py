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

        body = self.extract_body(
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

            "body": body,

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

        body = ""

        # Simple email
        if "body" in payload:

            data = payload["body"].get(
                "data"
            )

            if data:

                body += (
                    base64.urlsafe_b64decode(data)
                    .decode(
                        errors="ignore"
                    )
                )


        # Multipart email
        for part in payload.get(
            "parts",
            []
        ):

            if part.get(
                "mimeType"
            ) == "text/plain":

                data = part.get(
                    "body",
                    {}
                ).get(
                    "data"
                )

                if data:

                    body += (
                        base64.urlsafe_b64decode(data)
                        .decode(
                            errors="ignore"
                        )
                    )


        return body



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