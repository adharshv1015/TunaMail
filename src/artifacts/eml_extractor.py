from email import policy
from email.parser import BytesParser
from pathlib import Path

from src.entities.artifact import Artifact
from email.utils import parseaddr

from src.entities.email_address import EmailAddress


class EMLExtractor:
    def _parse_email(self, value: str) -> EmailAddress:
        name, address = parseaddr(value)

        domain = ""

        if "@" in address:
            domain = address.split("@")[1]

        return EmailAddress(
            display_name=name,
            address=address,
            domain=domain,
        )

    def extract(self, file_path: str) -> Artifact:
        artifact = Artifact(source=file_path)

        path = Path(file_path)

        with path.open("rb") as file:
            message = BytesParser(policy=policy.default).parse(file)

        artifact.headers = dict(message.items())

        artifact.subject = message.get("Subject", "")
        artifact.sender = self._parse_email(
            message.get("From", "")
        )
        artifact.recipients = [
            self._parse_email(item)
            for item in message.get_all("To", [])
        ]
        artifact.cc = [
            self._parse_email(item)
            for item in message.get_all("Cc", [])
        ]
        artifact.bcc = [
            self._parse_email(item)
            for item in message.get_all("Bcc", [])
        ]
        artifact.reply_to = self._parse_email(
            message.get("Reply-To", "")
        )
        artifact.message_id = message.get("Message-ID", "")
        artifact.date = message.get("Date", "")

        artifact.text_body = ""

        artifact.html_body = ""

        if message.is_multipart():
            for part in message.walk():
                content_type = part.get_content_type()

                try:
                    content = part.get_content()
                except Exception:
                    continue

                if content_type == "text/plain":
                    artifact.text_body = str(content)

                elif content_type == "text/html":
                    artifact.html_body = str(content)

        else:
            content = message.get_content()

            if message.get_content_type() == "text/plain":
                artifact.text_body = str(content)

            elif message.get_content_type() == "text/html":
                artifact.html_body = str(content)

        return artifact
