from email import policy
from email.parser import BytesParser
from pathlib import Path

from entities.artifact import Artifact


class EMLExtractor:
    def extract(self, file_path: str) -> Artifact:
        artifact = Artifact(source=file_path)

        path = Path(file_path)

        with path.open("rb") as file:
            message = BytesParser(policy=policy.default).parse(file)

        artifact.headers = dict(message.items())

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