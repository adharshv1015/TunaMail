import os
import re
from dataclasses import dataclass, field
from email.message import EmailMessage
from urllib.parse import urlparse

@dataclass
class EmailMetadata:
    subject: str = ""
    sender: str = ""
    recipients: list[str] = field(default_factory=list)
    reply_to: str = ""
    message_id: str = ""
    date: str = ""
    
    headers: dict[str, list[str]] = field(default_factory=dict)
    urls: list[dict] = field(default_factory=list)
    attachments: list[dict] = field(default_factory=list)
    
    text_body: str = ""
    html_body: str = ""

    URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

    @classmethod
    def from_message(cls, email: EmailMessage) -> "EmailMetadata":
        meta = cls()
        
        # Basic fields
        meta.subject = str(email.get("Subject", ""))
        meta.sender = str(email.get("From", ""))
        meta.reply_to = str(email.get("Reply-To", ""))
        meta.message_id = str(email.get("Message-ID", ""))
        meta.date = str(email.get("Date", ""))
        
        # Recipients
        to_header = str(email.get("To", ""))
        if to_header:
            meta.recipients = [r.strip() for r in to_header.split(",")]
            
        # Headers
        for key, value in email.items():
            lower_key = key.lower()
            if lower_key not in meta.headers:
                meta.headers[lower_key] = []
            meta.headers[lower_key].append(str(value))
            
        # Parse body and attachments
        if email.is_multipart():
            for part in email.walk():
                content_type = part.get_content_type()
                filename = part.get_filename()
                
                if filename:
                    # It's an attachment
                    payload = part.get_payload(decode=True)
                    size = len(payload) if payload else 0
                    extension = os.path.splitext(filename)[1].lower() if filename else None
                    meta.attachments.append({
                        "filename": filename,
                        "extension": extension,
                        "mime_type": content_type,
                        "size": size
                    })
                else:
                    # Not an attachment
                    if content_type == "text/plain":
                        meta.text_body += part.get_payload(decode=True).decode(errors="ignore")
                    elif content_type == "text/html":
                        meta.html_body += part.get_payload(decode=True).decode(errors="ignore")
        else:
            content_type = email.get_content_type()
            if content_type == "text/plain":
                meta.text_body = email.get_payload(decode=True).decode(errors="ignore")
            elif content_type == "text/html":
                meta.html_body = email.get_payload(decode=True).decode(errors="ignore")

        # Extract URLs
        sources = [
            ("text_body", meta.text_body),
            ("html_body", meta.html_body)
        ]
        
        for location, content in sources:
            if not content:
                continue
            
            urls = cls.URL_PATTERN.findall(content)
            for url in urls:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                meta.urls.append({
                    "url": url,
                    "domain": domain,
                    "location": location
                })
                
        return meta
