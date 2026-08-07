from __future__ import annotations
from dataclasses import dataclass, field


@dataclass(slots=True)
class Artifact:
    source: str = ""

    subject: str = ""

    sender: "EmailAddress | None" = None

    recipients: list["EmailAddress"] = field(default_factory=list)

    cc: list["EmailAddress"] = field(default_factory=list)

    bcc: list["EmailAddress"] = field(default_factory=list)

    reply_to: "EmailAddress | None" = None

    message_id: str = ""

    date: str = ""

    headers: dict[str, str] = field(default_factory=dict)

    text_body: str = ""

    html_body: str = ""

    urls: list[str] = field(default_factory=list)

    domains: list[str] = field(default_factory=list)

    ip_addresses: list[str] = field(default_factory=list)

    attachments: list[str] = field(default_factory=list)