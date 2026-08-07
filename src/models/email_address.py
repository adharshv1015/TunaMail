from dataclasses import dataclass


@dataclass(slots=True)
class EmailAddress:
    display_name: str = ""

    address: str = ""

    domain: str = ""
