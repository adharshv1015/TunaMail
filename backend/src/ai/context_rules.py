# ============================================================
# backend/src/ai/context_rules.py
# ============================================================

import re


URL_RE = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE,
)


def analyze_context(parsed_email):

    subject = (
        parsed_email.get("subject")
        or ""
    ).strip()

    body = (
        parsed_email.get("body")
        or ""
    ).strip()

    urls = URL_RE.findall(body)

    meaningful_text = re.sub(
        r"https?://[^\s<>\"]+",
        "",
        body,
        flags=re.IGNORECASE,
    ).strip()

    word_count = len(
        meaningful_text.split()
    )

    if not subject and not body:
        return {
            "state": "INSUFFICIENT_EVIDENCE",
            "link_only": False,
            "word_count": 0,
            "url_count": 0,
        }

    if urls and word_count <= 5:
        return {
            "state": "LIMITED_CONTEXT",
            "link_only": True,
            "word_count": word_count,
            "url_count": len(urls),
        }

    return {
        "state": "SUFFICIENT_CONTEXT",
        "link_only": False,
        "word_count": word_count,
        "url_count": len(urls),
    }
