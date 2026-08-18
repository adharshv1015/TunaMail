from bs4 import BeautifulSoup
import re
from typing import Dict, Any

class ContentExtractor:
    MAX_PAGE_TEXT_CHARS = 100000

    @classmethod
    def extract(cls, html_content: str) -> Dict[str, Any]:
        if not html_content:
            return {
                "title": "",
                "visible_text": "",
                "content_truncated": False,
                "word_count": 0,
                "forms": {
                    "count": 0,
                    "password_fields": 0,
                    "email_fields": 0,
                    "submit_buttons": 0
                }
            }

        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Remove scripts and styles
        for script in soup(["script", "style", "noscript", "meta", "link"]):
            script.extract()

        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        
        # Visible text
        text = soup.get_text(separator=' ')
        # collapse whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        content_truncated = False
        if len(text) > cls.MAX_PAGE_TEXT_CHARS:
            text = text[:cls.MAX_PAGE_TEXT_CHARS]
            content_truncated = True

        word_count = len(text.split())

        # Form extraction
        forms = soup.find_all("form")
        password_fields = len(soup.find_all("input", type="password"))
        email_fields = len(soup.find_all("input", type="email"))
        
        # Detect inputs that might be email based on name/id if type isn't email
        for inp in soup.find_all("input", type=["text", None]):
            name = (inp.get("name") or "").lower()
            id_attr = (inp.get("id") or "").lower()
            if "email" in name or "email" in id_attr or "user" in name or "login" in name:
                email_fields += 1

        submit_buttons = len(soup.find_all(["button", "input"], type="submit"))
        if submit_buttons == 0:
            # Fallback for generic buttons
            submit_buttons = len(soup.find_all("button"))

        return {
            "title": title,
            "visible_text": text,
            "content_truncated": content_truncated,
            "word_count": word_count,
            "forms": {
                "count": len(forms),
                "password_fields": password_fields,
                "email_fields": email_fields,
                "submit_buttons": submit_buttons
            }
        }
