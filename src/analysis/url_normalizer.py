from html import unescape


class URLNormalizer:
    """
    Normalizes URLs before they are stored.
    """

    def normalize(self, url: str) -> str:
        if not url:
            return url

        # Decode HTML entities
        url = unescape(url)

        # Decode escaped unicode ampersand
        url = url.replace("\\u0026", "&")

        # Remove surrounding whitespace
        url = url.strip()

        return url
