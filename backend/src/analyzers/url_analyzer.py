import re
from urllib.parse import urlparse


class URLAnalyzer:


    def analyze(self, body):

        urls = self.extract_urls(body)

        results = []

        for url in urls:

            results.append(
                self.analyze_url(url)
            )

        return {
            "urls": urls,
            "analysis": results
        }



    def extract_urls(self, text):

        pattern = r'https?://[^\s<>"]+'

        return re.findall(
            pattern,
            text
        )



    def analyze_url(self, url):

        parsed = urlparse(url)

        domain = parsed.netloc.lower()


        return {

            "url": url,

            "domain": domain,

            "ip_based": self.is_ip(domain),

            "shortener": self.is_shortener(domain),

            "keywords":
                self.detect_keywords(url, domain)

        }



    def is_ip(self, domain):

        pattern = (
            r'^\d{1,3}'
            r'(\.\d{1,3}){3}'
        )

        return bool(
            re.match(
                pattern,
                domain
            )
        )



    def is_shortener(self, domain):

        shorteners = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "ow.ly"
        ]

        return domain in shorteners



    def detect_keywords(self, url, domain):

        trusted_domains = [
            "google.com",
            "microsoft.com",
            "apple.com",
            "amazon.com",
            "paypal.com"
        ]

        # Do not penalize keywords if the domain is trusted
        for trusted in trusted_domains:
            if domain == trusted or domain.endswith("." + trusted):
                return []

        keywords = [
            "login",
            "verify",
            "secure",
            "account",
            "password",
            "update",
            "confirm"
        ]

        found = []

        lower = url.lower()

        for word in keywords:

            if word in lower:
                found.append(word)


        return found
