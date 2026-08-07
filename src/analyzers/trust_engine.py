from urllib.parse import urlparse
from email.utils import parseaddr


class TrustEngine:

    def __init__(self):

        self.known_organizations = {

            "google": [
                "google.com"
            ],

            "microsoft": [
                "microsoft.com",
                "microsoftonline.com",
                "office.com",
                "live.com"
            ],

            "apple": [
                "apple.com"
            ],

            "amazon": [
                "amazon.com"
            ],

            "paypal": [
                "paypal.com"
            ],

            "github": [
                "github.com"
            ],

            "linkedin": [
                "linkedin.com"
            ],

            "meta": [
                "facebook.com",
                "instagram.com"
            ],

            "x": [
                "x.com",
                "twitter.com"
            ],

            "dropbox": [
                "dropbox.com"
            ],

            "cloudflare": [
                "cloudflare.com"
            ]
        }

    def domain_matches(self, domain, trusted):
        return (
            domain == trusted or
            domain.endswith("." + trusted)
        )


    def evaluate(self, parsed_email, url_analysis):

        score = 0
        evidence = []

        ##################################################
        # Sender domain
        ##################################################

        email_address = parseaddr(parsed_email.get("from", ""))[1]
        sender_domain = email_address.split("@")[-1].lower() if "@" in email_address else ""

        urls = url_analysis.get(
            "analysis",
            []
        )

        ##################################################
        # Organization Lookup Helper
        ##################################################

        def get_organization(domain):
            for org, domains in self.known_organizations.items():
                for d in domains:
                    if self.domain_matches(domain, d):
                        return org
            return None

        sender_org = get_organization(sender_domain) if sender_domain else None

        ##################################################
        # Trusted sender
        ##################################################

        if sender_org:

            score += 20

            evidence.append(
                f"Trusted sender organization ({sender_org.capitalize()})"
            )

        ##################################################
        # URL reputation
        ##################################################

        trusted_organizations = set()

        for item in urls:

            domain = item.get(
                "domain",
                ""
            )

            org = get_organization(domain)
            if org:
                trusted_organizations.add(org)

        if trusted_organizations:

            score += len(trusted_organizations) * 10

            evidence.append(
                f"{len(trusted_organizations)} trusted URLs"
            )

        ##################################################
        # Sender matches URL Organization
        ##################################################

        if sender_org:

            for item in urls:

                url_org = get_organization(item.get("domain", ""))

                if url_org == sender_org:

                    score += 20

                    evidence.append(
                        f"Sender and URL belong to same organization ({sender_org.capitalize()})"
                    )

                    break

        score = min(score, 100)

        return {

            "trust_score": score,

            "evidence": evidence

        }