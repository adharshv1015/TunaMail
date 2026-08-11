import re


class ContentAnalyzer:

    TRUSTED_ORGANIZATIONS = {
        "google": {
            "sender_domains": {
                "google.com",
                "gmail.com",
                "googlemail.com",
            },
            "url_domains": {
                "google.com",
                "gmail.com",
                "googleusercontent.com",
                "gstatic.com",
                "googleapis.com",
            },
        },

        "microsoft": {
            "sender_domains": {
                "microsoft.com",
                "outlook.com",
                "office.com",
            },
            "url_domains": {
                "microsoft.com",
                "microsoftonline.com",
                "office.com",
                "live.com",
                "outlook.com",
            },
        },

        "apple": {
            "sender_domains": {
                "apple.com",
                "icloud.com",
            },
            "url_domains": {
                "apple.com",
                "icloud.com",
            },
        },

        "paypal": {
            "sender_domains": {
                "paypal.com",
            },
            "url_domains": {
                "paypal.com",
            },
        },
    }

    def analyze(
        self,
        body: str,
        sender: str = "",
        auth_results: dict = None,
        urls=None
    ):

        if auth_results is None:
            auth_results = {}

        if urls is None:
            urls = []

        body = body or ""
        sender = sender or ""

        text = body.lower()
        sender_lower = sender.lower()

        result = {
            "urgency": self.contains(
                text,
                [
                    "urgent",
                    "immediately",
                    "expire",
                    "within 24 hours",
                    "action required",
                    "suspended",
                    "limited time"
                ]
            ),

            "credential_request": self.contains(
                text,
                [
                    "password",
                    "login",
                    "verify account",
                    "confirm account",
                    "sign in",
                    "username"
                ]
            ),

            "financial_request": self.contains(
                text,
                [
                    "payment",
                    "bank",
                    "credit card",
                    "wire transfer",
                    "invoice",
                    "refund"
                ]
            ),

            "impersonation": False,

            "threat_language": self.contains(
                text,
                [
                    "suspended",
                    "locked",
                    "disabled",
                    "terminated",
                    "blocked"
                ]
            )
        }

        result["impersonation"] = self._detect_impersonation(
            body=body,
            sender=sender_lower,
            urls=urls,
            authentication=auth_results
        )

        score = 0

        if result["urgency"]:
            score += 20

        if result["credential_request"]:
            score += 25

        if result["financial_request"]:
            score += 25

        if result["impersonation"]:
            score += 10

        if result["threat_language"]:
            score += 20

        result["risk_score"] = score

        return result

    def contains(self, text, keywords):

        return any(
            keyword in text
            for keyword in keywords
        )

    def _extract_domain(self, value):
        """
        Extract a normalized domain from an email address or URL.
        """

        if not value:
            return ""

        value = value.lower().strip()

        if "@" in value:
            value = value.split("@")[-1]

        value = re.sub(
            r"^https?://",
            "",
            value
        )

        value = value.split("/")[0]
        value = value.split(":")[0]

        return value.strip(" .")

    def _is_same_or_subdomain(
        self,
        domain,
        trusted_domain
    ):
        """
        Returns True when domain is exactly the trusted
        domain or a legitimate subdomain of it.
        """

        domain = domain.lower().strip(".")
        trusted_domain = trusted_domain.lower().strip(".")

        return (
            domain == trusted_domain
            or domain.endswith("." + trusted_domain)
        )

    def _organization_for_domain(self, domain):
        """
        Identify which trusted organization owns/controls
        the domain.
        """

        domain = self._extract_domain(domain)

        for organization, config in (
            self.TRUSTED_ORGANIZATIONS.items()
        ):

            for trusted_domain in config["url_domains"]:

                if self._is_same_or_subdomain(
                    domain,
                    trusted_domain
                ):
                    return organization

        return None

    def _is_legitimate_organization_relationship(
        self,
        sender_domain,
        url_domain,
        organization
    ):
        """
        Determine whether sender and URL belong to the
        same recognized organization.
        """

        config = self.TRUSTED_ORGANIZATIONS.get(
            organization
        )

        if not config:
            return False

        sender_domain = self._extract_domain(
            sender_domain
        )

        url_domain = self._extract_domain(
            url_domain
        )

        sender_matches = any(
            self._is_same_or_subdomain(
                sender_domain,
                trusted_domain
            )
            for trusted_domain
            in config["sender_domains"]
        )

        url_matches = any(
            self._is_same_or_subdomain(
                url_domain,
                trusted_domain
            )
            for trusted_domain
            in config["url_domains"]
        )

        return (
            sender_matches
            and url_matches
        )

    def _detect_impersonation(
        self,
        body,
        sender,
        urls=None,
        authentication=None
    ):
        """
        Detect possible brand impersonation.

        Authentication failures are suspicious.

        Brand mentions alone are NOT considered
        impersonation.

        A legitimate organization relationship between
        sender and URL is allowed.

        Suspicious organization/domain mismatches
        are considered impersonation.
        """

        body_lower = (body or "").lower()

        sender_domain = self._extract_domain(
            sender
        )

        # -------------------------------------------------
        # 1. Authentication failure
        # -------------------------------------------------

        if authentication:

            if (
                authentication.get("spf") == "fail"
                or authentication.get("dkim") == "fail"
                or authentication.get("dmarc") == "fail"
            ):
                return True

        urls = urls or []

        # -------------------------------------------------
        # 2. Examine organization references
        # -------------------------------------------------

        for organization, config in (
            self.TRUSTED_ORGANIZATIONS.items()
        ):

            # Brand mentioned in body
            brand_mentioned = (
                organization in body_lower
            )

            # Find URLs belonging to this organization
            organization_urls = []

            for url in urls:

                url_domain = self._extract_domain(
                    url
                )

                url_organization = (
                    self._organization_for_domain(
                        url_domain
                    )
                )

                if url_organization == organization:
                    organization_urls.append(
                        url_domain
                    )

            # -------------------------------------------------
            # Brand mentioned but no organization URL
            # -------------------------------------------------

            if brand_mentioned and not organization_urls:

                continue

            # -------------------------------------------------
            # Organization URL exists
            # -------------------------------------------------

            for url_domain in organization_urls:

                legitimate = (
                    self._is_legitimate_organization_relationship(
                        sender_domain,
                        url_domain,
                        organization
                    )
                )

                if legitimate:
                    continue

                # Sender does not legitimately belong to
                # the organization but the email is using
                # its organization URL/identity.
                return True

        # -------------------------------------------------
        # 3. No suspicious impersonation relationship
        # -------------------------------------------------

        return False