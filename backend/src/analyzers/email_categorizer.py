import re


class EmailCategorizer:

    def categorize(
        self,
        parsed_email,
        content_analysis,
        url_analysis,
        attachment_analysis,
        decision
    ):

        categories = set()

        subject = (
            parsed_email.get("subject", "")
            .lower()
        )

        body = (
            parsed_email.get("body", "")
            .lower()
        )

        sender = (
            parsed_email.get("from", "")
            .lower()
        )

        text = f"{subject} {body}"

        #################################################
        # OTP
        #################################################

        otp_patterns = [
            r"\botp\b",
            r"verification code",
            r"one[- ]time password",
            r"security code",
            r"login code",
            r"6-digit code",
            r"authentication code"
        ]

        if any(
            re.search(pattern, text)
            for pattern in otp_patterns
        ):
            categories.add("OTP")

        #################################################
        # Security
        #################################################

        security_keywords = [
            "security alert",
            "password",
            "sign in",
            "login",
            "account",
            "device",
            "recovery",
            "verification",
            "2fa",
            "two-factor"
        ]

        if any(word in text for word in security_keywords):
            categories.add("Security")

        #################################################
        # Banking
        #################################################

        banking = [
            "bank",
            "transaction",
            "upi",
            "debit",
            "credit",
            "payment",
            "account balance",
            "statement"
        ]

        if any(word in text for word in banking):
            categories.add("Banking")

        #################################################
        # Invoice
        #################################################

        invoice = [
            "invoice",
            "receipt",
            "bill",
            "tax invoice",
            "payment received"
        ]

        if any(word in text for word in invoice):
            categories.add("Invoice")

        #################################################
        # Shopping
        #################################################

        shopping = [
            "order",
            "shipping",
            "delivered",
            "amazon",
            "flipkart",
            "purchase"
        ]

        if any(word in text for word in shopping):
            categories.add("Shopping")

        #################################################
        # Delivery
        #################################################

        delivery = [
            "tracking",
            "shipment",
            "courier",
            "parcel",
            "out for delivery"
        ]

        if any(word in text for word in delivery):
            categories.add("Delivery")

        #################################################
        # Social
        #################################################

        social = [
            "friend request",
            "liked your",
            "commented",
            "mentioned you",
            "follow"
        ]

        if any(word in text for word in social):
            categories.add("Social")

        #################################################
        # Newsletter
        #################################################

        newsletter = [
            "unsubscribe",
            "weekly",
            "newsletter",
            "digest"
        ]

        if any(word in text for word in newsletter):
            categories.add("Newsletter")

        #################################################
        # Promotion
        #################################################

        promotion = [
            "offer",
            "discount",
            "sale",
            "coupon",
            "deal",
            "% off"
        ]

        if any(word in text for word in promotion):
            categories.add("Promotion")

        #################################################
        # Attachment
        #################################################

        if attachment_analysis.get(
            "attachment_count",
            0
        ) > 0:
            categories.add("Attachment")

        #################################################
        # High Risk
        #################################################

        if decision.get(
            "risk_score",
            0
        ) >= 70:
            categories.add("High Risk")

        #################################################
        # Phishing
        #################################################

        if decision.get(
            "verdict"
        ) == "phishing":
            categories.add("Phishing")

        #################################################
        # Trusted
        #################################################

        if (
            decision.get("verdict") == "safe"
            and decision.get("risk_score", 0) < 30
        ):
            categories.add("Trusted")

        #################################################

        if not categories:
            categories.add("General")

        return sorted(categories)