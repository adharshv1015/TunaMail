from whois.exceptions import UnknownTldError
from datetime import datetime, timezone

import whois


class WhoisAnalyzer:

    def analyze(self, domain):

        result = {
            "domain": domain,
            "available": False,
            "created": None,
            "expires": None,
            "registrar": None,
            "country": None,
            "age_days": None,
            "age_category": "Unknown",
            "error": None
        }

        try:

            data = whois.whois(domain)

            result["available"] = True

            creation = data.creation_date
            expiration = data.expiration_date

            if isinstance(creation, list):
                creation = creation[0]

            if isinstance(expiration, list):
                expiration = expiration[0]

            result["created"] = (
                creation.isoformat()
                if creation else None
            )

            result["expires"] = (
                expiration.isoformat()
                if expiration else None
            )

            result["registrar"] = data.registrar
            result["country"] = getattr(
                data,
                "country",
                None
            )

            if creation:
                if creation.tzinfo is None:
                    creation = creation.replace(
                        tzinfo=timezone.utc
                    )

                result["age_days"] = (
                    datetime.now(timezone.utc) - creation
                ).days

                age_days = result["age_days"]

                if age_days >= 3650:
                    result["age_category"] = "very_old"

                elif age_days >= 1095:
                    result["age_category"] = "established"

                elif age_days >= 365:
                    result["age_category"] = "recent"

                elif age_days >= 0:
                    result["age_category"] = "new"

        except Exception as e:

            error_str = str(e).strip().split('\n')[0]
            words = error_str.split()
            
            if len(words) > 10:
                result["error"] = " ".join(words[:10]) + "..."
            else:
                result["error"] = error_str

        return result