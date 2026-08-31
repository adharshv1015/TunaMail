import logging
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

import dns.resolver
import requests

logger = logging.getLogger(__name__)


class MTASTSService:
    """
    Defensive MTA-STS policy inspector.

    Checks:
    - _mta-sts.<domain> TXT discovery
    - MTA-STS policy retrieval over HTTPS
    - policy mode
    - policy MX patterns
    - policy validity

    This service evaluates the receiving domain's published policy.
    It does NOT claim that a particular email session used TLS.
    """

    DNS_PREFIX = "_mta-sts"

    POLICY_URL = (
        "https://mta-sts.{domain}/.well-known/mta-sts.txt"
    )

    TIMEOUT = 5

    VALID_MODES = {
        "enforce",
        "testing",
        "none",
    }

    def analyze(self, domain: str) -> Dict[str, Any]:
        domain = self._normalize_domain(domain)

        if not domain:
            return self._unavailable(
                "Invalid or empty domain."
            )

        dns_result = self._lookup_dns_policy(domain)

        # Do not perform the HTTPS policy fetch when MTA-STS
        # discovery itself is unavailable. There is no published
        # MTA-STS policy to retrieve in this case, and waiting for
        # an HTTPS timeout only adds unnecessary latency.
        if not dns_result.get("available", False):
            https_result = {
                "available": False,
                "url": self.POLICY_URL.format(domain=domain),
                "status_code": None,
                "policy": {},
                "error": "MTA-STS DNS policy record unavailable.",
            }
        else:
            https_result = self._fetch_policy(domain)

        policy = https_result.get("policy", {})

        mode = str(
            policy.get("mode", "")
        ).lower().strip()

        mx_patterns = policy.get("mx", [])

        valid_policy = (
            https_result.get("available", False)
            and mode in self.VALID_MODES
            and bool(mx_patterns)
        )

        strict = mode == "enforce"

        issues: List[str] = []

        if not dns_result["available"]:
            issues.append(
                "MTA-STS DNS policy discovery unavailable."
            )

        if dns_result["available"] and not https_result["available"]:
            issues.append(
                "MTA-STS policy could not be retrieved over HTTPS."
            )

        if https_result["available"] and not valid_policy:
            issues.append(
                "MTA-STS policy is malformed or incomplete."
            )

        if mode == "testing":
            issues.append(
                "MTA-STS is published in testing mode."
            )

        if mode == "none":
            issues.append(
                "MTA-STS is published with mode=none."
            )

        severity = "INFO"

        if strict and valid_policy:
            severity = "LOW"
        elif mode in {"testing", "none"}:
            severity = "MEDIUM"
        elif issues:
            severity = "MEDIUM"

        return {
            "available": bool(
                dns_result["available"]
                or https_result["available"]
            ),
            "domain": domain,
            "dns": dns_result,
            "https": https_result,
            "policy": policy,
            "mode": mode or "unknown",
            "mx": mx_patterns,
            "strict": strict,
            "valid_policy": valid_policy,
            "issues": issues,
            "severity": severity,
            "evidence_type": (
                "MTA_STS_STRICT"
                if strict and valid_policy
                else "MTA_STS_POLICY"
            ),
        }

    def _lookup_dns_policy(
        self,
        domain: str,
    ) -> Dict[str, Any]:

        name = f"{self.DNS_PREFIX}.{domain}"

        try:
            answers = dns.resolver.resolve(
                name,
                "TXT",
                lifetime=self.TIMEOUT,
            )

            records = []

            for answer in answers:
                text = "".join(
                    part.decode()
                    if isinstance(part, bytes)
                    else str(part)
                    for part in answer.strings
                )
                records.append(text)

            matching = [
                record
                for record in records
                if record.lower().startswith("v=stsv1")
            ]

            return {
                "available": bool(matching),
                "record": matching[0]
                if matching
                else None,
                "records": records,
            }

        except Exception as exc:
            logger.debug(
                "MTA-STS DNS lookup failed for %s: %s",
                domain,
                exc,
            )

            return {
                "available": False,
                "record": None,
                "records": [],
                "error": str(exc),
            }

    def _fetch_policy(
        self,
        domain: str,
    ) -> Dict[str, Any]:

        url = self.POLICY_URL.format(
            domain=domain
        )

        try:
            response = requests.get(
                url,
                timeout=self.TIMEOUT,
                headers={
                    "User-Agent": "TunaMail-MTA-STS/1.0"
                },
            )

            response.raise_for_status()

            policy = self._parse_policy(
                response.text
            )

            return {
                "available": True,
                "url": url,
                "status_code": response.status_code,
                "policy": policy,
            }

        except Exception as exc:
            logger.debug(
                "MTA-STS HTTPS policy retrieval failed for %s: %s",
                domain,
                exc,
            )

            return {
                "available": False,
                "url": url,
                "status_code": None,
                "policy": {},
                "error": str(exc),
            }

    @staticmethod
    def _parse_policy(
        text: str,
    ) -> Dict[str, Any]:

        policy: Dict[str, Any] = {
            "version": None,
            "mode": None,
            "mx": [],
            "max_age": None,
        }

        for raw_line in str(text or "").splitlines():

            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            if ":" not in line:
                continue

            key, value = line.split(":", 1)

            key = key.strip().lower()
            value = value.strip()

            if key == "mx":
                policy["mx"].append(value)

            elif key == "mode":
                policy["mode"] = value.lower()

            elif key == "version":
                policy["version"] = value

            elif key == "max_age":
                try:
                    policy["max_age"] = int(value)
                except ValueError:
                    policy["max_age"] = None

        return policy

    @staticmethod
    def _normalize_domain(
        domain: str,
    ) -> str:

        value = str(
            domain or ""
        ).strip().lower().rstrip(".")

        if "@" in value:
            value = value.split(
                "@",
                1,
            )[-1]

        try:
            parsed = urlparse(
                value
                if "://" in value
                else f"https://{value}"
            )

            hostname = parsed.hostname

            if hostname:
                value = hostname.lower().rstrip(".")

        except Exception:
            pass

        if not re.match(
            r"^[a-z0-9.-]+$",
            value,
        ):
            return ""

        return value

    @staticmethod
    def _unavailable(
        reason: str,
    ) -> Dict[str, Any]:

        return {
            "available": False,
            "domain": "",
            "dns": {
                "available": False,
            },
            "https": {
                "available": False,
            },
            "policy": {},
            "mode": "unknown",
            "mx": [],
            "strict": False,
            "valid_policy": False,
            "issues": [reason],
            "severity": "INFO",
            "evidence_type": "MTA_STS_POLICY",
        }

