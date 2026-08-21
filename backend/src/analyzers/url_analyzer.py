# ============================================================
# backend/src/analyzers/url_analyzer.py
# ============================================================

from __future__ import annotations

import difflib
import ipaddress
import re
from email.utils import parseaddr
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import (
    parse_qs,
    unquote,
    urlparse,
)

import tldextract

try:
    from bs4 import BeautifulSoup

    _BS4_AVAILABLE = True
except ImportError:
    BeautifulSoup = None
    _BS4_AVAILABLE = False

from src.services.url_inspection_service import (
    URLInspectionService,
)


# ============================================================
# Known redirect/safety-wrapper patterns
# ============================================================

_REDIRECT_PATTERNS = [
    ("google.com", "q"),
    ("google.com", "url"),
    ("safelinks.protection.outlook.com", "url"),
    ("urldefense.com", "u"),
    (None, "redirect_uri"),
    (None, "redirect_url"),
    (None, "target_url"),
    (None, "destination"),
]


class URLAnalyzer:
    """
    Defensive URL intelligence analyzer.

    Responsibilities:
    - Extract URLs from plain text and HTML email.
    - Safely normalize and unwrap known redirect wrappers.
    - Generate lexical URL evidence.
    - Inspect URLs through URLInspectionService.
    - Evaluate sender/URL alignment.
    - Detect brand relationships and lookalikes.
    - Normalize TLS policy evidence.
    - Preserve structured evidence for ARE / fusion.

    Important:
    - URL indicators are evidence, not final verdicts.
    - A trusted domain is not automatically SAFE.
    - HTTPS is not automatically SAFE.
    - HTTP is a warning, not automatically phishing.
    - TLS inspection failure is not the same as a certificate violation.
    """

    TRUSTED_DOMAINS = {
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "accounts.google.com",
        "myaccount.google.com",
        "mail.google.com",

        "microsoft.com",
        "microsoftonline.com",
        "office.com",
        "live.com",
        "outlook.com",
        "account.microsoft.com",
        "accountprotection.microsoft.com",

        "apple.com",
        "icloud.com",
        "appleid.apple.com",
        "id.apple.com",

        "amazon.com",
        "amazon.in",
        "amazonaws.com",

        "paypal.com",

        "github.com",
        "githubusercontent.com",

        "linkedin.com",
        "lnkd.in",

        "facebook.com",
        "instagram.com",
        "meta.com",

        "x.com",
        "twitter.com",

        "dropbox.com",
        "cloudflare.com",
    }

    SHORTENERS = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "shorturl.at",
    }

    SUSPICIOUS_KEYWORDS = {
        "login",
        "verify",
        "secure",
        "account",
        "password",
        "update",
        "confirm",
        "signin",
        "authenticate",
        "unlock",
        "suspended",
        "validation",
        "credential",
    }

    TLS_POLICY_VIOLATIONS = {
        "EXPIRED_CERTIFICATE",
        "HOSTNAME_MISMATCH",
        "SELF_SIGNED_CERTIFICATE",
        "UNTRUSTED_ISSUER",
        "CERTIFICATE_INVALID",
    }

    TLS_UNAVAILABLE_STATES = {
        "TLS_HANDSHAKE_FAILED",
        "TLS_UNAVAILABLE",
    }

    URL_TRAILING_CHARS = ".,;:!?)]}>\"'"

    URL_PATTERN = re.compile(
        r"https?://[^\s<>'\"\]\[()]+",
        re.IGNORECASE,
    )

    WWW_PATTERN = re.compile(
        r"(?<![/\w])www\.[^\s<>'\"\]\[()]+",
        re.IGNORECASE,
    )

    EMAIL_ADDRESS_PATTERN = re.compile(
        r"(?<![\w.+-])"
        r"[A-Za-z0-9._%+-]+@"
        r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    )

    def __init__(
        self,
        inspection_service=None,
    ):
        self.inspection_service = (
            inspection_service
            if inspection_service is not None
            else URLInspectionService()
        )

        self._tld_cache: Dict[
            str,
            Any,
        ] = {}

    # ========================================================
    # Main API
    # ========================================================

    def analyze(
        self,
        body: str | None,
        sender_headers: Dict[str, Any] | None = None,
        auth_results: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:

        body = (
            body
            if isinstance(body, str)
            else str(body or "")
        )

        sender_headers = (
            sender_headers
            if isinstance(sender_headers, dict)
            else {}
        )

        auth_results = (
            auth_results
            if isinstance(auth_results, dict)
            else {}
        )

        urls = self.extract_urls(
            body
        )

        results = []

        for url in urls:
            try:
                results.append(
                    self.analyze_url(
                        url=url,
                        sender_headers=sender_headers,
                        auth_results=auth_results,
                    )
                )
            except Exception as exc:
                results.append(
                    self._failed_url_result(
                        url,
                        str(exc),
                    )
                )

        limited_context = (
            self._is_limited_context(
                body,
                urls,
            )
        )

        structured_evidence = []

        for result in results:
            structured_evidence.extend(
                result.get(
                    "structured_evidence",
                    [],
                )
                or []
            )

        # Link-only should remain a context state.
        # It must not be converted into SAFE simply because
        # the URL itself has no obvious lexical indicators.
        if limited_context:
            structured_evidence.append(
                self._evidence(
                    type_="LIMITED_CONTEXT",
                    severity="MEDIUM",
                    direction="NEUTRAL",
                    source="URLAnalyzer",
                    explanation=(
                        "The email contains URLs with very little "
                        "surrounding text."
                    ),
                    confidence=0.90,
                )
            )

        return {
            "analysis_status": "AVAILABLE",
            "urls": urls,
            "count": len(urls),
            "analysis": results,
            "limited_context": limited_context,
            "link_only": limited_context,
            "structured_evidence": (
                self._deduplicate_evidence(
                    structured_evidence
                )
            ),
        }

    # ========================================================
    # Limited context
    # ========================================================

    def _is_limited_context(
        self,
        body: str,
        urls: Iterable[str],
    ) -> bool:

        urls = list(
            urls or []
        )

        if not urls:
            return False

        text_without_urls = self.URL_PATTERN.sub(
            " ",
            body or "",
        )

        text_without_urls = self.WWW_PATTERN.sub(
            " ",
            text_without_urls,
        )

        cleaned_text = re.sub(
            r"\s+",
            " ",
            text_without_urls,
        ).strip()

        words = (
            cleaned_text.split()
            if cleaned_text
            else []
        )

        return (
            len(cleaned_text) < 30
            or len(words) < 5
        )

    # ========================================================
    # Redirect unwrapping
    # ========================================================

    def _unwrap_redirect(
        self,
        url: str,
        max_depth: int = 3,
    ) -> str:

        current = (
            self._normalize_url(
                url
            )
        )

        seen = set()

        for _ in range(
            max_depth
        ):

            if not current:
                break

            if current in seen:
                break

            seen.add(
                current
            )

            next_url = (
                self._unwrap_once(
                    current
                )
            )

            if (
                next_url == current
                or not next_url
            ):
                break

            current = next_url

        return current

    def _unwrap_once(
        self,
        url: str,
    ) -> str:

        try:
            parsed = urlparse(
                url
            )

            hostname = (
                parsed.hostname
                or ""
            ).lower().rstrip(".")

            if not hostname:
                return url

            query = parse_qs(
                parsed.query,
                keep_blank_values=True,
            )

            for domain, parameter in (
                _REDIRECT_PATTERNS
            ):

                if domain is not None:

                    if not self._domain_matches(
                        hostname,
                        domain,
                    ):
                        continue

                values = query.get(
                    parameter
                )

                if not values:
                    continue

                inner = unquote(
                    str(
                        values[0]
                    )
                ).strip()

                inner = self._normalize_url(
                    inner
                )

                try:
                    inner_parsed = urlparse(
                        inner
                    )
                except Exception:
                    continue

                if (
                    inner_parsed.scheme.lower()
                    in {"http", "https"}
                    and inner_parsed.hostname
                ):
                    return inner

        except Exception:
            return url

        return url

    # ========================================================
    # URL extraction
    # ========================================================

    def extract_urls(
        self,
        text: str | None,
    ) -> List[str]:

        if not text:
            return []

        text = str(
            text
        )

        raw_urls: List[str] = []

        # ----------------------------------------------------
        # HTML extraction
        # ----------------------------------------------------

        if (
            _BS4_AVAILABLE
            and (
                "<a " in text.lower()
                or "href=" in text.lower()
                or "<form" in text.lower()
                or "<iframe" in text.lower()
            )
        ):

            try:
                soup = BeautifulSoup(
                    text,
                    "html.parser",
                )

                for tag in soup.find_all(
                    [
                        "a",
                        "link",
                        "img",
                        "iframe",
                        "form",
                        "area",
                    ]
                ):

                    for attr in (
                        "href",
                        "src",
                        "action",
                        "data-url",
                        "data-href",
                    ):

                        value = tag.get(
                            attr
                        )

                        if not isinstance(
                            value,
                            str,
                        ):
                            continue

                        value = self._normalize_url(
                            value
                        )

                        if self._is_http_url(
                            value
                        ):
                            raw_urls.append(
                                value
                            )

            except Exception:
                # Regex extraction below remains available.
                pass

        # ----------------------------------------------------
        # Plain-text http/https URLs
        # ----------------------------------------------------

        raw_urls.extend(
            self.URL_PATTERN.findall(
                text
            )
        )

        # ----------------------------------------------------
        # www.example.com fallback
        # ----------------------------------------------------

        for value in self.WWW_PATTERN.findall(
            text
        ):
            normalized = (
                "http://"
                + self._normalize_url(
                    value
                )
            )

            raw_urls.append(
                normalized
            )

        # ----------------------------------------------------
        # Normalize, unwrap and deduplicate
        # ----------------------------------------------------

        cleaned_urls = []
        seen = set()

        for raw_url in raw_urls:

            url = self._normalize_url(
                raw_url
            )

            if not self._is_http_url(
                url
            ):
                continue

            url = self._unwrap_redirect(
                url
            )

            url = self._normalize_url(
                url
            )

            if not self._is_http_url(
                url
            ):
                continue

            # Normalize host casing while preserving the rest
            # of the URL as much as possible.
            key = self._canonical_url_key(
                url
            )

            if key in seen:
                continue

            seen.add(
                key
            )

            cleaned_urls.append(
                url
            )

        return cleaned_urls

    # ========================================================
    # Analyze single URL
    # ========================================================

    def analyze_url(
        self,
        url: str,
        sender_headers: Dict[str, Any] | None = None,
        auth_results: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:

        sender_headers = (
            sender_headers
            if isinstance(
                sender_headers,
                dict,
            )
            else {}
        )

        auth_results = (
            auth_results
            if isinstance(
                auth_results,
                dict,
            )
            else {}
        )

        url = self._normalize_url(
            url
        )

        # ----------------------------------------------------
        # Safe parsing
        # ----------------------------------------------------

        try:
            parsed = urlparse(
                url
            )
        except Exception:
            return self._failed_url_result(
                url,
                "Invalid URL syntax",
            )

        if (
            parsed.scheme.lower()
            not in {
                "http",
                "https",
            }
            or not parsed.hostname
        ):
            return self._failed_url_result(
                url,
                "Unsupported or invalid URL",
            )

        domain = (
            parsed.hostname
            or ""
        ).lower().rstrip(".")

        registered_domain = (
            self._registered_domain(
                domain
            )
        )

        # ----------------------------------------------------
        # Inspection service
        # ----------------------------------------------------

        try:

            inspection_data = (
                self.inspection_service.inspect(
                    url
                )
                or {}
            )

        except Exception as exc:

            inspection_data = {
                "analysis_status": "UNAVAILABLE",
                "inspection_error": (
                    "URL inspection unavailable"
                ),
                "inspection_error_detail": str(
                    exc
                ),
            }

        # Never allow inspection failure to erase
        # deterministic local fields.
        inspection_data = dict(
            inspection_data
        )

        inspection_data.setdefault(
            "analysis_status",
            "AVAILABLE",
        )

        inspection_data["url"] = url
        inspection_data["domain"] = domain

        if not inspection_data.get(
            "registered_domain"
        ):
            inspection_data[
                "registered_domain"
            ] = registered_domain

        # ----------------------------------------------------
        # Basic lexical indicators
        # ----------------------------------------------------

        inspection_data[
            "ip_based"
        ] = self.is_ip(
            domain
        )

        inspection_data[
            "shortener"
        ] = self.is_shortener(
            domain
        )

        inspection_data[
            "keywords"
        ] = self.detect_keywords(
            url,
            domain,
        )

        inspection_data[
            "obfuscated"
        ] = self.is_obfuscated(
            url
        )

        inspection_data[
            "punycode"
        ] = self.is_punycode(
            domain
        )

        inspection_data[
            "suspicious_port"
        ] = self.has_suspicious_port(
            parsed
        )

        inspection_data[
            "subdomain_count"
        ] = self.subdomain_count(
            domain
        )

        # ----------------------------------------------------
        # Alignment
        # ----------------------------------------------------

        inspection_data[
            "email_alignment"
        ] = self.evaluate_alignment(
            inspection_data,
            sender_headers,
            auth_results,
        )

        inspection_data[
            "alignment"
        ] = inspection_data[
            "email_alignment"
        ]

        # ----------------------------------------------------
        # Brand relationship
        # ----------------------------------------------------

        brand_relationship = (
            self.evaluate_brand_relationship(
                inspection_data
            )
        )

        inspection_data[
            "brand_relationship"
        ] = brand_relationship

        inspection_data[
            "brand_impersonation"
        ] = brand_relationship in {
            "IMPERSONATION",
            "LOOKALIKE",
        }

        inspection_data[
            "brand_match"
        ] = brand_relationship in {
            "OFFICIAL",
            "SUBDOMAIN_OF_OFFICIAL",
        }

        # ----------------------------------------------------
        # TLS
        # ----------------------------------------------------

        self._apply_tls_policy(
            inspection_data
        )

        # ----------------------------------------------------
        # Structured evidence
        # ----------------------------------------------------

        structured_evidence = (
            inspection_data.get(
                "structured_evidence",
                [],
            )
            or []
        )

        structured_evidence = list(
            structured_evidence
        )

        structured_evidence.extend(
            self._build_local_evidence(
                inspection_data
            )
        )

        inspection_data[
            "structured_evidence"
        ] = self._deduplicate_evidence(
            structured_evidence
        )

        # ----------------------------------------------------
        # Contextual risk summary
        # ----------------------------------------------------

        inspection_data[
            "risk_indicators"
        ] = self._risk_indicators(
            inspection_data
        )

        inspection_data[
            "has_strong_negative_evidence"
        ] = self._has_strong_negative_evidence(
            inspection_data
        )

        return inspection_data

    # ========================================================
    # TLS policy normalization
    # ========================================================

    def _apply_tls_policy(
        self,
        inspection_data: Dict[str, Any],
    ) -> None:

        tls_info = (
            inspection_data.get(
                "tls",
                {},
            )
            or {}
        )

        violation = str(
            tls_info.get(
                "violation",
                "",
            )
            or ""
        ).upper()

        https_value = tls_info.get(
            "https"
        )

        inspection_data[
            "http_policy_warning"
        ] = (
            https_value is False
        )

        inspection_data[
            "tls_policy_violation"
        ] = (
            violation
            in self.TLS_POLICY_VIOLATIONS
        )

        inspection_data[
            "tls_inspection_unavailable"
        ] = (
            violation
            in self.TLS_UNAVAILABLE_STATES
        )

        # Explicit certificate details are preserved.
        inspection_data[
            "tls_violation"
        ] = violation or None

        inspection_data[
            "tls_error_detail"
        ] = tls_info.get(
            "error_detail"
        )

        if inspection_data[
            "tls_policy_violation"
        ]:

            inspection_data[
                "tls_risk_severity"
            ] = str(
                tls_info.get(
                    "severity",
                    "MEDIUM",
                )
            ).upper()

        elif inspection_data[
            "tls_inspection_unavailable"
        ]:

            inspection_data[
                "tls_risk_severity"
            ] = "INFO"

        elif inspection_data[
            "http_policy_warning"
        ]:

            inspection_data[
                "tls_risk_severity"
            ] = "LOW"

        else:

            inspection_data[
                "tls_risk_severity"
            ] = (
                tls_info.get(
                    "severity",
                    "INFO",
                )
                or "INFO"
            )

    # ========================================================
    # Alignment
    # ========================================================
    @staticmethod
    def get_email_domain(value: Any) -> str:
        """
        Extract the normalized domain from an email address or
        a full email header value such as:
        'Security Team <security@example.com>'.
        """
        if not value:
            return ""

        try:
            _, address = parseaddr(str(value))
        except Exception:
            address = str(value)

        address = address.strip().lower()

        if "@" not in address:
            return ""

        domain = address.rsplit("@", 1)[-1].strip().strip(">").strip()

        if not domain:
            return ""

        try:
            return domain.encode("idna").decode("ascii").lower()
        except Exception:
            return domain.lower()   
    def evaluate_alignment(
        self,
        inspection_data: Dict[str, Any],
        sender_headers: Dict[str, Any] | None,
        auth_results: Dict[str, Any] | None,
    ) -> str:
        if not sender_headers:
            return "unknown"

        url_registered_domain = (
            inspection_data.get(
                "registered_domain"
            )
            or ""
        ).lower()

        if not url_registered_domain:
            return "unknown"

        def _header_value(*names: str) -> str:
            for name in names:
                value = sender_headers.get(name)
                if value:
                    return str(value)

            lowered = {
                str(key).lower(): value
                for key, value in sender_headers.items()
            }

            for name in names:
                value = lowered.get(name.lower())
                if value:
                    return str(value)

            return ""

        from_domain = self.get_email_domain(
            _header_value(
                "from",
                "From",
            )
        )

        return_path_domain = self.get_email_domain(
            _header_value(
                "return-path",
                "Return-Path",
            )
        )

        if not from_domain:
            return "unknown"

        sender_registered_domain = (
            self._registered_domain(
                from_domain
            )
        )

        return_path_registered_domain = (
            self._registered_domain(
                return_path_domain
            )
            if return_path_domain
            else ""
        )

        auth_state = (
            self._authentication_state(
                auth_results
            )
        )

        if (
            sender_registered_domain
            == url_registered_domain
        ):
            if auth_state == "PASSED":
                return "aligned"

            if auth_state == "FAILED":
                return "misaligned"

            return "unknown"

        if (
            return_path_registered_domain
            and return_path_registered_domain
            == url_registered_domain
            and auth_state == "PASSED"
        ):
            return "aligned"

        if (
            sender_registered_domain
            and sender_registered_domain
            != url_registered_domain
        ):
            return "misaligned"

        return "unknown"

    # ========================================================
    # Brand relationship
    # ========================================================

    def evaluate_brand_relationship(
        self,
        inspection_data: Dict[str, Any],
    ) -> str:

        hostname = (
            inspection_data.get(
                "domain",
                "",
            )
            or ""
        ).lower().rstrip(".")

        registered_domain = (
            inspection_data.get(
                "registered_domain",
                "",
            )
            or ""
        ).lower().rstrip(".")

        if not hostname:
            return "UNKNOWN"

        # ----------------------------------------------------
        # Exact / legitimate subdomain
        # ----------------------------------------------------

        for trusted in self.TRUSTED_DOMAINS:

            trusted = (
                trusted.lower().rstrip(".")
            )

            if hostname == trusted:
                return "OFFICIAL"

            if hostname.endswith(
                "."
                + trusted
            ):
                return "SUBDOMAIN_OF_OFFICIAL"

        # ----------------------------------------------------
        # Extract trusted brand labels
        # ----------------------------------------------------

        trusted_brands = []

        for trusted in self.TRUSTED_DOMAINS:

            try:
                trusted_extract = (
                    tldextract.extract(
                        trusted
                    )
                )

                brand = (
                    trusted_extract.domain
                    or trusted.split(
                        "."
                    )[0]
                )

            except Exception:
                brand = trusted.split(
                    "."
                )[0]

            if brand:
                trusted_brands.append(
                    (
                        trusted,
                        brand.lower(),
                    )
                )

        # ----------------------------------------------------
        # Registered-domain comparison
        # ----------------------------------------------------

        for trusted, brand in trusted_brands:

            if not registered_domain:
                continue

            if (
                registered_domain
                == trusted
            ):
                continue

            # Brand appears in the host but the registered
            # domain is unrelated.
            labels = (
                hostname.split(".")
            )

            brand_present = any(
                (
                    len(brand) >= 4
                    and (
                        brand == label
                        or brand in label
                    )
                )
                for label in labels
            )

            if brand_present:

                return "IMPERSONATION"

        # ----------------------------------------------------
        # Lookalike / typo-squatting
        # ----------------------------------------------------

        candidate_labels = (
            hostname.split(".")
        )

        for trusted, brand in trusted_brands:

            if len(brand) < 4:
                continue

            for label in candidate_labels:

                if len(label) < 4:
                    continue

                normalized_label = (
                    self._normalize_lookalike(
                        label
                    )
                )

                if (
                    normalized_label
                    == brand
                    and registered_domain
                    != trusted
                ):
                    return "LOOKALIKE"

                ratio = (
                    difflib.SequenceMatcher(
                        None,
                        brand,
                        normalized_label,
                    ).ratio()
                )

                if (
                    ratio >= 0.88
                    and registered_domain
                    != trusted
                ):
                    return "LOOKALIKE"

        return "UNKNOWN"

    # ========================================================
    # IP / shortener / trusted domain
    # ========================================================

    @staticmethod
    def is_ip(
        domain: str,
    ) -> bool:

        if not domain:
            return False

        try:
            ipaddress.ip_address(
                domain
            )
            return True
        except ValueError:
            return False

    def is_shortener(
        self,
        domain: str,
    ) -> bool:

        domain = (
            domain
            or ""
        ).lower().rstrip(".")

        return (
            domain in self.SHORTENERS
        )

    def is_trusted_domain(
        self,
        domain: str,
    ) -> bool:

        domain = (
            domain
            or ""
        ).lower().rstrip(".")

        for trusted in self.TRUSTED_DOMAINS:

            trusted = (
                trusted.lower().rstrip(".")
            )

            if (
                domain == trusted
                or domain.endswith(
                    "."
                    + trusted
                )
            ):
                return True

        return False

    # ========================================================
    # Keyword detection
    # ========================================================

    def detect_keywords(
        self,
        url: str,
        domain: str,
    ) -> List[str]:

        if self.is_trusted_domain(
            domain
        ):
            return []

        decoded_url = unquote(
            url
        ).lower()

        found = []

        for word in (
            self.SUSPICIOUS_KEYWORDS
        ):

            if word in decoded_url:
                found.append(
                    word
                )

        return sorted(
            set(found)
        )

    # ========================================================
    # Obfuscation
    # ========================================================

    def is_obfuscated(
        self,
        url: str,
    ) -> bool:

        try:
            parsed = urlparse(
                url
            )

        except Exception:
            return True

        domain = (
            parsed.hostname
            or ""
        ).lower()

        # ----------------------------------------------------
        # Credentials embedded in authority
        # ----------------------------------------------------

        if parsed.username is not None:
            return True

        if parsed.password is not None:
            return True

        # ----------------------------------------------------
        # Percent encoding in hostname/netloc
        # ----------------------------------------------------

        if "%" in (
            parsed.netloc
            or ""
        ):
            return True

        # ----------------------------------------------------
        # Suspicious control characters
        # ----------------------------------------------------

        if any(
            ord(char) < 32
            for char in url
        ):
            return True

        # ----------------------------------------------------
        # Punycode is separately classified. Do not double
        # count it here.
        # ----------------------------------------------------

        if (
            "xn--" in domain
        ):
            return False

        # ----------------------------------------------------
        # Odd numeric/IP-looking host
        # ----------------------------------------------------

        if (
            domain
            and self.is_ip(
                domain
            )
        ):
            return True

        return False

    # ========================================================
    # Punycode
    # ========================================================

    @staticmethod
    def is_punycode(
        domain: str,
    ) -> bool:

        return (
            "xn--"
            in (
                domain
                or ""
            ).lower()
        )

    # ========================================================
    # Port
    # ========================================================

    @staticmethod
    def has_suspicious_port(
        parsed,
    ) -> bool:

        try:

            port = parsed.port

            if port is None:
                return False

            return port not in {
                80,
                443,
            }

        except ValueError:
            return True

    # ========================================================
    # Subdomain count
    # ========================================================

    def subdomain_count(
        self,
        domain: str,
    ) -> int:

        if not domain:
            return 0

        if self.is_ip(
            domain
        ):
            return 0

        registered_domain = self._registered_domain(
            domain
        )

        if not registered_domain:
            return 0

        labels = [
            item
            for item in domain.split(".")
            if item
        ]

        registered_labels = [
            item
            for item in registered_domain.split(".")
            if item
        ]

        return max(
            0,
            len(
                labels
            )
            - len(
                registered_labels
            ),
        )

    # ========================================================
    # Registered domain
    # ========================================================

    def _registered_domain(
        self,
        domain: str | None,
    ) -> str:

        domain = (
            domain
            or ""
        ).lower().strip(".")

        if not domain:
            return ""

        if self.is_ip(
            domain
        ):
            return domain

        cached = (
            self._tld_cache.get(
                domain
            )
        )

        if cached is not None:
            return cached

        try:

            extracted = tldextract.extract(
                domain
            )

            registered = (
                extracted.registered_domain
            )

            if not registered:

                if (
                    extracted.domain
                    and extracted.suffix
                ):
                    registered = (
                        extracted.domain
                        + "."
                        + extracted.suffix
                    )

                else:
                    registered = domain

        except Exception:
            registered = domain

        self._tld_cache[
            domain
        ] = registered

        return registered

    # ========================================================
    # Authentication state
    # ========================================================

    @staticmethod
    def _authentication_state(
        auth_results: Dict[str, Any] | None,
    ) -> str:

        if not isinstance(
            auth_results,
            dict,
        ):
            return "UNAVAILABLE"

        status = str(
            auth_results.get(
                "analysis_status",
                "AVAILABLE",
            )
        ).upper()

        if status == "UNAVAILABLE":
            return "UNAVAILABLE"

        spf = URLAnalyzer._auth_value(
            auth_results,
            "spf",
            "spf_result",
        )

        dkim = URLAnalyzer._auth_value(
            auth_results,
            "dkim",
            "dkim_result",
        )

        dmarc = URLAnalyzer._auth_value(
            auth_results,
            "dmarc",
            "dmarc_result",
        )

        if (
            spf == "pass"
            and dkim == "pass"
            and dmarc == "pass"
        ):
            return "PASSED"

        if (
            spf == "fail"
            or dkim == "fail"
            or dmarc == "fail"
        ):
            return "FAILED"

        if (
            spf
            or dkim
            or dmarc
        ):
            return "PARTIAL"

        return "UNAVAILABLE"

    @staticmethod
    def _auth_value(
        auth_results: Dict[str, Any],
        primary: str,
        fallback: str,
    ) -> str:

        return str(
            auth_results.get(
                primary,
                auth_results.get(
                    fallback,
                    "",
                ),
            )
            or ""
        ).strip().lower()

    # ========================================================
    # Evidence generation
    # ========================================================

    def _build_local_evidence(
        self,
        inspection_data: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        evidence = []

        domain = (
            inspection_data.get(
                "domain",
                "",
            )
        )

        if inspection_data.get(
            "ip_based"
        ):

            evidence.append(
                self._evidence(
                    type_="SUSPICIOUS_URL",
                    severity="HIGH",
                    direction="NEGATIVE",
                    source="URLAnalyzer",
                    explanation=(
                        f"URL uses an IP address as the destination: {domain}."
                    ),
                    confidence=0.90,
                )
            )

        if inspection_data.get(
            "shortener"
        ):

            evidence.append(
                self._evidence(
                    type_="SUSPICIOUS_URL",
                    severity="MEDIUM",
                    direction="NEGATIVE",
                    source="URLAnalyzer",
                    explanation=(
                        "URL uses a shortening service."
                    ),
                    confidence=0.80,
                )
            )

        keywords = (
            inspection_data.get(
                "keywords",
                [],
            )
            or []
        )

        if keywords:

            evidence.append(
                self._evidence(
                    type_="SUSPICIOUS_URL_KEYWORD",
                    severity="LOW",
                    direction="NEGATIVE",
                    source="URLAnalyzer",
                    explanation=(
                        "URL contains contextual security-sensitive "
                        "keywords: "
                        + ", ".join(
                            keywords
                        )
                    ),
                    confidence=0.55,
                )
            )

        if inspection_data.get(
            "punycode"
        ):

            evidence.append(
                self._evidence(
                    type_="PUNYCODE_DOMAIN",
                    severity="HIGH",
                    direction="NEGATIVE",
                    source="URLAnalyzer",
                    explanation=(
                        "Destination domain uses Punycode."
                    ),
                    confidence=0.90,
                )
            )

        if inspection_data.get(
            "obfuscated"
        ):

            evidence.append(
                self._evidence(
                    type_="OBFUSCATED_URL",
                    severity="HIGH",
                    direction="NEGATIVE",
                    source="URLAnalyzer",
                    explanation=(
                        "URL contains obfuscation indicators."
                    ),
                    confidence=0.90,
                )
            )

        if inspection_data.get(
            "suspicious_port"
        ):

            evidence.append(
                self._evidence(
                    type_="SUSPICIOUS_URL_PORT",
                    severity="MEDIUM",
                    direction="NEGATIVE",
                    source="URLAnalyzer",
                    explanation=(
                        "URL uses a non-standard HTTP/HTTPS port."
                    ),
                    confidence=0.80,
                )
            )

        subdomain_count = self._safe_int(
            inspection_data.get(
                "subdomain_count",
                0,
            )
        )

        if subdomain_count > 3:

            evidence.append(
                self._evidence(
                    type_="EXCESSIVE_SUBDOMAINS",
                    severity="LOW",
                    direction="NEGATIVE",
                    source="URLAnalyzer",
                    explanation=(
                        f"Destination contains {subdomain_count} "
                        "subdomain level(s)."
                    ),
                    confidence=0.65,
                )
            )

        relationship = (
            inspection_data.get(
                "brand_relationship",
                "UNKNOWN",
            )
        )

        if relationship == "OFFICIAL":

            evidence.append(
                self._evidence(
                    type_="OFFICIAL_BRAND",
                    severity="LOW",
                    direction="POSITIVE",
                    source="URLAnalyzer",
                    explanation=(
                        "URL exactly matches a recognized official domain."
                    ),
                    confidence=0.95,
                )
            )

        elif relationship == "SUBDOMAIN_OF_OFFICIAL":

            evidence.append(
                self._evidence(
                    type_="OFFICIAL_BRAND_SUBDOMAIN",
                    severity="LOW",
                    direction="POSITIVE",
                    source="URLAnalyzer",
                    explanation=(
                        "URL is a subdomain of a recognized official domain."
                    ),
                    confidence=0.92,
                )
            )

        elif relationship == "IMPERSONATION":

            evidence.append(
                self._evidence(
                    type_="BRAND_IMPERSONATION",
                    severity="CRITICAL",
                    direction="NEGATIVE",
                    source="URLAnalyzer",
                    explanation=(
                        "URL appears to impersonate a recognized brand."
                    ),
                    confidence=0.95,
                )
            )

        elif relationship == "LOOKALIKE":

            evidence.append(
                self._evidence(
                    type_="HOMOGRAPH_DOMAIN",
                    severity="HIGH",
                    direction="NEGATIVE",
                    source="URLAnalyzer",
                    explanation=(
                        "URL appears visually or lexically similar "
                        "to a recognized brand domain."
                    ),
                    confidence=0.90,
                )
            )

        alignment = str(
            inspection_data.get(
                "email_alignment",
                "unknown",
            )
        ).lower()

        if alignment == "aligned":

            evidence.append(
                self._evidence(
                    type_="URL_ALIGNMENT",
                    severity="LOW",
                    direction="POSITIVE",
                    source="URLAnalyzer",
                    explanation=(
                        "URL registered domain aligns with the sender."
                    ),
                    confidence=0.90,
                )
            )

        elif alignment == "misaligned":

            evidence.append(
                self._evidence(
                    type_="DOMAIN_MISMATCH",
                    severity="HIGH",
                    direction="NEGATIVE",
                    source="URLAnalyzer",
                    explanation=(
                        "URL registered domain does not align with the sender."
                    ),
                    confidence=0.90,
                )
            )

        # ----------------------------------------------------
        # TLS
        # ----------------------------------------------------

        if inspection_data.get(
            "tls_policy_violation"
        ):

            tls = (
                inspection_data.get(
                    "tls",
                    {},
                )
                or {}
            )

            evidence.append(
                self._evidence(
                    type_="TLS_POLICY_VIOLATION",
                    severity=self._normalize_severity(
                        tls.get(
                            "severity",
                            "MEDIUM",
                        )
                    ),
                    direction="NEGATIVE",
                    source="URLAnalyzer",
                    explanation=(
                        "TLS policy violation: "
                        + str(
                            tls.get(
                                "violation",
                                "UNKNOWN",
                            )
                        )
                    ),
                    confidence=0.90,
                )
            )

        elif inspection_data.get(
            "http_policy_warning"
        ):

            evidence.append(
                self._evidence(
                    type_="HTTP_POLICY_WARNING",
                    severity="LOW",
                    direction="NEGATIVE",
                    source="URLAnalyzer",
                    explanation=(
                        "URL uses plain HTTP instead of HTTPS."
                    ),
                    confidence=0.90,
                )
            )

        elif inspection_data.get(
            "tls_inspection_unavailable"
        ):

            evidence.append(
                self._evidence(
                    type_="TLS_INSPECTION_UNAVAILABLE",
                    severity="INFO",
                    direction="NEUTRAL",
                    source="URLAnalyzer",
                    explanation=(
                        "TLS inspection could not be completed."
                    ),
                    confidence=0.0,
                )
            )

        return evidence

    # ========================================================
    # Risk summary
    # ========================================================

    @staticmethod
    def _risk_indicators(
        inspection_data: Dict[str, Any],
    ) -> List[str]:

        indicators = []

        if inspection_data.get(
            "ip_based"
        ):
            indicators.append(
                "IP-based URL"
            )

        if inspection_data.get(
            "shortener"
        ):
            indicators.append(
                "URL shortener"
            )

        if inspection_data.get(
            "punycode"
        ):
            indicators.append(
                "Punycode domain"
            )

        if inspection_data.get(
            "obfuscated"
        ):
            indicators.append(
                "Obfuscated URL"
            )

        if inspection_data.get(
            "suspicious_port"
        ):
            indicators.append(
                "Suspicious port"
            )

        if inspection_data.get(
            "brand_impersonation"
        ):
            indicators.append(
                "Brand impersonation"
            )

        if inspection_data.get(
            "email_alignment"
        ) == "misaligned":
            indicators.append(
                "Sender/domain mismatch"
            )

        if inspection_data.get(
            "tls_policy_violation"
        ):
            indicators.append(
                "TLS policy violation"
            )

        if inspection_data.get(
            "http_policy_warning"
        ):
            indicators.append(
                "Insecure transport"
            )

        return indicators

    def _has_strong_negative_evidence(
        self,
        inspection_data: Dict[str, Any],
    ) -> bool:

        evidence = (
            inspection_data.get(
                "structured_evidence",
                [],
            )
            or []
        )

        return any(
            item.get(
                "direction"
            ) == "NEGATIVE"
            and (
                item.get(
                    "severity"
                )
                in {
                    "HIGH",
                    "CRITICAL",
                }
            )
            for item in evidence
            if isinstance(
                item,
                dict,
            )
        )

    # ========================================================
    # Failed result
    # ========================================================

    def _failed_url_result(
        self,
        url: str,
        error: str,
    ) -> Dict[str, Any]:

        return {
            "analysis_status": "UNAVAILABLE",
            "url": url,
            "domain": "",
            "registered_domain": "",
            "inspection_error": (
                "URL analysis unavailable"
            ),
            "inspection_error_detail": str(
                error
            ),
            "ip_based": False,
            "shortener": False,
            "keywords": [],
            "obfuscated": False,
            "punycode": False,
            "suspicious_port": False,
            "subdomain_count": 0,
            "email_alignment": "unknown",
            "alignment": "unknown",
            "brand_relationship": "UNKNOWN",
            "brand_impersonation": False,
            "brand_match": False,
            "tls_policy_violation": False,
            "tls_inspection_unavailable": True,
            "http_policy_warning": False,
            "structured_evidence": [
                self._evidence(
                    type_="URL_ANALYSIS_UNAVAILABLE",
                    severity="INFO",
                    direction="NEUTRAL",
                    source="URLAnalyzer",
                    explanation=(
                        "URL inspection was unavailable."
                    ),
                    confidence=0.0,
                )
            ],
            "risk_indicators": [],
            "has_strong_negative_evidence": False,
        }

    # ========================================================
    # Normalization helpers
    # ========================================================

    @staticmethod
    def _normalize_url(
        url: Any,
    ) -> str:

        url = str(
            url
            or ""
        ).strip()

        url = url.strip(
            URLAnalyzer.URL_TRAILING_CHARS
        )

        return url

    @staticmethod
    def _is_http_url(
        url: str,
    ) -> bool:

        if not url:
            return False

        try:
            parsed = urlparse(
                url
            )

            return (
                parsed.scheme.lower()
                in {
                    "http",
                    "https",
                }
                and bool(
                    parsed.hostname
                )
            )

        except (
            ValueError,
            TypeError,
        ):
            return False

    @staticmethod
    def _canonical_url_key(
        url: str,
    ) -> str:

        try:
            parsed = urlparse(
                url
            )

            scheme = (
                parsed.scheme.lower()
            )

            hostname = (
                parsed.hostname
                or ""
            ).lower().rstrip(".")

            port = ""

            try:
                if parsed.port:
                    if not (
                        (
                            scheme == "http"
                            and parsed.port == 80
                        )
                        or (
                            scheme == "https"
                            and parsed.port == 443
                        )
                    ):
                        port = (
                            ":"
                            + str(
                                parsed.port
                            )
                        )
            except ValueError:
                return url.lower()

            path = (
                parsed.path
                or "/"
            )

            query = (
                parsed.query
                or ""
            )

            return (
                scheme
                + "://"
                + hostname
                + port
                + path
                + (
                    "?"
                    + query
                    if query
                    else ""
                )
            ).lower()

        except Exception:
            return str(
                url
            ).lower()

    def _normalize_lookalike(
        self,
        value: str,
    ) -> str:

        value = (
            value
            or ""
        ).lower()

        substitutions = str.maketrans(
            {
                "0": "o",
                "1": "l",
                "3": "e",
                "5": "s",
                "7": "t",
                "@": "a",
            }
        )

        return value.translate(
            substitutions
        )

    @staticmethod
    def _normalize_severity(
        severity: Any,
    ) -> str:

        value = str(
            severity
            or "MEDIUM"
        ).upper()

        if value not in {
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
            "INFO",
        }:
            return "MEDIUM"

        return value

    @staticmethod
    def _safe_int(
        value: Any,
    ) -> int:

        try:
            return int(
                float(
                    value
                    or 0
                )
            )
        except (
            TypeError,
            ValueError,
        ):
            return 0

    @staticmethod
    def _evidence(
        type_: str,
        severity: str,
        direction: str,
        source: str,
        explanation: str,
        confidence: float,
    ) -> Dict[str, Any]:

        try:
            confidence = float(
                confidence
            )
        except (
            TypeError,
            ValueError,
        ):
            confidence = 0.0

        return {
            "type": (
                str(
                    type_
                    or "UNKNOWN"
                )
                .strip()
                .upper()
                .replace(
                    "-",
                    "_",
                )
                .replace(
                    " ",
                    "_",
                )
            ),
            "severity": str(
                severity
                or "INFO"
            ).upper(),
            "direction": str(
                direction
                or "NEUTRAL"
            ).upper(),
            "source": source,
            "explanation": explanation,
            "confidence": max(
                0.0,
                min(
                    1.0,
                    confidence,
                ),
            ),
        }

    @staticmethod
    def _deduplicate_evidence(
        evidence,
    ) -> List[Dict[str, Any]]:

        if not isinstance(
            evidence,
            list,
        ):
            return []

        result = []
        seen = set()

        for item in evidence:

            if not isinstance(
                item,
                dict,
            ):
                continue

            key = (
                str(
                    item.get(
                        "type",
                        "",
                    )
                ),
                str(
                    item.get(
                        "severity",
                        "",
                    )
                ),
                str(
                    item.get(
                        "direction",
                        "",
                    )
                ),
                str(
                    item.get(
                        "source",
                        "",
                    )
                ),
                str(
                    item.get(
                        "explanation",
                        "",
                    )
                ),
            )

            if key in seen:
                continue

            seen.add(
                key
            )

            result.append(
                item
            )

        return result
