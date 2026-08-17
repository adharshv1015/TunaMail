# ============================================================
# backend/src/services/url_inspection_service.py
# ============================================================

from __future__ import annotations

import ipaddress
import logging
import socket
import ssl
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import (
    parse_qsl,
    urlencode,
    urlparse,
)

import tldextract

from .page_cache import page_cache
from .url_jobs import URLInspectionJob, url_queue
from .url_worker.worker import URLWorker


logger = logging.getLogger(__name__)


# ============================================================
# Network safety configuration
# ============================================================

BLOCKED_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
)


def _is_blocked_ip(
    value: str,
) -> bool:
    """
    Returns True for private, loopback, link-local,
    multicast, reserved, documentation, unspecified,
    and otherwise non-public addresses.
    """

    try:
        ip = ipaddress.ip_address(
            value
        )
    except ValueError:
        return True

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    ):
        return True

    for network in BLOCKED_NETWORKS:
        if ip in network:
            return True

    return False


def _resolve_dns(
    hostname: str,
) -> Dict[str, Any]:
    """
    Resolve a hostname and validate every returned address.

    A hostname is considered usable only when at least one
    public IP is available and no blocked/private address is
    encountered.
    """

    result = {
        "resolved": False,
        "a": [],
        "aaaa": [],
        "private_ip_detected": False,
        "blocked_ip_detected": False,
        "validated_ips": [],
        "error": None,
    }

    if not hostname:
        result["error"] = "Hostname is empty."
        return result

    hostname = (
        str(hostname)
        .strip()
        .rstrip(".")
    )

    try:
        addr_infos = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )

        seen = set()

        for info in addr_infos:
            if len(info) < 5:
                continue

            ip_value = info[4][0]

            if not ip_value:
                continue

            if ip_value in seen:
                continue

            seen.add(
                ip_value
            )

            try:
                ip_obj = ipaddress.ip_address(
                    ip_value
                )
            except ValueError:
                continue

            if _is_blocked_ip(
                ip_value
            ):
                result[
                    "private_ip_detected"
                ] = True

                result[
                    "blocked_ip_detected"
                ] = True

                continue

            if isinstance(
                ip_obj,
                ipaddress.IPv4Address,
            ):
                if ip_value not in result["a"]:
                    result["a"].append(
                        ip_value
                    )
            else:
                if ip_value not in result["aaaa"]:
                    result["aaaa"].append(
                        ip_value
                    )

            result[
                "validated_ips"
            ].append(
                ip_value
            )

        result["resolved"] = bool(
            result["validated_ips"]
        )

        if (
            not result["resolved"]
            and result["blocked_ip_detected"]
        ):
            result["error"] = (
                "Hostname resolves only to blocked/private addresses."
            )

    except socket.gaierror as exc:
        result["error"] = (
            "DNS resolution failed."
        )
        result["error_detail"] = str(
            exc
        )

    except socket.timeout as exc:
        result["error"] = (
            "DNS resolution timed out."
        )
        result["error_detail"] = str(
            exc
        )

    except Exception as exc:
        result["error"] = (
            "DNS resolution unavailable."
        )
        result["error_detail"] = str(
            exc
        )

    return result


# ============================================================
# Certificate helpers
# ============================================================

def _extract_certificate_metadata(
    cert: Dict[str, Any],
) -> Dict[str, Any]:
    issuer = None
    subject = None

    try:
        issuer_tuples = cert.get(
            "issuer",
            (),
        )

        for pair in issuer_tuples:
            for key_value in pair:
                if not key_value:
                    continue

                key, value = key_value

                if (
                    key in {
                        "organizationName",
                        "commonName",
                    }
                    and issuer is None
                ):
                    issuer = value

        subject_tuples = cert.get(
            "subject",
            (),
        )

        subject_values = []

        for pair in subject_tuples:
            for key_value in pair:
                if not key_value:
                    continue

                key, value = key_value

                if key in {
                    "commonName",
                    "organizationName",
                }:
                    subject_values.append(
                        value
                    )

        if subject_values:
            subject = ", ".join(
                str(value)
                for value in subject_values
            )

    except Exception:
        pass

    return {
        "issuer": issuer,
        "subject": subject,
    }


def _normalize_tls_error(
    exc: BaseException,
) -> Dict[str, Any]:
    """
    Convert Python/OpenSSL exceptions into stable categories.
    """

    message = str(
        exc
    ).strip()

    lower = message.lower()

    result = {
        "violation": "TLS_HANDSHAKE_FAILED",
        "severity": "MEDIUM",
        "error_detail": (
            "TLS handshake failed."
        ),
        "hostname_match": None,
        "chain_trusted": False,
        "expired": False,
        "self_signed": False,
    }

    verify_code = getattr(
        exc,
        "verify_code",
        None,
    )

    if verify_code == 10:
        result.update(
            {
                "violation": "EXPIRED_CERTIFICATE",
                "severity": "MEDIUM",
                "expired": True,
                "error_detail": (
                    "Certificate has expired."
                ),
            }
        )
        return result

    if verify_code == 9:
        result.update(
            {
                "violation": "EXPIRED_CERTIFICATE",
                "severity": "MEDIUM",
                "expired": True,
                "error_detail": (
                    "Certificate is not yet valid."
                ),
            }
        )
        return result

    if verify_code in {
        18,
        19,
    }:
        result.update(
            {
                "violation": "SELF_SIGNED_CERTIFICATE",
                "severity": "MEDIUM",
                "self_signed": True,
                "error_detail": (
                    "Certificate is self-signed."
                ),
            }
        )
        return result

    if verify_code in {
        20,
        21,
    }:
        result.update(
            {
                "violation": "UNTRUSTED_ISSUER",
                "severity": "MEDIUM",
                "error_detail": (
                    "Certificate chain is not trusted."
                ),
            }
        )
        return result

    if (
        "hostname mismatch" in lower
        or "certificate is not valid for" in lower
        or "doesn't match" in lower
    ):
        result.update(
            {
                "violation": "HOSTNAME_MISMATCH",
                "severity": "HIGH",
                "hostname_match": False,
                "chain_trusted": True,
                "error_detail": (
                    "Hostname does not match the certificate."
                ),
            }
        )
        return result

    if (
        "self signed" in lower
        or "self-signed" in lower
    ):
        result.update(
            {
                "violation": "SELF_SIGNED_CERTIFICATE",
                "severity": "MEDIUM",
                "self_signed": True,
                "error_detail": (
                    "Certificate is self-signed."
                ),
            }
        )
        return result

    if (
        "certificate has expired" in lower
        or "certificate is expired" in lower
        or "not yet valid" in lower
    ):
        result.update(
            {
                "violation": "EXPIRED_CERTIFICATE",
                "severity": "MEDIUM",
                "expired": True,
                "error_detail": (
                    "Certificate is expired or not yet valid."
                ),
            }
        )
        return result

    if (
        "unable to get local issuer" in lower
        or "unable to verify the first certificate" in lower
        or "certificate verify failed" in lower
        or "unable to verify the certificate" in lower
    ):
        result.update(
            {
                "violation": "UNTRUSTED_ISSUER",
                "severity": "MEDIUM",
                "error_detail": (
                    "Certificate chain is not trusted."
                ),
            }
        )
        return result

    if (
        "certificate revoked" in lower
        or "certificate is revoked" in lower
    ):
        result.update(
            {
                "violation": "CERTIFICATE_INVALID",
                "severity": "HIGH",
                "error_detail": (
                    "Certificate was rejected because it is revoked."
                ),
            }
        )
        return result

    if isinstance(
        exc,
        ssl.SSLCertVerificationError,
    ):
        result.update(
            {
                "violation": "CERTIFICATE_INVALID",
                "severity": "MEDIUM",
                "error_detail": (
                    "Certificate validation failed."
                ),
            }
        )

    return result


# ============================================================
# TLS inspection
# ============================================================

def _check_tls(
    hostname: str,
    port: int = 443,
    validated_ips: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Validate TLS using the public-IP list already validated by
    DNS inspection.

    Original hostname is retained for SNI and hostname validation.
    """

    result = {
        "https": port == 443,
        "certificate_present": False,
        "certificate_valid": None,
        "hostname_match": None,
        "chain_trusted": None,
        "expired": False,
        "self_signed": False,
        "violation": None,
        "severity": (
            "LOW"
            if port != 443
            else None
        ),
        "issuer": None,
        "subject": None,
        "error_detail": None,
        "tls_version": None,
        "cipher": None,
        "inspection_status": (
            "NOT_APPLICABLE"
            if port != 443
            else "PENDING"
        ),
    }

    if port != 443:
        return result

    if not hostname:
        result.update(
            {
                "inspection_status": "UNAVAILABLE",
                "violation": "TLS_UNAVAILABLE",
                "severity": "MEDIUM",
                "error_detail": (
                    "Hostname is unavailable for TLS inspection."
                ),
            }
        )
        return result

    # --------------------------------------------------------
    # Reject IP literals that are unsafe
    # --------------------------------------------------------

    try:
        ipaddress.ip_address(
            hostname
        )

        if _is_blocked_ip(
            hostname
        ):
            result.update(
                {
                    "inspection_status": "BLOCKED",
                    "violation": "TLS_UNAVAILABLE",
                    "severity": "MEDIUM",
                    "error_detail": (
                        "TLS inspection blocked for non-public destination."
                    ),
                }
            )
            return result

    except ValueError:
        pass

    candidates = []

    for ip_value in (
        validated_ips or []
    ):
        if not ip_value:
            continue

        if _is_blocked_ip(
            ip_value
        ):
            continue

        if ip_value not in candidates:
            candidates.append(
                ip_value
            )

    if not candidates:
        result.update(
            {
                "inspection_status": "UNAVAILABLE",
                "violation": "TLS_UNAVAILABLE",
                "severity": "MEDIUM",
                "error_detail": (
                    "No validated public IP address is available "
                    "for TLS inspection."
                ),
            }
        )
        return result

    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
    except Exception:
        result.update(
            {
                "inspection_status": "UNAVAILABLE",
                "violation": "TLS_UNAVAILABLE",
                "severity": "MEDIUM",
                "error_detail": (
                    "Unable to create a secure TLS context."
                ),
            }
        )
        return result

    last_error = None

    for ip_value in candidates:
        try:
            with socket.create_connection(
                (
                    ip_value,
                    port,
                ),
                timeout=5,
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=hostname,
                ) as ssock:

                    cert = (
                        ssock.getpeercert()
                    )

                    metadata = (
                        _extract_certificate_metadata(
                            cert
                        )
                    )

                    cipher_info = ssock.cipher()

                    result.update(
                        {
                            "certificate_present": True,
                            "certificate_valid": True,
                            "hostname_match": True,
                            "chain_trusted": True,
                            "expired": False,
                            "self_signed": False,
                            "violation": None,
                            "severity": None,
                            "issuer": metadata.get(
                                "issuer"
                            ),
                            "subject": metadata.get(
                                "subject"
                            ),
                            "error_detail": None,
                            "tls_version": ssock.version(),
                            "cipher": (
                                cipher_info[0]
                                if cipher_info
                                else None
                            ),
                            "inspection_status": "VALID",
                        }
                    )

                    return result

        except ssl.SSLCertVerificationError as exc:
            result.update(
                {
                    "certificate_present": True,
                    "certificate_valid": False,
                    "inspection_status": "POLICY_VIOLATION",
                    **_normalize_tls_error(
                        exc
                    ),
                }
            )
            return result

        except ssl.CertificateError:
            result.update(
                {
                    "certificate_present": True,
                    "certificate_valid": False,
                    "hostname_match": False,
                    "chain_trusted": True,
                    "inspection_status": "POLICY_VIOLATION",
                    "violation": "HOSTNAME_MISMATCH",
                    "severity": "HIGH",
                    "error_detail": (
                        "Hostname does not match the certificate."
                    ),
                }
            )
            return result

        except socket.timeout as exc:
            last_error = exc
            continue

        except ConnectionRefusedError as exc:
            last_error = exc
            continue

        except ssl.SSLError as exc:
            last_error = exc

            normalized = _normalize_tls_error(
                exc
            )

            result.update(
                {
                    "certificate_present": False,
                    "certificate_valid": None,
                    "inspection_status": "HANDSHAKE_FAILED",
                    **normalized,
                }
            )

            if result.get(
                "violation"
            ) in {
                "CERTIFICATE_INVALID",
                "EXPIRED_CERTIFICATE",
                "SELF_SIGNED_CERTIFICATE",
                "UNTRUSTED_ISSUER",
                "HOSTNAME_MISMATCH",
            }:
                return result

            result.update(
                {
                    "violation": "TLS_HANDSHAKE_FAILED",
                    "severity": "MEDIUM",
                    "error_detail": (
                        "TLS handshake failed."
                    ),
                }
            )
            return result

        except OSError as exc:
            last_error = exc
            continue

        except Exception as exc:
            last_error = exc
            continue

    if isinstance(
        last_error,
        socket.timeout,
    ):
        result.update(
            {
                "inspection_status": "TIMEOUT",
                "violation": "TLS_UNAVAILABLE",
                "severity": "MEDIUM",
                "error_detail": (
                    "TLS connection timed out."
                ),
            }
        )

    elif isinstance(
        last_error,
        ConnectionRefusedError,
    ):
        result.update(
            {
                "inspection_status": "UNAVAILABLE",
                "violation": "TLS_UNAVAILABLE",
                "severity": "MEDIUM",
                "error_detail": (
                    "TLS connection was refused."
                ),
            }
        )

    elif last_error is not None:
        result.update(
            {
                "inspection_status": "UNAVAILABLE",
                "violation": "TLS_UNAVAILABLE",
                "severity": "MEDIUM",
                "error_detail": (
                    "TLS connection is unavailable."
                ),
            }
        )

    else:
        result.update(
            {
                "inspection_status": "UNAVAILABLE",
                "violation": "TLS_UNAVAILABLE",
                "severity": "MEDIUM",
                "error_detail": (
                    "TLS inspection could not be completed."
                ),
            }
        )

    return result


# ============================================================
# URL Inspection Service
# ============================================================

class URLInspectionService:
    """
    URL inspection orchestration service.

    Synchronous:
        inspect()

    Asynchronous:
        inspect_urls()

    Security model:
        - DNS results are validated before network connections.
        - Private/internal destinations are blocked.
        - TLS connects only to previously validated public IPs.
        - Original hostname is retained for TLS SNI verification.
        - Deep page execution stays inside URLWorker.
    """

    MAX_URLS_PER_EMAIL = 50
    MAX_CONCURRENT_INSPECTIONS = 3
    INSPECTION_TIMEOUT = 10
    WORKER_IDLE_SLEEP = 0.10
    SOCKET_TIMEOUT = 5

    # Regression compatibility / security limits.
    max_redirects = 10
    DEFAULT_TIMEOUT = 5

    SENSITIVE_QUERY_KEYS = {
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "auth",
        "authorization",
        "apikey",
        "api_key",
        "key",
        "secret",
        "password",
        "passwd",
        "pass",
        "pwd",
        "session",
        "sessionid",
        "session_id",
        "sid",
        "code",
        "oauth",
        "oauth_token",
        "jwt",
        "signature",
        "sig",
        "credential",
        "credentials",
        "email",
        "username",
        "user",
        "reset_token",
        "verification_token",
        "invite_token",
    }

    _worker_threads: List[
        threading.Thread
    ] = []

    _stop_event = threading.Event()
    _worker_lock = threading.Lock()

    # ========================================================
    # Compatibility properties
    # ========================================================

    @property
    def timeout(
        self,
    ) -> int:
        return int(
            self.DEFAULT_TIMEOUT
        )

    @timeout.setter
    def timeout(
        self,
        value: int,
    ) -> None:
        try:
            value = int(
                value
            )
        except (
            TypeError,
            ValueError,
        ):
            value = 5

        self.DEFAULT_TIMEOUT = max(
            1,
            min(
                value,
                60,
            ),
        )

    @property
    def redirect_hop_limit(
        self,
    ) -> int:
        return int(
            self.max_redirects
        )

    @redirect_hop_limit.setter
    def redirect_hop_limit(
        self,
        value: int,
    ) -> None:
        try:
            value = int(
                value
            )
        except (
            TypeError,
            ValueError,
        ):
            value = 10

        self.max_redirects = max(
            1,
            min(
                value,
                10,
            ),
        )

    # ========================================================
    # SSRF compatibility helpers
    # ========================================================

    @staticmethod
    def is_safe_ip(
        ip: str,
    ) -> bool:
        """
        True only for publicly routable IP addresses.
        """

        if not ip:
            return False

        try:
            return not _is_blocked_ip(
                str(
                    ip
                ).strip()
            )
        except Exception:
            return False

    @staticmethod
    def is_safe_hostname(
        hostname: str,
    ) -> bool:
        """
        Resolve a hostname and return True only when it has at least
        one validated public destination and no blocked/private result.
        """

        if not hostname:
            return False

        hostname = (
            str(
                hostname
            )
            .strip()
            .rstrip(".")
        )

        try:
            ipaddress.ip_address(
                hostname
            )

            return URLInspectionService.is_safe_ip(
                hostname
            )

        except ValueError:
            pass

        dns = _resolve_dns(
            hostname
        )

        if dns.get(
            "blocked_ip_detected"
        ):
            return False

        return bool(
            dns.get(
                "validated_ips",
                [],
            )
        )

    # ========================================================
    # Cache key normalization
    # ========================================================

    def _get_cache_key(
        self,
        parsed_url,
    ) -> Optional[str]:
        """
        Build a normalized cache key without exposing sensitive
        query-string values.

        Rules:
        - scheme is lowercase
        - hostname is lowercase
        - trailing hostname dot is removed
        - default ports are removed
        - non-default ports are preserved
        - path is normalized
        - fragments are ignored
        - sensitive query values are replaced with [REDACTED]
        - sensitive values are NEVER stored in the cache key
        """

        if parsed_url is None:
            return None

        try:
            scheme = (
                str(
                    getattr(
                        parsed_url,
                        "scheme",
                        "",
                    )
                    or ""
                )
                .strip()
                .lower()
            )

            hostname = (
                str(
                    getattr(
                        parsed_url,
                        "hostname",
                        "",
                    )
                    or ""
                )
                .strip()
                .lower()
                .rstrip(".")
            )

            if not scheme or not hostname:
                return None

            if scheme not in {
                "http",
                "https",
            }:
                return None

            # ------------------------------------------------
            # Port normalization
            # ------------------------------------------------

            try:
                port = parsed_url.port
            except ValueError:
                return None

            if (
                port is None
                or (
                    scheme == "http"
                    and port == 80
                )
                or (
                    scheme == "https"
                    and port == 443
                )
            ):
                port_part = ""
            else:
                port_part = f":{port}"

            # ------------------------------------------------
            # Query normalization
            # ------------------------------------------------

            raw_query = (
                getattr(
                    parsed_url,
                    "query",
                    "",
                )
                or ""
            ).strip()

            normalized_query = ""

            if raw_query:

                try:
                    query_pairs = parse_qsl(
                        raw_query,
                        keep_blank_values=True,
                    )
                except Exception:
                    return None

                normalized_pairs = []

                for key, value in query_pairs:

                    normalized_key = (
                        str(
                            key
                            or ""
                        )
                        .strip()
                        .lower()
                    )

                    if not normalized_key:
                        continue

                    # ------------------------------------------------
                    # Sensitive query values are redacted, not stored.
                    #
                    # Example:
                    #
                    # ?token=VERY_SECRET
                    #
                    # becomes:
                    #
                    # ?token=%5BREDACTED%5D
                    # ------------------------------------------------

                    is_sensitive = (
                        normalized_key
                        in self.SENSITIVE_QUERY_KEYS
                    )

                    if not is_sensitive:
                        is_sensitive = any(
                            marker in normalized_key
                            for marker in (
                                "token",
                                "secret",
                                "password",
                                "passwd",
                                "session",
                                "credential",
                                "authorization",
                                "signature",
                                "apikey",
                                "api_key",
                            )
                        )

                    if is_sensitive:
                        normalized_value = "[REDACTED]"
                    else:
                        normalized_value = str(
                            value
                            or ""
                        )

                    normalized_pairs.append(
                        (
                            normalized_key,
                            normalized_value,
                        )
                    )

                if normalized_pairs:
                    normalized_query = (
                        "?"
                        + urlencode(
                            sorted(
                                normalized_pairs
                            ),
                            doseq=True,
                        )
                    )

            # ------------------------------------------------
            # Path normalization
            # ------------------------------------------------

            path = (
                getattr(
                    parsed_url,
                    "path",
                    "",
                )
                or "/"
            )

            if not path.startswith(
                "/"
            ):
                path = (
                    "/"
                    + path
                )

            if (
                path != "/"
                and path.endswith("/")
            ):
                path = path.rstrip(
                    "/"
                )

            # ------------------------------------------------
            # Fragment intentionally excluded.
            # ------------------------------------------------

            return (
                f"{scheme}://"
                f"{hostname}"
                f"{port_part}"
                f"{path}"
                f"{normalized_query}"
            )

        except Exception:
            return None

    # ========================================================
    # Synchronous URL inspection
    # ========================================================

    def inspect(
        self,
        url: str,
    ) -> Dict[str, Any]:
        """
        Perform DNS + TLS inspection for one URL.
        """

        normalized_url = self._normalize_url(
            url
        )

        try:
            parsed = urlparse(
                normalized_url
            )

            scheme = (
                parsed.scheme.lower()
            )

            hostname = (
                parsed.hostname
                or ""
            ).lower().rstrip(".")

            if scheme not in {
                "http",
                "https",
            }:
                return self._blocked_result(
                    normalized_url,
                    "Unsupported URL scheme.",
                    hostname=hostname,
                )

            if not hostname:
                return self._blocked_result(
                    normalized_url,
                    "URL hostname is missing.",
                )

            # ------------------------------------------------
            # IP literal destination
            # ------------------------------------------------

            try:
                ipaddress.ip_address(
                    hostname
                )

                if _is_blocked_ip(
                    hostname
                ):
                    return self._blocked_result(
                        normalized_url,
                        (
                            "Inspection blocked for a "
                            "non-public IP destination."
                        ),
                        hostname=hostname,
                    )

                validated_ips = [
                    hostname
                ]

                dns = {
                    "resolved": True,
                    "a": (
                        [hostname]
                        if isinstance(
                            ipaddress.ip_address(
                                hostname
                            ),
                            ipaddress.IPv4Address,
                        )
                        else []
                    ),
                    "aaaa": (
                        [hostname]
                        if isinstance(
                            ipaddress.ip_address(
                                hostname
                            ),
                            ipaddress.IPv6Address,
                        )
                        else []
                    ),
                    "private_ip_detected": False,
                    "blocked_ip_detected": False,
                    "validated_ips": validated_ips,
                    "error": None,
                }

            except ValueError:
                # ------------------------------------------------
                # Hostname -> DNS
                # ------------------------------------------------

                dns = _resolve_dns(
                    hostname
                )

                if dns.get(
                    "blocked_ip_detected"
                ):
                    return {
                        "url": normalized_url,
                        "domain": hostname,
                        "registered_domain": (
                            self._registered_domain(
                                hostname
                            )
                        ),
                        "dns": dns,
                        "tls": {
                            "https": scheme == "https",
                            "certificate_present": False,
                            "certificate_valid": None,
                            "hostname_match": None,
                            "chain_trusted": None,
                            "expired": False,
                            "self_signed": False,
                            "violation": (
                                "TLS_UNAVAILABLE"
                                if scheme == "https"
                                else None
                            ),
                            "severity": (
                                "MEDIUM"
                                if scheme == "https"
                                else "LOW"
                            ),
                            "issuer": None,
                            "subject": None,
                            "error_detail": (
                                "Inspection blocked because the "
                                "hostname resolved to a non-public address."
                            ),
                            "inspection_status": "BLOCKED",
                        },
                        "redirects": (
                            self._empty_redirects()
                        ),
                        "threat_intelligence": (
                            self._empty_threat_intelligence()
                        ),
                        "security": {
                            "blocked": True,
                            "error": (
                                "SSRF protection blocked "
                                "the resolved destination."
                            ),
                        },
                        "structured_evidence": [
                            self._evidence(
                                type_="PRIVATE_IP_DESTINATION",
                                severity="CRITICAL",
                                direction="NEGATIVE",
                                source="URLInspectionService",
                                explanation=(
                                    "Hostname resolved to a non-public "
                                    "destination and inspection was blocked."
                                ),
                                confidence=1.0,
                            )
                        ],
                    }

                validated_ips = (
                    dns.get(
                        "validated_ips",
                        [],
                    )
                    or []
                )

            # ------------------------------------------------
            # No public destination
            # ------------------------------------------------

            if not validated_ips:
                tls = {
                    "https": scheme == "https",
                    "certificate_present": False,
                    "certificate_valid": None,
                    "hostname_match": None,
                    "chain_trusted": None,
                    "expired": False,
                    "self_signed": False,
                    "violation": (
                        "TLS_UNAVAILABLE"
                        if scheme == "https"
                        else None
                    ),
                    "severity": (
                        "MEDIUM"
                        if scheme == "https"
                        else "LOW"
                    ),
                    "issuer": None,
                    "subject": None,
                    "error_detail": (
                        dns.get(
                            "error"
                        )
                        or "DNS resolution unavailable."
                    ),
                    "inspection_status": (
                        "UNAVAILABLE"
                        if scheme == "https"
                        else "NOT_APPLICABLE"
                    ),
                }

                return {
                    "url": normalized_url,
                    "domain": hostname,
                    "registered_domain": (
                        self._registered_domain(
                            hostname
                        )
                    ),
                    "dns": dns,
                    "tls": tls,
                    "redirects": (
                        self._empty_redirects()
                    ),
                    "threat_intelligence": (
                        self._empty_threat_intelligence()
                    ),
                    "security": {
                        "blocked": False,
                        "error": None,
                    },
                    "structured_evidence": [],
                }

            # ------------------------------------------------
            # Determine port
            # ------------------------------------------------

            port = (
                parsed.port
                or (
                    443
                    if scheme == "https"
                    else 80
                )
            )

            # ------------------------------------------------
            # TLS inspection
            # ------------------------------------------------

            if scheme == "https":
                tls = _check_tls(
                    hostname=hostname,
                    port=port,
                    validated_ips=validated_ips,
                )
            else:
                tls = {
                    "https": False,
                    "certificate_present": False,
                    "certificate_valid": None,
                    "hostname_match": None,
                    "chain_trusted": None,
                    "expired": False,
                    "self_signed": False,
                    "violation": None,
                    "severity": "LOW",
                    "issuer": None,
                    "subject": None,
                    "error_detail": None,
                    "inspection_status": "NOT_APPLICABLE",
                    "tls_version": None,
                    "cipher": None,
                }

            registered_domain = (
                self._registered_domain(
                    hostname
                )
            )

            structured_evidence = []

            violation = str(
                tls.get(
                    "violation",
                    "",
                )
                or ""
            ).upper()

            if violation in {
                "EXPIRED_CERTIFICATE",
                "HOSTNAME_MISMATCH",
                "SELF_SIGNED_CERTIFICATE",
                "UNTRUSTED_ISSUER",
                "CERTIFICATE_INVALID",
            }:
                structured_evidence.append(
                    self._evidence(
                        type_="TLS_POLICY_VIOLATION",
                        severity=str(
                            tls.get(
                                "severity",
                                "MEDIUM",
                            )
                        ).upper(),
                        direction="NEGATIVE",
                        source="TLSInspector",
                        explanation=(
                            tls.get(
                                "error_detail",
                                violation,
                            )
                        ),
                        confidence=0.90,
                    )
                )

            elif violation in {
                "TLS_HANDSHAKE_FAILED",
                "TLS_UNAVAILABLE",
            }:
                structured_evidence.append(
                    self._evidence(
                        type_="TLS_INSPECTION_UNAVAILABLE",
                        severity="INFO",
                        direction="NEUTRAL",
                        source="TLSInspector",
                        explanation=(
                            tls.get(
                                "error_detail",
                                "TLS inspection could not be completed.",
                            )
                        ),
                        confidence=0.0,
                    )
                )

            elif tls.get(
                "certificate_valid"
            ) is True:
                structured_evidence.append(
                    self._evidence(
                        type_="VALID_TLS",
                        severity="INFO",
                        direction="POSITIVE",
                        source="TLSInspector",
                        explanation=(
                            "TLS certificate validation succeeded."
                        ),
                        confidence=0.96,
                    )
                )

            if scheme == "http":
                structured_evidence.append(
                    self._evidence(
                        type_="HTTP_POLICY_WARNING",
                        severity="LOW",
                        direction="NEGATIVE",
                        source="TLSInspector",
                        explanation=(
                            "URL uses plain HTTP without TLS."
                        ),
                        confidence=0.95,
                    )
                )

            return {
                "url": normalized_url,
                "domain": hostname,
                "registered_domain": registered_domain,
                "dns": dns,
                "tls": tls,
                "redirects": (
                    self._empty_redirects()
                ),
                "threat_intelligence": (
                    self._empty_threat_intelligence()
                ),
                "security": {
                    "blocked": False,
                    "error": None,
                },
                "structured_evidence": (
                    structured_evidence
                ),
            }

        except ValueError as exc:

            logger.warning(
                "Invalid URL inspected: %s",
                normalized_url,
            )

            return self._blocked_result(
                normalized_url,
                "Invalid URL.",
                detail=str(
                    exc
                ),
            )

        except Exception as exc:

            logger.exception(
                "URLInspectionService.inspect() failed for %s",
                normalized_url,
            )

            return {
                "url": normalized_url,
                "domain": "",
                "registered_domain": "",
                "dns": {
                    "resolved": False,
                    "a": [],
                    "aaaa": [],
                    "private_ip_detected": False,
                    "blocked_ip_detected": False,
                    "validated_ips": [],
                    "error": (
                        "URL inspection unavailable."
                    ),
                    "error_detail": str(
                        exc
                    ),
                },
                "tls": {
                    "https": False,
                    "certificate_present": False,
                    "certificate_valid": None,
                    "hostname_match": None,
                    "chain_trusted": None,
                    "expired": False,
                    "self_signed": False,
                    "violation": (
                        "TLS_UNAVAILABLE"
                    ),
                    "severity": "MEDIUM",
                    "issuer": None,
                    "subject": None,
                    "error_detail": (
                        "URL inspection unavailable."
                    ),
                    "inspection_status": "UNAVAILABLE",
                },
                "redirects": (
                    self._empty_redirects()
                ),
                "threat_intelligence": (
                    self._empty_threat_intelligence()
                ),
                "security": {
                    "blocked": False,
                    "error": (
                        "URL inspection unavailable."
                    ),
                    "error_detail": str(
                        exc
                    ),
                },
                "structured_evidence": [],
            }

    # ========================================================
    # Background workers
    # ========================================================

    @classmethod
    def start_local_worker(
        cls,
    ) -> None:

        with cls._worker_lock:

            cls._worker_threads = [
                thread
                for thread in cls._worker_threads
                if thread.is_alive()
            ]

            required = max(
                1,
                int(
                    cls.MAX_CONCURRENT_INSPECTIONS
                ),
            )

            if len(
                cls._worker_threads
            ) >= required:
                return

            cls._stop_event.clear()

            while len(
                cls._worker_threads
            ) < required:

                index = len(
                    cls._worker_threads
                )

                thread = threading.Thread(
                    target=cls._worker_loop,
                    name=(
                        f"tunamail-url-worker-{index + 1}"
                    ),
                    daemon=True,
                )

                cls._worker_threads.append(
                    thread
                )

                thread.start()

            logger.info(
                "Started %s local URL worker(s).",
                len(
                    cls._worker_threads
                ),
            )

    @classmethod
    def stop_local_worker(
        cls,
    ) -> None:

        cls._stop_event.set()

        with cls._worker_lock:
            cls._worker_threads = []

    @classmethod
    def _worker_loop(
        cls,
    ) -> None:

        while not cls._stop_event.is_set():

            try:
                job = url_queue.dequeue()
            except Exception:
                logger.exception(
                    "URL queue dequeue failed."
                )
                time.sleep(
                    cls.WORKER_IDLE_SLEEP
                )
                continue

            if not job:
                time.sleep(
                    cls.WORKER_IDLE_SLEEP
                )
                continue

            try:
                url_queue.update_job(
                    job.job_id,
                    "RUNNING",
                )
            except Exception:
                logger.exception(
                    "Could not mark URL job as RUNNING."
                )

            try:

                result = URLWorker.inspect(
                    job.url
                )

                if result is None:
                    result = {
                        "security": {
                            "error": (
                                "Worker returned no result."
                            )
                        }
                    }

                security = (
                    result.get(
                        "security",
                        {},
                    )
                    or {}
                )

                if security.get(
                    "blocked"
                ):
                    url_queue.update_job(
                        job.job_id,
                        "BLOCKED",
                        result=result,
                        error=security.get(
                            "error"
                        ),
                    )

                elif security.get(
                    "error"
                ):
                    url_queue.update_job(
                        job.job_id,
                        "FAILED",
                        result=result,
                        error=security.get(
                            "error"
                        ),
                    )

                else:

                    url_queue.update_job(
                        job.job_id,
                        "COMPLETED",
                        result=result,
                    )

                    try:
                        page_cache.set(
                            job.url,
                            result,
                        )
                    except Exception:
                        logger.exception(
                            "Failed to cache page intelligence for %s",
                            job.url,
                        )

            except Exception as exc:

                logger.exception(
                    "URL worker failed on %s",
                    job.url,
                )

                try:
                    url_queue.update_job(
                        job.job_id,
                        "FAILED",
                        error=str(
                            exc
                        ),
                    )
                except Exception:
                    logger.exception(
                        "Could not mark URL job as FAILED."
                    )

    # ========================================================
    # Batch page inspection
    # ========================================================

    @classmethod
    def inspect_urls(
        cls,
        urls: List[str],
        message_id: str,
        user_id: str = "system",
    ) -> Dict[str, Any]:
        """
        Queue deeper page inspections and wait for results up to
        INSPECTION_TIMEOUT.
        """

        cls.start_local_worker()

        results: Dict[str, Any] = {}

        if not urls:
            return results

        unique_urls = []
        seen = set()

        for url in urls:

            normalized = cls._normalize_url(
                url
            )

            if not normalized:
                continue

            key = normalized.lower()

            if key in seen:
                continue

            seen.add(
                key
            )

            unique_urls.append(
                normalized
            )

            if (
                len(
                    unique_urls
                )
                >= cls.MAX_URLS_PER_EMAIL
            ):
                break

        jobs_to_wait = []

        for url in unique_urls:

            try:
                cached = page_cache.get(
                    url
                )
            except Exception:
                logger.exception(
                    "Page cache lookup failed for %s",
                    url,
                )
                cached = None

            if cached:
                results[url] = cached
                continue

            try:
                job = URLInspectionJob(
                    message_id=message_id,
                    url=url,
                    user_id=user_id,
                )

                url_queue.enqueue(
                    job
                )

                jobs_to_wait.append(
                    job
                )

            except Exception as exc:

                logger.exception(
                    "Could not enqueue URL inspection job for %s",
                    url,
                )

                results[url] = {
                    "security": {
                        "error": (
                            "URL inspection could not be queued."
                        ),
                        "error_detail": str(
                            exc
                        ),
                    }
                }

        start_time = time.monotonic()

        while (
            jobs_to_wait
            and (
                time.monotonic()
                - start_time
                < cls.INSPECTION_TIMEOUT
            )
        ):

            remaining = []

            for job in jobs_to_wait:

                try:
                    updated_job = (
                        url_queue.get_job(
                            job.job_id
                        )
                    )
                except Exception as exc:

                    logger.exception(
                        "Could not retrieve URL job %s",
                        job.job_id,
                    )

                    results[job.url] = {
                        "security": {
                            "error": (
                                "Unable to retrieve inspection job status."
                            ),
                            "error_detail": str(
                                exc
                            ),
                        }
                    }

                    continue

                if updated_job is None:
                    remaining.append(
                        job
                    )
                    continue

                status = str(
                    getattr(
                        updated_job,
                        "status",
                        "",
                    )
                ).upper()

                if status == "COMPLETED":

                    result = getattr(
                        updated_job,
                        "result",
                        None,
                    )

                    results[job.url] = (
                        result
                        if isinstance(
                            result,
                            dict,
                        )
                        else {
                            "security": {
                                "error": (
                                    "Inspection completed "
                                    "without a result."
                                )
                            }
                        }
                    )

                elif status == "BLOCKED":

                    results[job.url] = {
                        "security": {
                            "error": (
                                getattr(
                                    updated_job,
                                    "error",
                                    None,
                                )
                                or "INSPECTION_BLOCKED"
                            ),
                            "blocked": True,
                        }
                    }

                elif status == "FAILED":

                    result = getattr(
                        updated_job,
                        "result",
                        None,
                    )

                    results[job.url] = (
                        result
                        if isinstance(
                            result,
                            dict,
                        )
                        else {
                            "security": {
                                "error": (
                                    getattr(
                                        updated_job,
                                        "error",
                                        None,
                                    )
                                    or "INSPECTION_FAILED"
                                )
                            }
                        }
                    )

                elif status == "TIMEOUT":

                    results[job.url] = {
                        "security": {
                            "error": "INSPECTION_TIMEOUT",
                            "blocked": False,
                        }
                    }

                else:
                    remaining.append(
                        job
                    )

            jobs_to_wait = remaining

            if jobs_to_wait:
                time.sleep(
                    0.20
                )

        for job in jobs_to_wait:

            try:
                url_queue.update_job(
                    job.job_id,
                    "TIMEOUT",
                    error="INSPECTION_TIMEOUT",
                )
            except Exception:
                logger.exception(
                    "Could not mark URL job as TIMEOUT."
                )

            results[job.url] = {
                "security": {
                    "error": "INSPECTION_TIMEOUT",
                    "blocked": False,
                }
            }

        return results

    # ========================================================
    # Result helpers
    # ========================================================

    @classmethod
    def _blocked_result(
        cls,
        url: str,
        error: str,
        hostname: str = "",
        detail: str | None = None,
    ) -> Dict[str, Any]:

        return {
            "url": url,
            "domain": hostname,
            "registered_domain": (
                cls._registered_domain(
                    hostname
                )
                if hostname
                else ""
            ),
            "dns": {
                "resolved": False,
                "a": [],
                "aaaa": [],
                "private_ip_detected": True,
                "blocked_ip_detected": True,
                "validated_ips": [],
                "error": error,
            },
            "tls": {
                "https": (
                    urlparse(
                        url
                    ).scheme.lower()
                    == "https"
                ),
                "certificate_present": False,
                "certificate_valid": None,
                "hostname_match": None,
                "chain_trusted": None,
                "expired": False,
                "self_signed": False,
                "violation": (
                    "TLS_UNAVAILABLE"
                ),
                "severity": "MEDIUM",
                "issuer": None,
                "subject": None,
                "error_detail": error,
                "inspection_status": "BLOCKED",
            },
            "redirects": (
                cls._empty_redirects()
            ),
            "threat_intelligence": (
                cls._empty_threat_intelligence()
            ),
            "security": {
                "blocked": True,
                "error": error,
                "error_detail": detail,
            },
            "structured_evidence": [
                cls._evidence(
                    type_="PRIVATE_IP_DESTINATION",
                    severity="CRITICAL",
                    direction="NEGATIVE",
                    source="URLInspectionService",
                    explanation=error,
                    confidence=1.0,
                )
            ],
        }

    @staticmethod
    def _empty_redirects() -> Dict[str, Any]:
        return {
            "detected": False,
            "chain": [],
            "external_domain_change": False,
        }

    @staticmethod
    def _empty_threat_intelligence() -> Dict[str, Any]:
        return {
            "status": "not_checked",
            "detections": 0,
            "engines": [],
            "available": False,
            "reason": "No external threat-intelligence provider was queried.",
        }

    @staticmethod
    def _normalize_url(
        url: Any,
    ) -> str:
        return (
            str(
                url
                or ""
            )
            .strip()
            .rstrip(
                ".,;:!?)]}>\"'"
            )
        )

    @staticmethod
    def _registered_domain(
        hostname: str,
    ) -> str:

        if not hostname:
            return ""

        try:
            ipaddress.ip_address(
                hostname
            )
            return hostname

        except ValueError:
            pass

        try:
            extracted = tldextract.extract(
                hostname
            )

            return (
                extracted.registered_domain
                or hostname
            )

        except Exception:
            return hostname

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
            "severity": (
                str(
                    severity
                    or "INFO"
                ).upper()
            ),
            "direction": (
                str(
                    direction
                    or "NEUTRAL"
                ).upper()
            ),
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