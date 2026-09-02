import ipaddress
import socket
from urllib.parse import urlparse


class URLSafetyException(Exception):
    pass


class URLSafetyChecker:
    ALLOWED_SCHEMES = {"http", "https", "data", "blob"}

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

    @classmethod
    def validate_scheme(cls, url: str) -> None:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
            raise URLSafetyException(
                f"Unsupported scheme: {parsed.scheme}"
            )

    @classmethod
    def is_private_ip(cls, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(
                str(ip_str).strip()
            )
        except ValueError:
            return True

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return True

        for network in cls.BLOCKED_NETWORKS:
            if ip in network:
                return True

        return False

    @classmethod
    def validate_destination(cls, hostname: str) -> None:
        if not hostname:
            raise URLSafetyException(
                "Empty hostname"
            )

        hostname = (
            str(hostname)
            .strip()
            .rstrip(".")
        )

        if not hostname:
            raise URLSafetyException(
                "Empty hostname"
            )

        # ----------------------------------------------------
        # Direct IP literal
        # ----------------------------------------------------

        try:
            ip = ipaddress.ip_address(
                hostname
            )

            if cls.is_private_ip(
                str(ip)
            ):
                raise URLSafetyException(
                    f"Blocked non-public IP destination: {hostname}"
                )

            return

        except ValueError:
            pass

        # ----------------------------------------------------
        # Hostname validation
        # ----------------------------------------------------

        try:
            addr_info = socket.getaddrinfo(
                hostname,
                None,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise URLSafetyException(
                f"DNS resolution failed for {hostname}: {exc}"
            ) from exc
        except socket.timeout as exc:
            raise URLSafetyException(
                f"DNS resolution timed out for {hostname}"
            ) from exc

        if not addr_info:
            raise URLSafetyException(
                f"Hostname {hostname} resolved to no addresses"
            )

        seen_ips = set()
        public_ip_found = False

        for addr in addr_info:
            if len(addr) < 5:
                continue

            ip_addr = addr[4][0]

            if not ip_addr:
                continue

            if ip_addr in seen_ips:
                continue

            seen_ips.add(
                ip_addr
            )

            try:
                ipaddress.ip_address(
                    ip_addr
                )
            except ValueError as exc:
                raise URLSafetyException(
                    f"Invalid DNS address returned for {hostname}: {ip_addr}"
                ) from exc

            if cls.is_private_ip(
                ip_addr
            ):
                raise URLSafetyException(
                    f"Hostname {hostname} resolves to blocked IP: {ip_addr}"
                )

            public_ip_found = True

        if not public_ip_found:
            raise URLSafetyException(
                f"Hostname {hostname} has no validated public destination"
            )

    @classmethod
    def validate_url(cls, url: str) -> None:
        if not url or not str(url).strip():
            raise URLSafetyException(
                "URL is empty"
            )

        cls.validate_scheme(
            url
        )

        parsed = urlparse(
            url
        )

        if parsed.scheme.lower() in {"data", "blob"}:
            return

        if not parsed.hostname:
            raise URLSafetyException(
                "URL hostname is missing"
            )

        cls.validate_destination(
            parsed.hostname
        )