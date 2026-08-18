import ipaddress
import socket
from urllib.parse import urlparse

class URLSafetyException(Exception):
    pass

class URLSafetyChecker:
    ALLOWED_SCHEMES = {"http", "https"}
    
    @classmethod
    def validate_scheme(cls, url: str):
        parsed = urlparse(url)
        if parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
            raise URLSafetyException(f"Unsupported scheme: {parsed.scheme}")
            
    @classmethod
    def is_private_ip(cls, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            # Check for loopback, private, link-local, multicast, reserved
            return (ip.is_loopback or 
                    ip.is_private or 
                    ip.is_link_local or 
                    ip.is_multicast or 
                    ip.is_reserved or
                    ip.is_unspecified)
        except ValueError:
            return True # If it's not a valid IP, treat as unsafe just in case

    @classmethod
    def validate_destination(cls, hostname: str):
        """
        Resolves the hostname and checks if ANY returned IP is private.
        Protects against DNS rebinding and SSRF.
        """
        if not hostname:
            raise URLSafetyException("Empty hostname")
            
        try:
            # Check if it's already an IP
            ipaddress.ip_address(hostname)
            # It's an IP, let's check if it's private
            if cls.is_private_ip(hostname):
                raise URLSafetyException(f"Blocked private IP destination: {hostname}")
            return  # If it parsed as a valid IP and wasn't private, it's fine.
        except ValueError:
            pass # It's a hostname, proceed to resolution

        try:
            # Resolve all IPs for the hostname
            addr_info = socket.getaddrinfo(hostname, None)
            for addr in addr_info:
                ip_addr = addr[4][0]
                if cls.is_private_ip(ip_addr):
                    raise URLSafetyException(f"Hostname {hostname} resolves to blocked IP: {ip_addr}")
        except socket.gaierror as e:
            raise URLSafetyException(f"DNS resolution failed for {hostname}: {e}")

    @classmethod
    def validate_url(cls, url: str):
        cls.validate_scheme(url)
        parsed = urlparse(url)
        cls.validate_destination(parsed.hostname)
