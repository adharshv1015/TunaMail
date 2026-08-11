import re
import socket
import ssl
import ipaddress
import requests
from requests.exceptions import RequestException
import dns.resolver
from urllib.parse import urlparse
import tldextract
from datetime import datetime, timezone

class URLInspectionService:
    def __init__(self):
        self.timeout = 3.0
        self.max_redirects = 5

    def is_safe_ip(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            # Block all loopback, private, link-local, multicast, and reserved ranges
            if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
                return False
            # Block IPv4-mapped IPv6
            if ip.version == 6 and ip.ipv4_mapped:
                return self.is_safe_ip(str(ip.ipv4_mapped))
            return True
        except ValueError:
            return False

    def is_safe_hostname(self, hostname):
        if not hostname:
            return False
            
        hostname = hostname.lower()
        if hostname in ("localhost", "localhost.localdomain", "broadcasthost"):
            return False
            
        # If it's literally an IP address representation, check it
        try:
            ipaddress.ip_address(hostname)
            return self.is_safe_ip(hostname)
        except ValueError:
            pass

        return True

    def _resolve_dns(self, hostname, record_type):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            answers = resolver.resolve(hostname, record_type)
            return [rdata.to_text() for rdata in answers]
        except Exception:
            return []

    def inspect(self, url_string):
        parsed = urlparse(url_string)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        
        result = {
            "url": url_string,
            "normalized_url": parsed.geturl(),
            "domain": hostname,
            "registered_domain": None,
            "dns": {
                "a": [],
                "aaaa": [],
                "mx": [],
                "ns": [],
                "resolved": False,
                "private_ip_detected": False,
                "status": "unavailable"
            },
            "tls": {
                "https": parsed.scheme == "https",
                "certificate_valid": False,
                "hostname_match": False,
                "expired": False,
                "issuer": None,
                "status": "unavailable"
            },
            "http": {
                "status_code": None,
                "final_url": None,
                "content_type": None,
                "reachable": False
            },
            "redirects": {
                "detected": False,
                "chain": [],
                "external_domain_change": False
            },
            "threat_intelligence": {
                "status": "unavailable",
                "detections": 0,
                "providers": []
            }
        }

        if not hostname or not self.is_safe_hostname(hostname):
            result["dns"]["private_ip_detected"] = True
            return result

        # 1. Registered Domain (Brand analysis support)
        ext = tldextract.extract(hostname)
        if ext.registered_domain:
            result["registered_domain"] = ext.registered_domain
        else:
            result["registered_domain"] = hostname

        # 2. DNS Analysis + SSRF Check
        a_records = self._resolve_dns(hostname, "A")
        aaaa_records = self._resolve_dns(hostname, "AAAA")
        
        result["dns"]["a"] = a_records
        result["dns"]["aaaa"] = aaaa_records
        
        if a_records or aaaa_records:
            result["dns"]["resolved"] = True
            result["dns"]["status"] = "available"
            
            # SSRF check: Verify no IPs point to internal networks
            for ip in a_records + aaaa_records:
                if not self.is_safe_ip(ip):
                    result["dns"]["private_ip_detected"] = True
                    return result
        
        result["dns"]["mx"] = self._resolve_dns(result["registered_domain"], "MX")
        result["dns"]["ns"] = self._resolve_dns(result["registered_domain"], "NS")

        # 3. TLS Analysis
        if result["tls"]["https"]:
            try:
                context = ssl.create_default_context()
                context.check_hostname = True
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        result["tls"]["certificate_valid"] = True
                        result["tls"]["hostname_match"] = True
                        result["tls"]["status"] = "available"
                        
                        # Check Expiration
                        not_after = cert.get("notAfter")
                        if not_after:
                            exp_date = ssl.cert_time_to_seconds(not_after)
                            if datetime.now(timezone.utc).timestamp() > exp_date:
                                result["tls"]["expired"] = True
                                result["tls"]["certificate_valid"] = False

                        # Extract issuer
                        issuer_info = cert.get("issuer", [])
                        for item in issuer_info:
                            for field in item:
                                if field[0] == "organizationName":
                                    result["tls"]["issuer"] = field[1]
                                    break
            except Exception as e:
                result["tls"]["status"] = "failed"
                result["tls"]["certificate_valid"] = False

        # 4. HTTP & Redirect Analysis
        current_url = url_string
        visited = set()
        
        try:
            for hop in range(self.max_redirects):
                visited.add(current_url)
                
                # Double-check SSRF for the current URL before fetching
                parsed_current = urlparse(current_url)
                if not parsed_current.hostname or not self.is_safe_hostname(parsed_current.hostname):
                    break
                    
                cur_a = self._resolve_dns(parsed_current.hostname, "A")
                if cur_a and not self.is_safe_ip(cur_a[0]):
                    break
                    
                # Use HEAD to avoid downloading large bodies
                resp = requests.head(current_url, timeout=self.timeout, allow_redirects=False, headers={'User-Agent': 'TunaMail-Security-Bot/1.0'})
                
                result["http"]["reachable"] = True
                result["http"]["status_code"] = resp.status_code
                result["http"]["content_type"] = resp.headers.get("Content-Type", "").split(";")[0]
                result["http"]["final_url"] = current_url
                
                if resp.is_redirect:
                    location = resp.headers.get("Location")
                    if not location:
                        break
                    
                    # Handle relative redirects
                    if location.startswith("/"):
                        location = f"{parsed_current.scheme}://{parsed_current.netloc}{location}"
                        
                    if location in visited:
                        break
                        
                    result["redirects"]["detected"] = True
                    result["redirects"]["chain"].append(location)
                    
                    # Check if domain changed
                    new_ext = tldextract.extract(urlparse(location).hostname)
                    if new_ext.registered_domain != result["registered_domain"]:
                        result["redirects"]["external_domain_change"] = True
                        
                    current_url = location
                else:
                    break
                    
        except RequestException:
            pass

        return result
