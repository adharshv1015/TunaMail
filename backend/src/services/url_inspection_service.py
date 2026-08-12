import time
import socket
import ssl
import threading
import logging
from typing import Dict, Any, List
from urllib.parse import urlparse
import tldextract
from .url_jobs import url_queue, URLInspectionJob
from .page_cache import page_cache
from .url_worker.worker import URLWorker

logger = logging.getLogger(__name__)


def _resolve_dns(hostname: str) -> Dict[str, Any]:
    """Resolve hostname to IPs. Returns dns dict for URLAnalyzer schema."""
    import ipaddress
    result = {"resolved": False, "a": [], "aaaa": [], "private_ip_detected": False}
    if not hostname:
        return result
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
        for info in addr_infos:
            ip = info[4][0]
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private or ip_obj.is_loopback:
                    result["private_ip_detected"] = True
                if isinstance(ip_obj, ipaddress.IPv4Address):
                    if ip not in result["a"]:
                        result["a"].append(ip)
                else:
                    if ip not in result["aaaa"]:
                        result["aaaa"].append(ip)
            except ValueError:
                pass
        result["resolved"] = bool(result["a"] or result["aaaa"])
    except socket.gaierror:
        result["resolved"] = False
    return result


def _check_tls(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Quick TLS certificate check. Returns tls dict for URLAnalyzer schema."""
    result = {"https": False, "certificate_valid": False, "issuer": None}
    if not hostname or port != 443:
        return result
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=5),
            server_hostname=hostname,
        ) as ssock:
            cert = ssock.getpeercert()
            issuer_tuples = cert.get("issuer", ())
            issuer_dict = {k: v for pair in issuer_tuples for k, v in [pair[0]]}
            result["https"] = True
            result["certificate_valid"] = True
            result["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName")
    except ssl.SSLCertVerificationError:
        result["https"] = True
        result["certificate_valid"] = False
    except Exception:
        pass
    return result

class URLInspectionService:
    MAX_URLS_PER_EMAIL = 50
    MAX_CONCURRENT_INSPECTIONS = 3
    INSPECTION_TIMEOUT = 10 # seconds
    
    _worker_thread = None
    _stop_event = threading.Event()

    def inspect(self, url: str) -> Dict[str, Any]:
        """
        Synchronous per-URL inspection called by URLAnalyzer.analyze_url().
        Performs DNS resolution and TLS checking and returns the schema
        that URLAnalyzer expects:
          { url, domain, registered_domain, dns, tls, redirects, threat_intelligence }
        """
        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower().rstrip(".")
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            ext = tldextract.extract(url)
            registered_domain = ext.registered_domain or hostname

            dns = _resolve_dns(hostname)
            tls = _check_tls(hostname, port)

            # Build redirect info — we don't follow here, just note the initial URL
            redirects = {
                "detected": False,
                "chain": [],
                "external_domain_change": False,
            }

            # Threat intelligence stub — populated by future integration (VirusTotal etc.)
            threat_intelligence = {
                "status": "unavailable",
                "detections": 0,
                "engines": [],
            }

            return {
                "url": url,
                "domain": hostname,
                "registered_domain": registered_domain,
                "dns": dns,
                "tls": tls,
                "redirects": redirects,
                "threat_intelligence": threat_intelligence,
            }
        except Exception as e:
            logger.warning(f"URLInspectionService.inspect() failed for {url}: {e}")
            return {
                "url": url,
                "domain": "",
                "registered_domain": "",
                "dns": {"resolved": False, "a": [], "aaaa": [], "private_ip_detected": False},
                "tls": {"https": False, "certificate_valid": False, "issuer": None},
                "redirects": {"detected": False, "chain": [], "external_domain_change": False},
                "threat_intelligence": {"status": "unavailable", "detections": 0, "engines": []},
            }


    @classmethod
    def start_local_worker(cls):
        """Starts a background thread to process jobs in the local queue."""
        if cls._worker_thread is None or not cls._worker_thread.is_alive():
            cls._stop_event.clear()
            cls._worker_thread = threading.Thread(target=cls._worker_loop, daemon=True)
            cls._worker_thread.start()
            logger.info("Local URL worker thread started.")

    @classmethod
    def _worker_loop(cls):
        while not cls._stop_event.is_set():
            job = url_queue.dequeue()
            if job:
                url_queue.update_job(job.job_id, "RUNNING")
                try:
                    result = URLWorker.inspect(job.url)
                    url_queue.update_job(job.job_id, "COMPLETED", result=result)
                    
                    # Cache public intelligence
                    if result and not result.get("security", {}).get("error"):
                        page_cache.set(job.url, result)
                        
                except Exception as e:
                    logger.error(f"Worker failed on {job.url}: {e}")
                    url_queue.update_job(job.job_id, "FAILED", error=str(e))
            else:
                time.sleep(0.1)

    @classmethod
    def inspect_urls(cls, urls: List[str], message_id: str, user_id: str = "system") -> Dict[str, Any]:
        """
        Orchestrates inspection of multiple URLs.
        Checks cache, queues missing URLs, waits for completion.
        """
        cls.start_local_worker()
        
        results = {}
        jobs_to_wait = []
        
        # Deduplicate and limit
        unique_urls = list(set(urls))[:cls.MAX_URLS_PER_EMAIL]
        
        for url in unique_urls:
            cached = page_cache.get(url)
            if cached:
                results[url] = cached
                continue
                
            job = URLInspectionJob(message_id=message_id, url=url, user_id=user_id)
            url_queue.enqueue(job)
            jobs_to_wait.append(job)

        # Wait for pending jobs
        start_time = time.time()
        while jobs_to_wait and time.time() - start_time < cls.INSPECTION_TIMEOUT:
            still_waiting = []
            for job in jobs_to_wait:
                updated_job = url_queue.get_job(job.job_id)
                if updated_job.status in ["COMPLETED", "FAILED", "BLOCKED", "TIMEOUT"]:
                    if updated_job.result:
                        results[job.url] = updated_job.result
                    else:
                        results[job.url] = {"security": {"error": updated_job.error or "Unknown failure"}}
                else:
                    still_waiting.append(job)
            jobs_to_wait = still_waiting
            if jobs_to_wait:
                time.sleep(0.2)
                
        # Handle timeouts
        for job in jobs_to_wait:
            url_queue.update_job(job.job_id, "TIMEOUT")
            results[job.url] = {"security": {"error": "INSPECTION_TIMEOUT", "blocked": False}}
            
        return results
