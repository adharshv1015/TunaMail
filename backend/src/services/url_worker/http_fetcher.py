import requests
from urllib.parse import urljoin
from .safety import URLSafetyChecker, URLSafetyException
from .content_extractor import ContentExtractor
from typing import Dict, Any

class HTTPFetcher:
    MAX_REDIRECT_HOPS = 5
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024 # 5 MB

    @classmethod
    def fetch(cls, start_url: str) -> Dict[str, Any]:
        """
        Fetches the URL, manually following redirects and validating each hop.
        """
        current_url = start_url
        redirect_chain = []
        hops = 0
        
        session = requests.Session()
        # Common headers to avoid 403s on simple fetches
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        })

        try:
            while hops < cls.MAX_REDIRECT_HOPS:
                URLSafetyChecker.validate_url(current_url)
                
                # Fetch without auto-redirects
                resp = session.get(current_url, allow_redirects=False, timeout=10)
                
                if 300 <= resp.status_code < 400 and 'Location' in resp.headers:
                    redirect_url = urljoin(current_url, resp.headers['Location'])
                    redirect_chain.append({
                        "from": current_url,
                        "to": redirect_url,
                        "status": resp.status_code
                    })
                    current_url = redirect_url
                    hops += 1
                else:
                    # Final destination reached
                    content_type = resp.headers.get("Content-Type", "")
                    
                    if "text/html" not in content_type and "text/plain" not in content_type:
                        return cls._build_result(current_url, resp.status_code, redirect_chain, error="Not HTML content")
                        
                    content_length = int(resp.headers.get("Content-Length", 0))
                    if content_length > cls.MAX_CONTENT_LENGTH:
                        return cls._build_result(current_url, resp.status_code, redirect_chain, error="Content too large")
                        
                    text_content = resp.text
                    extracted = ContentExtractor.extract(text_content)
                    return cls._build_result(current_url, resp.status_code, redirect_chain, extracted=extracted)
                    
            return cls._build_result(current_url, 0, redirect_chain, error="Too many redirects")
            
        except URLSafetyException as e:
            return cls._build_result(current_url, 0, redirect_chain, error=f"Safety blocked: {str(e)}", blocked=True)
        except requests.RequestException as e:
            return cls._build_result(current_url, 0, redirect_chain, error=f"Fetch failed: {str(e)}")

    @classmethod
    def _build_result(cls, final_url: str, status_code: int, redirect_chain: list, extracted: Dict[str, Any] = None, error: str = None, blocked: bool = False) -> Dict[str, Any]:
        res = {
            "http": {
                "final_url": final_url,
                "status_code": status_code,
            },
            "redirects": redirect_chain,
            "security": {
                "blocked": blocked,
                "error": error
            }
        }
        if extracted:
            res.update(extracted)
        else:
            # Provide empty defaults if fetch failed or content wasn't HTML
            res.update({
                "title": "",
                "visible_text": "",
                "forms": {"count": 0, "password_fields": 0, "email_fields": 0}
            })
        return res
