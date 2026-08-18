import logging
from typing import Dict, Any
from .http_fetcher import HTTPFetcher
# from .browser_fetcher import BrowserFetcher

logger = logging.getLogger(__name__)

class URLWorker:
    """
    Coordinates the two-stage URL inspection fetch.
    """
    MIN_VISIBLE_TEXT = 50 # If less than this, we might need a browser fetch

    @classmethod
    def inspect(cls, url: str) -> Dict[str, Any]:
        logger.info(f"Worker starting inspection for {url}")
        
        # STAGE A - Lightweight HTTP fetch
        result = HTTPFetcher.fetch(url)
        
        if result.get("security", {}).get("blocked"):
            return result # Don't proceed if it was blocked by safety checks
            
        if result.get("security", {}).get("error"):
            # Could be a timeout, 404, or non-HTML.
            pass
            
        word_count = result.get("word_count", 0)
        forms_count = result.get("forms", {}).get("count", 0)
        
        # STAGE B - Browser fetch (if needed)
        # If the page is essentially empty (often happens with JS-rendered SPAs)
        # we would trigger the browser fallback here.
        if word_count < cls.MIN_VISIBLE_TEXT and forms_count == 0:
            logger.info(f"Insufficient content for {url} in Stage A, browser fallback recommended.")
            # browser_result = BrowserFetcher.fetch(url)
            # if browser_result:
            #     return browser_result
        
        return result
