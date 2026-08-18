from urllib.parse import urlparse

class URLHistoryTracker:
    def __init__(self):
        pass

    def sanitize_url(self, url: str) -> str:
        """
        Strip query parameters to prevent storing sensitive tokens/session IDs.
        """
        try:
            parsed = urlparse(url)
            # Reconstruct without query and fragment
            sanitized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            return sanitized
        except:
            return url

    def track_urls(self, urls: list, sender: str, domain: str):
        # Tracking logic should be handled by AdaptiveIntelligence Engine 
        # combining the store and this utility class.
        pass
        
    def analyze_infrastructure(self, url_store, current_urls: list, current_sender: str):
        """
        Detects if current URLs have been used by other senders/campaigns.
        """
        shared = []
        for url in current_urls:
            sanitized = self.sanitize_url(url)
            history = url_store.get_url_history(sanitized)
            if history:
                senders = history.get("senders", [])
                if len(senders) > 0 and current_sender not in senders:
                    shared.append({
                        "url": sanitized,
                        "previous_senders": len(senders)
                    })
                    
        return shared
