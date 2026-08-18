import re
from urllib.parse import urlparse
import tldextract

SECURITY_PHRASES = {
    "verify", "verification", "account", "password", "login", 
    "suspended", "urgent", "immediately", "payment", "invoice", 
    "refund", "security", "confirm", "credential", "reset", 
    "click", "activate", "sign", "secure", "unusual", "locked", 
    "otp", "mfa", "recover", "banking", "transaction", "alert"
}

URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
NUMBER_REGEX = re.compile(r'\b\d+\b')
PUNCTUATION_REGEX = re.compile(r'[^\w\s]')

class SecurityTokenizer:
    def __init__(self):
        pass

    def tokenize(self, text: str):
        if not text:
            return []
        
        tokens = []
        
        # 1. Extract URLs
        urls = URL_REGEX.findall(text)
        for url in urls:
            # Replace URL with a placeholder to prevent it from being broken down in normal text processing
            text = text.replace(url, ' __URL_PLACEHOLDER__ ')
            tokens.extend(self._tokenize_url(url))

        # 2. Extract Emails
        emails = EMAIL_REGEX.findall(text)
        for email in emails:
            text = text.replace(email, ' __EMAIL_PLACEHOLDER__ ')
            tokens.append("<EMAIL>")
            
            # Optionally extract domain from email
            domain = email.split('@')[-1]
            ext = tldextract.extract(domain)
            if ext.domain:
                tokens.append(f"email_domain:{ext.domain}")
                if ext.suffix:
                    tokens.append(f"email_root:{ext.domain}.{ext.suffix}")

        # 3. Lowercase normalization
        text = text.lower()
        
        # 4. Process the remaining text
        words = text.split()
        for word in words:
            if word == '__url_placeholder__':
                continue # Already handled
            if word == '__email_placeholder__':
                continue # Already handled
                
            # Check for numbers
            if NUMBER_REGEX.fullmatch(word):
                tokens.append("<NUMBER>")
                continue
                
            # Strip punctuation from the edges
            clean_word = PUNCTUATION_REGEX.sub('', word)
            
            if not clean_word:
                continue
                
            if clean_word in SECURITY_PHRASES:
                tokens.append(f"SEC_PHRASE_{clean_word.upper()}")
            
            tokens.append(clean_word)
            
        # 5. Extract multi-word combinations (bigrams)
        text_clean = re.sub(r'[^\w\s]', ' ', text)
        words_clean = text_clean.split()
        for i in range(len(words_clean) - 1):
            w1 = words_clean[i]
            w2 = words_clean[i+1]
            if w1 == "account" and w2 in ["verify", "verification", "suspended", "locked"]:
                tokens.append(f"COMBO_ACCOUNT_{w2.upper()}")
            elif w1 in ["unusual", "suspicious"] and w2 == "activity":
                tokens.append("COMBO_UNUSUAL_ACTIVITY")
            elif w1 == "security" and w2 == "alert":
                tokens.append("COMBO_SECURITY_ALERT")
            elif w1 == "sign" and w2 == "in":
                tokens.append("COMBO_SIGN_IN")
            elif w1 == "password" and w2 == "reset":
                tokens.append("COMBO_PASSWORD_RESET")
            
        return tokens

    def _tokenize_url(self, url: str):
        tokens = ["<URL>"]
        
        if not url.startswith('http'):
            url = 'http://' + url
            
        try:
            parsed = urlparse(url)
            
            if parsed.scheme:
                tokens.append(f"url_scheme:{parsed.scheme}")
            
            if parsed.netloc:
                tokens.append(f"url_host:{parsed.netloc}")
                
            if parsed.path and parsed.path != '/':
                tokens.append(f"url_path:{parsed.path}")
                
            ext = tldextract.extract(url)
            if ext.domain and ext.suffix:
                root_domain = f"{ext.domain}.{ext.suffix}"
                tokens.append(f"url_root_domain:{root_domain}")
                
        except Exception:
            pass # Ignore malformed URL parsing errors
            
        return tokens
