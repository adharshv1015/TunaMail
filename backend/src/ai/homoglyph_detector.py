import re

class HomoglyphDetector:
    """
    Detects visually deceptive domains using Punycode, Unicode lookalikes,
    and ASCII substitutions (like paypa1.com).
    """

    def __init__(self):
        # Common ASCII substitutions
        # 1 for l/i, 0 for o, vv for w, rn for m, cl for d, etc.
        self.ascii_homoglyphs = {
            'l': ['1', 'I'],
            'i': ['1', 'l', 'j'],
            'o': ['0'],
            'm': ['rn'],
            'w': ['vv'],
            'd': ['cl']
        }
        
    def analyze_domain(self, domain: str) -> dict:
        if not domain:
            return None

        domain = domain.lower()
        
        # 1. Punycode check
        if "xn--" in domain:
            return {
                "homoglyph_detected": True,
                "type": "PUNYCODE",
                "confidence": 0.99,
                "evidence": f"Punycode encoding detected in domain: {domain}"
            }
            
        # 2. Mixed script / Unicode check
        # A simple heuristic: domain has characters outside standard ASCII alphanumeric & hyphen
        if re.search(r'[^\x00-\x7F]', domain):
            return {
                "homoglyph_detected": True,
                "type": "UNICODE_LOOKALIKE",
                "confidence": 0.95,
                "evidence": f"Non-ASCII characters detected in domain: {domain}"
            }

        # 3. Simple ASCII substitution heuristic
        # We don't flag all numbers, but if we see 'paypa1', it's suspicious.
        # This is basic, for advanced we would compute edit distance against brand names.
        suspicious_patterns = [
            (r'paypa[1l!]', "PayPal"),
            (r'g00gle', "Google"),
            (r'micros0ft', "Microsoft"),
            (r'app1e', "Apple"),
            (r'netflix[1l]', "Netflix"),
            (r'rnicrosoft', "Microsoft")
        ]
        
        for pattern, brand in suspicious_patterns:
            if re.search(pattern, domain):
                return {
                    "homoglyph_detected": True,
                    "type": "ASCII_SUBSTITUTION",
                    "confidence": 0.90,
                    "evidence": f"ASCII homoglyph resembling '{brand}' detected: {domain}"
                }
                
        return None
