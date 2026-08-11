SCORING = {

    "authentication": {
        "spf_fail": 25,
        "dkim_fail": 25,
        "dmarc_fail": 25
    },

    "url": {
        "ip_url": 20,
        "shortener": 15,
        "keyword": 5,
        "obfuscated": 15,
        "punycode": 15,
        "suspicious_port": 10,
        "excessive_subdomains": 10
    },

    "content": {
        "urgency": 20,
        "credential_request": 25,
        "financial_request": 25,
        "impersonation": 10,
        "threat_language": 20
    },

    "attachment": {
        "risk_multiplier": 1
    },

    "whois": {
        "new_domain": 15,
        "recent_domain": 5,
        "lookup_error": 0
    }

}