import ssl
import socket
from typing import Dict, Any
import json

def _check_tls(hostname: str, port: int = 443) -> Dict[str, Any]:
    result = {
        "https": port == 443,
        "certificate_present": False,
        "certificate_valid": None,
        "hostname_match": None,
        "chain_trusted": None,
        "expired": False,
        "self_signed": False,
        "violation": None,
        "severity": "LOW" if port != 443 else None,
        "issuer": None,
        "error_detail": None
    }
    
    if not hostname or port != 443:
        return result

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer_tuples = cert.get("issuer", ())
                issuer_dict = {k: v for pair in issuer_tuples for k, v in [pair[0]]}
                
                result["certificate_present"] = True
                result["certificate_valid"] = True
                result["hostname_match"] = True
                result["chain_trusted"] = True
                result["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName")
                
    except ssl.CertificateError as e:
        result["certificate_present"] = True
        result["certificate_valid"] = False
        result["chain_trusted"] = True
        result["hostname_match"] = False
        result["violation"] = "HOSTNAME_MISMATCH"
        result["severity"] = "HIGH"
        result["error_detail"] = "Hostname does not match certificate."
        
    except ssl.SSLCertVerificationError as e:
        result["certificate_present"] = True
        result["certificate_valid"] = False
        result["chain_trusted"] = False
        
        err_msg = str(e).lower()
        if "expired" in err_msg or "not yet valid" in err_msg:
            result["expired"] = True
            result["violation"] = "EXPIRED_CERTIFICATE"
            result["severity"] = "MEDIUM"
            result["error_detail"] = "Certificate has expired."
        elif "self signed" in err_msg or "self-signed" in err_msg:
            result["self_signed"] = True
            result["violation"] = "SELF_SIGNED_CERTIFICATE"
            result["severity"] = "MEDIUM"
            result["error_detail"] = "Certificate is self-signed."
        elif "unable to get local issuer" in err_msg or "certificate verify failed" in err_msg:
            result["violation"] = "UNTRUSTED_ISSUER"
            result["severity"] = "MEDIUM"
            result["error_detail"] = "Certificate chain is not trusted."
        else:
            result["violation"] = "CERTIFICATE_INVALID"
            result["severity"] = "MEDIUM"
            result["error_detail"] = "Certificate is invalid."

    except ssl.SSLError as e:
        result["certificate_present"] = False
        result["violation"] = "TLS_HANDSHAKE_FAILED"
        result["severity"] = "MEDIUM"
        result["error_detail"] = "TLS handshake failed."
        
    except Exception as e:
        result["certificate_present"] = False
        result["violation"] = "TLS_UNAVAILABLE"
        result["severity"] = "MEDIUM"
        result["error_detail"] = "TLS connection unavailable."
        
    return result


print("expired.badssl.com:", json.dumps(_check_tls("expired.badssl.com"), indent=2))
print("self-signed.badssl.com:", json.dumps(_check_tls("self-signed.badssl.com"), indent=2))
print("wrong.host.badssl.com:", json.dumps(_check_tls("wrong.host.badssl.com"), indent=2))
print("untrusted-root.badssl.com:", json.dumps(_check_tls("untrusted-root.badssl.com"), indent=2))
print("google.com:", json.dumps(_check_tls("google.com"), indent=2))
