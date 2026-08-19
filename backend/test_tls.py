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
                issuer_dict = {
                    k: v
                    for pair in issuer_tuples
                    for k, v in [pair[0]]
                }

                result["certificate_present"] = True
                result["certificate_valid"] = True
                result["hostname_match"] = True
                result["chain_trusted"] = True
                result["issuer"] = (
                    issuer_dict.get("organizationName")
                    or issuer_dict.get("commonName")
                )

    except ssl.SSLCertVerificationError as e:
        result["certificate_present"] = True
        result["certificate_valid"] = False

        err_msg = str(e).lower()
        verify_msg = getattr(e, "verify_message", "").lower()

        combined_msg = f"{err_msg} {verify_msg}"

        if (
            "hostname mismatch" in combined_msg
            or "doesn't match" in combined_msg
            or "does not match" in combined_msg
            or "certificate is not valid for" in combined_msg
        ):
            result["hostname_match"] = False
            result["chain_trusted"] = True
            result["violation"] = "HOSTNAME_MISMATCH"
            result["severity"] = "HIGH"
            result["error_detail"] = "Hostname does not match certificate."

        elif "expired" in combined_msg or "not yet valid" in combined_msg:
            result["hostname_match"] = True
            result["chain_trusted"] = True
            result["expired"] = True
            result["violation"] = "EXPIRED_CERTIFICATE"
            result["severity"] = "MEDIUM"
            result["error_detail"] = "Certificate has expired."

        elif "self signed" in combined_msg or "self-signed" in combined_msg:
            result["hostname_match"] = True
            result["chain_trusted"] = False
            result["self_signed"] = True
            result["violation"] = "SELF_SIGNED_CERTIFICATE"
            result["severity"] = "MEDIUM"
            result["error_detail"] = "Certificate is self-signed."

        elif (
            "unable to get local issuer" in combined_msg
            or "unable to verify the first certificate" in combined_msg
            or "certificate verify failed" in combined_msg
        ):
            result["hostname_match"] = True
            result["chain_trusted"] = False
            result["violation"] = "UNTRUSTED_ISSUER"
            result["severity"] = "MEDIUM"
            result["error_detail"] = "Certificate chain is not trusted."

        else:
            result["hostname_match"] = None
            result["chain_trusted"] = False
            result["violation"] = "CERTIFICATE_INVALID"
            result["severity"] = "MEDIUM"
            result["error_detail"] = "Certificate is invalid."

    except ssl.CertificateError:
        result["certificate_present"] = True
        result["certificate_valid"] = False
        result["hostname_match"] = False
        result["chain_trusted"] = True
        result["violation"] = "HOSTNAME_MISMATCH"
        result["severity"] = "HIGH"
        result["error_detail"] = "Hostname does not match certificate."

    except ssl.SSLError:
        result["certificate_present"] = False
        result["violation"] = "TLS_HANDSHAKE_FAILED"
        result["severity"] = "MEDIUM"
        result["error_detail"] = "TLS handshake failed."

    except Exception:
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
