
import os
import sys
import threading
import time
import ssl
import datetime

from http.server import HTTPServer, BaseHTTPRequestHandler

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# ============================================================
# Certificate helpers
# ============================================================

def generate_ca(
    cert_file,
    key_file,
):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME,
            "TunaMail Test CA",
        ),
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            "TunaMail Test Root CA",
        ),
    ])

    now = datetime.datetime.now(
        datetime.UTC
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(
            x509.random_serial_number()
        )
        .not_valid_before(
            now - datetime.timedelta(days=1)
        )
        .not_valid_after(
            now + datetime.timedelta(days=30)
        )
        .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=None,
            ),
            critical=True,
        )
        .sign(
            key,
            hashes.SHA256(),
        )
    )

    with open(
        cert_file,
        "wb",
    ) as f:
        f.write(
            cert.public_bytes(
                serialization.Encoding.PEM
            )
        )

    with open(
        key_file,
        "wb",
    ) as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )


def generate_cert(
    cert_file,
    key_file,
    hostname="localhost",
    expired=False,
    wrong_host=False,
    ca_cert=None,
    ca_key=None,
):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject_name = (
        "wronghost.local"
        if wrong_host
        else hostname
    )

    subject = x509.Name([
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME,
            "TunaMail Test",
        ),
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            subject_name,
        ),
    ])

    # --------------------------------------------------------
    # Self-signed certificate
    # --------------------------------------------------------

    if ca_cert is None or ca_key is None:
        issuer = subject
        signing_key = key

    # --------------------------------------------------------
    # CA-signed certificate
    # --------------------------------------------------------

    else:
        issuer = ca_cert.subject
        signing_key = ca_key

    now = datetime.datetime.now(
        datetime.UTC
    )

    not_valid_before = (
        now - datetime.timedelta(days=10)
    )

    if expired:
        not_valid_after = (
            now - datetime.timedelta(days=1)
        )
    else:
        not_valid_after = (
            now + datetime.timedelta(days=10)
        )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(
            x509.random_serial_number()
        )
        .not_valid_before(
            not_valid_before
        )
        .not_valid_after(
            not_valid_after
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(subject_name)
            ]),
            critical=False,
        )
        .sign(
            signing_key,
            hashes.SHA256(),
        )
    )

    with open(
        cert_file,
        "wb",
    ) as f:
        f.write(
            cert.public_bytes(
                serialization.Encoding.PEM
            )
        )

    with open(
        key_file,
        "wb",
    ) as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )


def load_private_key(
    key_file,
):
    with open(
        key_file,
        "rb",
    ) as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
        )


def load_certificate(
    cert_file,
):
    with open(
        cert_file,
        "rb",
    ) as f:
        return x509.load_pem_x509_certificate(
            f.read()
        )


# ============================================================
# Dummy HTTP handler
# ============================================================

class DummyHandler(
    BaseHTTPRequestHandler
):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(
        self,
        format,
        *args,
    ):
        pass


# ============================================================
# Local test server
# ============================================================

def start_server(
    port,
    cert_file=None,
    key_file=None,
    plain_http=False,
):
    httpd = HTTPServer(
        ("127.0.0.1", port),
        DummyHandler,
    )

    if not plain_http:
        context = ssl.SSLContext(
            ssl.PROTOCOL_TLS_SERVER
        )

        context.load_cert_chain(
            certfile=cert_file,
            keyfile=key_file,
        )

        httpd.socket = (
            context.wrap_socket(
                httpd.socket,
                server_side=True,
            )
        )

    thread = threading.Thread(
        target=httpd.serve_forever,
        daemon=True,
    )

    thread.start()

    return httpd


# ============================================================
# Test fixture setup
# ============================================================

os.makedirs(
    "test_certs",
    exist_ok=True,
)


# ------------------------------------------------------------
# Generate local test CA
# ------------------------------------------------------------

generate_ca(
    "test_certs/test_ca.crt",
    "test_certs/test_ca.key",
)

ca_cert = load_certificate(
    "test_certs/test_ca.crt"
)

ca_key = load_private_key(
    "test_certs/test_ca.key"
)


# ------------------------------------------------------------
# Self-signed certificate
# ------------------------------------------------------------

generate_cert(
    "test_certs/self_signed.crt",
    "test_certs/self_signed.key",
    hostname="localhost",
)


# ------------------------------------------------------------
# CA-signed expired certificate
# ------------------------------------------------------------

generate_cert(
    "test_certs/expired.crt",
    "test_certs/expired.key",
    hostname="localhost",
    expired=True,
    ca_cert=ca_cert,
    ca_key=ca_key,
)


# ------------------------------------------------------------
# CA-signed wrong-host certificate
# ------------------------------------------------------------

generate_cert(
    "test_certs/wrong_host.crt",
    "test_certs/wrong_host.key",
    hostname="localhost",
    wrong_host=True,
    ca_cert=ca_cert,
    ca_key=ca_key,
)


# ------------------------------------------------------------
# Start servers
# ------------------------------------------------------------

s_self = start_server(
    18443,
    "test_certs/self_signed.crt",
    "test_certs/self_signed.key",
)

s_exp = start_server(
    18444,
    "test_certs/expired.crt",
    "test_certs/expired.key",
)

s_wrong = start_server(
    18445,
    "test_certs/wrong_host.crt",
    "test_certs/wrong_host.key",
)

s_plain = start_server(
    18446,
    plain_http=True,
)

time.sleep(0.5)


# ============================================================
# Project imports
# ============================================================

sys.path.insert(
    0,
    "src",
)

import src.services.url_inspection_service as url_inspection_service

from src.analyzers.url_analyzer import (
    URLAnalyzer,
)

from src.engines.are import (
    AnalyticalReasoningEngine,
)


# ============================================================
# Test-only SSRF override
#
# Production SSRF protection remains unchanged.
# This exists only in this isolated test process so the local
# 127.0.0.1 fixtures can reach TLS inspection.
# ============================================================

original_is_blocked_ip = (
    url_inspection_service._is_blocked_ip
)

url_inspection_service._is_blocked_ip = (
    lambda value: False
)


# ============================================================
# Test-only TLS context override
#
# The production implementation uses:
#
#     ssl.create_default_context()
#
# We temporarily add our test CA to that context so the
# CA-signed expired and wrong-host certificates can reach the
# intended validation stage.
#
# Self-signed certificate remains untrusted.
# ============================================================

original_create_default_context = (
    url_inspection_service.ssl.create_default_context
)


def test_create_default_context(
    *args,
    **kwargs,
):
    context = (
        original_create_default_context(
            *args,
            **kwargs,
        )
    )

    context.load_verify_locations(
        cafile="test_certs/test_ca.crt"
    )

    return context


url_inspection_service.ssl.create_default_context = (
    test_create_default_context
)


# ============================================================
# Analyzer / ARE
# ============================================================

analyzer = URLAnalyzer()
are = AnalyticalReasoningEngine()


# ============================================================
# Test cases
# ============================================================

test_cases = [
    (
        "Self-Signed",
        "https://localhost:18443",
        "SELF_SIGNED_CERTIFICATE",
    ),
    (
        "Expired",
        "https://localhost:18444",
        "EXPIRED_CERTIFICATE",
    ),
    (
        "Hostname Mismatch",
        "https://localhost:18445",
        "HOSTNAME_MISMATCH",
    ),
    (
        "Handshake Failure",
        "https://localhost:18446",
        "TLS_HANDSHAKE_FAILED",
    ),
]


# ============================================================
# E2E test
# ============================================================

def run_e2e_test():
    failures = []

    try:
        for (
            name,
            url,
            expected_violation,
        ) in test_cases:

            print(
                f"\n--- Testing {name} ---"
            )

            # ------------------------------------------------
            # 1. URL Analyzer
            # ------------------------------------------------

            inspection_data = (
                analyzer.analyze_url(
                    url,
                    {},
                    {},
                )
            )

            tls_data = (
                inspection_data.get(
                    "tls",
                    {},
                )
            )

            actual_violation = (
                tls_data.get(
                    "violation"
                )
            )

            print(
                "Violation Detected:",
                actual_violation,
                f"(Expected: {expected_violation})",
            )

            if (
                actual_violation
                != expected_violation
            ):
                failures.append(
                    f"{name}: expected "
                    f"{expected_violation}, got "
                    f"{actual_violation}"
                )

            # ------------------------------------------------
            # 2. ARE evaluation
            # ------------------------------------------------

            auth = {
                "analysis_status": "AVAILABLE",
                "spf": "pass",
                "dkim": "pass",
                "dmarc": "pass",
            }

            url_analysis = {
                "analysis": [
                    {
                        "url": url,
                        "domain": "localhost",
                        "tls": tls_data,
                        "tls_policy_violation": (
                            inspection_data.get(
                                "tls_policy_violation"
                            )
                        ),
                        "tls_inspection_unavailable": (
                            inspection_data.get(
                                "tls_inspection_unavailable"
                            )
                        ),
                    }
                ]
            }

            result = are.evaluate(
                auth,
                url_analysis,
                [],
                {},
                {},
                {},
            )

            score = result[
                "risk_score"
            ]

            evidence = result[
                "evidence"
            ]

            print(
                "ARE Score:",
                score,
            )

            print(
                "ARE Network Evidence:",
                evidence.get(
                    "network",
                    [],
                ),
            )

            # ------------------------------------------------
            # 3. Structured TLS evidence
            # ------------------------------------------------

            structured_evidence = (
                inspection_data.get(
                    "structured_evidence",
                    [],
                )
            )

            print(
                "Structured TLS Evidence:",
                structured_evidence,
            )

            if not structured_evidence:
                failures.append(
                    f"{name}: no structured "
                    "TLS evidence was produced"
                )

    finally:
        # ----------------------------------------------------
        # Restore production functions
        # ----------------------------------------------------

        url_inspection_service._is_blocked_ip = (
            original_is_blocked_ip
        )

        url_inspection_service.ssl.create_default_context = (
            original_create_default_context
        )

        # ----------------------------------------------------
        # Stop test servers
        # ----------------------------------------------------

        for server in (
            s_self,
            s_exp,
            s_wrong,
            s_plain,
        ):
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                pass

    # ========================================================
    # Final result
    # ========================================================

    if failures:
        print(
            "\n=== TLS E2E TEST FAILED ==="
        )

        for failure in failures:
            print(
                "FAIL:",
                failure,
            )

        raise AssertionError(
            "TLS E2E test failures detected."
        )

    print(
        "\n=== TLS E2E TEST PASSED ==="
    )


# ============================================================
# Execute
# ============================================================

if __name__ == "__main__":
    run_e2e_test()
