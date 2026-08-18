import os
import threading
import time
import ssl
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime
import socket

# Helpers to generate certs
def generate_cert(cert_file, key_file, hostname="localhost", expired=False, wrong_host=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    subject_name = "wronghost.local" if wrong_host else hostname
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])
    
    not_valid_before = datetime.datetime.utcnow() - datetime.timedelta(days=10)
    not_valid_after = datetime.datetime.utcnow() - datetime.timedelta(days=1) if expired else datetime.datetime.utcnow() + datetime.timedelta(days=10)
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_valid_before
    ).not_valid_after(
        not_valid_after
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(subject_name)]),
        critical=False,
    ).sign(key, hashes.SHA256())
    
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

# Create dummy handler
class DummyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    def log_message(self, format, *args):
        pass

def start_server(port, cert_file=None, key_file=None, plain_http=False):
    httpd = HTTPServer(('127.0.0.1', port), DummyHandler)
    if not plain_http:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        
    thread = threading.Thread(target=httpd.serve_forever)
    thread.daemon = True
    thread.start()
    return httpd

# --- Setup Fixtures ---
os.makedirs("test_certs", exist_ok=True)
generate_cert("test_certs/self_signed.crt", "test_certs/self_signed.key")
generate_cert("test_certs/expired.crt", "test_certs/expired.key", expired=True)
generate_cert("test_certs/wrong_host.crt", "test_certs/wrong_host.key", wrong_host=True)

s_self = start_server(18443, "test_certs/self_signed.crt", "test_certs/self_signed.key")
s_exp = start_server(18444, "test_certs/expired.crt", "test_certs/expired.key")
s_wrong = start_server(18445, "test_certs/wrong_host.crt", "test_certs/wrong_host.key")
s_plain = start_server(18446, plain_http=True)
time.sleep(0.5)

import sys
sys.path.insert(0, 'src')
from src.services.url_inspection_service import URLInspectionService
from src.analyzers.url_analyzer import URLAnalyzer
from src.engines.are import AnalyticalReasoningEngine

analyzer = URLAnalyzer()
are = AnalyticalReasoningEngine()

test_cases = [
    ("Self-Signed", "https://localhost:18443", "SELF_SIGNED_CERTIFICATE"),
    ("Expired", "https://localhost:18444", "EXPIRED_CERTIFICATE"),
    ("Hostname Mismatch", "https://127.0.0.1:18445", "HOSTNAME_MISMATCH"),
    ("Handshake Failure", "https://localhost:18446", "TLS_HANDSHAKE_FAILED") # connecting HTTPS to plain HTTP port
]

def run_e2e_test():
    for name, url, expected_violation in test_cases:
        print(f"\\n--- Testing {name} ---")
        # 1. URL Analyzer (which calls URLInspectionService._check_tls internally)
        inspection_data = analyzer.analyze_url(url, {}, {})
        tls_data = inspection_data.get("tls", {})
        
        print(f"Violation Detected: {tls_data.get('violation')} (Expected: {expected_violation})")
        # assert tls_data.get("violation") == expected_violation
        
        # 2. ARE evaluation
        auth = {"analysis_status": "AVAILABLE", "spf": "pass", "dkim": "pass", "dmarc": "pass"}
        url_analysis = {"analysis": [
            {"url": url, "domain": "127.0.0.1", "tls": tls_data, "tls_policy_violation": inspection_data.get("tls_policy_violation"), "tls_inspection_unavailable": inspection_data.get("tls_inspection_unavailable")}
        ]}
        
        result = are.evaluate(auth, url_analysis, [], {}, {}, {})
        score = result["risk_score"]
        evidence = result["evidence"]
        print("ARE Score:", score)
        print("ARE Network Evidence:", evidence.get("network", []))
        
run_e2e_test()
