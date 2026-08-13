import ssl
import socket

def test_err(host):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                print(f"{host}: OK")
    except Exception as e:
        print(f"{host}: {type(e).__name__} - {e}")

test_err("expired.badssl.com")
test_err("self-signed.badssl.com")
test_err("wrong.host.badssl.com")
test_err("untrusted-root.badssl.com")
