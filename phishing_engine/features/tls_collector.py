from __future__ import annotations

import socket
import ssl
from typing import Optional
from urllib.parse import urlparse

from cryptography import x509


def fetch_tls_data(url: str, timeout: float = 10.0) -> Optional[dict]:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        return None

    hostname = parsed.hostname
    if not hostname:
        return None

    port = parsed.port if parsed.port else 443

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                protocol = tls_sock.version() or ""
                cipher_info = tls_sock.cipher() or ("", "", 0)
                cipher = cipher_info[0]
                cert_der = tls_sock.getpeercert(binary_form=True)

        certificates = []  # Leaf-only chain to keep the handshake lightweight.
        if cert_der:
            certificates.append(x509.load_der_x509_certificate(cert_der))

        return {
            "protocol": protocol,
            "cipher": cipher,
            "certificates": certificates,
            "count": len(certificates),
        }
    except Exception:
        return None
