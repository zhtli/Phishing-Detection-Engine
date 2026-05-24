from __future__ import annotations

import socket
import ssl
from typing import Optional
from urllib.parse import urlparse


def fetch_tls_data(url: str, timeout: float = 10.0) -> Optional[dict]:
    """Perform a lightweight TLS handshake and return a JSON/BSON-serializable summary.

    Certificates are returned as DER bytes (``certificates_der``) so the result can be
    stored verbatim in MongoDB by the collectors. The content feature extractor
    reconstructs them into x509 objects at feature time.
    """
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
    except Exception:
        return None

    certificates_der = [cert_der] if cert_der else []
    return {
        "protocol": protocol,
        "cipher": cipher,
        "certificates_der": certificates_der,
        "count": len(certificates_der),
    }
