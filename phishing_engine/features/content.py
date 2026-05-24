from __future__ import annotations

from typing import Dict, Optional, Tuple

import pandas as pd

from phishing_engine.features.domainradar.transformations.html import HTMLTransformation
from phishing_engine.features.domainradar.transformations.tls import TLSTransformation


def _load_tls_certs(tls_data: Optional[dict]) -> Optional[dict]:
    """Reconstruct the x509-object TLS shape the TLS transformation expects.

    Accepts the serializable form produced by ``collectors.tls.fetch_tls_data`` (and
    stored in Mongo): ``{protocol, cipher, certificates_der, count}``.
    """
    if not tls_data:
        return None

    from cryptography import x509

    certificates = []
    for der in tls_data.get("certificates_der") or []:
        if isinstance(der, str):
            der = bytes.fromhex(der)
        try:
            certificates.append(x509.load_der_x509_certificate(der))
        except Exception:
            continue

    return {
        "protocol": tls_data.get("protocol", ""),
        "cipher": tls_data.get("cipher", ""),
        "certificates": certificates,
        "count": tls_data.get("count", len(certificates)),
    }


class ContentFeatureExtractor:
    """Extracts HTML + TLS content features from a fetched page.

    ``tls_data`` is the serializable shape produced by ``fetch_tls_data`` / stored by the
    content collector; certificates are reconstructed into x509 objects here.
    """

    def __init__(self):
        self.html_transform = HTMLTransformation(None)
        self.tls_transform = TLSTransformation(None)

    def extract(
        self,
        html: str,
        tls_data: dict | None,
    ) -> Tuple[Dict[str, object], Dict[str, object]]:
        df = pd.DataFrame([
            {
                "html": html,
                "tls": _load_tls_certs(tls_data),
            }
        ])

        df = self.html_transform.transform(df)
        df = self.tls_transform.transform(df)

        df = df.drop(columns=["html", "tls"], errors="ignore")
        features = df.iloc[0].to_dict()

        return features, {}
