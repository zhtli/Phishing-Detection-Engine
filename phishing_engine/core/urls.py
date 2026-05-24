"""URL normalization helpers shared by the pipeline and the store.

A normalized URL is used as the MongoDB document ``_id``, so prediction and collection
key the same URL identically.
"""
from __future__ import annotations

from urllib.parse import urlparse


def normalize_url(url: str) -> str:
    """Canonicalize a URL: add a scheme if missing and IDNA-encode the host.

    Keeps the rest of the URL intact; used as the stable document key.
    """
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    host = parsed.hostname or ""
    try:
        host = host.encode("idna").decode("ascii")
    except Exception:
        pass
    normalized = parsed._replace(netloc=host).geturl()
    return normalized


def extract_domain(url: str) -> str:
    """Return the host/domain portion of a URL (without scheme, path or trailing dot)."""
    parsed = urlparse(url)
    host = parsed.hostname or parsed.path
    return (host or "").strip().strip(".")
