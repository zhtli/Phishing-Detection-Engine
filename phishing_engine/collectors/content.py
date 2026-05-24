"""Collects raw page content (HTML + TLS) for a URL.

Used both by the enrichment collector (which stores the content in MongoDB) and by the
prediction pipeline's content stage (which collects in-memory and never stores).
JavaScript is never fetched/executed — HTML only.
"""
from __future__ import annotations

from typing import Optional

from phishing_engine.collectors.web_fetch import fetch_website
from phishing_engine.collectors.tls import fetch_tls_data

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"

def collect_content(url: str, tls_timeout: float = 10.0, max_html_bytes: Optional[int] = None) -> dict:
    """Fetch a page's HTML and a TLS summary into one serializable dict.

    ``max_html_bytes`` optionally truncates stored HTML. The returned dict (html, status,
    redirects, final_url, tls) is BSON-serializable so the content collector can store it
    verbatim; the content stage uses the same dict in-memory at prediction time.
    """
    html, status_code, redirect_count, final_url, reason = fetch_website(
        url,
        user_agent=USER_AGENT
    )

    if max_html_bytes is not None and html:
        encoded = html.encode("utf-8")[:max_html_bytes]
        html = encoded.decode("utf-8", errors="ignore")

    target_url = final_url or url
    tls_data = fetch_tls_data(target_url, timeout=tls_timeout)

    return {
        "html": html,
        "status_code": status_code,
        "redirect_count": redirect_count,
        "final_url": final_url,
        "reason": reason,
        "tls": tls_data,
    }
