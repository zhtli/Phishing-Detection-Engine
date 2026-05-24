"""HTML fetching for the content collector. HTML only — never fetches/executes JS."""
from __future__ import annotations

import requests


def fetch_website(url, user_agent=None):
    """Fetch a page's HTML.

    Returns: (html, status_code, redirect_count, final_url, reason).
    """
    headers = {}
    if user_agent:
        headers["User-Agent"] = user_agent

    resp = requests.get(url, headers=headers, timeout=10, verify=False)
    content_type = (resp.headers.get("Content-Type") or "").lower()
    is_html = ("text/html" in content_type) or ("application/xhtml+xml" in content_type)

    html = resp.text if is_html else ""
    return html, resp.status_code, len(resp.history), resp.url, resp.reason
