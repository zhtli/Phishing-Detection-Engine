"""PhishTank source: fetches verified phishing URLs from the public feed."""
from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
from io import StringIO
from typing import Iterable, List, Optional

import requests

PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.csv"
PHISHTANK_HEADERS = {"User-Agent": "phishtank"}


def _parse_iso_datetime(value: str) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp (treating a trailing ``Z`` as UTC); None on failure."""
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def fetch_phishtank_urls(
    limit: Optional[int] = None,
    days: Optional[int] = None,
    since: Optional[str] = None,
) -> List[str]:
    """Download the PhishTank feed and return phishing URLs.

    Optionally filters to entries verified within the last ``days`` or ``since`` an ISO
    timestamp, and caps the result at ``limit``.
    """
    resp = requests.get(PHISHTANK_URL, headers=PHISHTANK_HEADERS, timeout=30, verify=False)
    resp.raise_for_status()

    cutoff = None
    if since:
        cutoff = _parse_iso_datetime(since)
    elif days is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    urls: List[str] = []
    reader = csv.DictReader(StringIO(resp.text))
    for row in reader:
        url = (row.get("url") or "").strip()
        if not url:
            continue

        if cutoff:
            verification_time = _parse_iso_datetime(row.get("verification_time") or "")
            if verification_time and verification_time < cutoff:
                continue

        urls.append(url)
        if limit and len(urls) >= limit:
            break

    return urls
