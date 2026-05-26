"""Search source: benign URLs obtained by running search terms through DuckDuckGo."""
from __future__ import annotations

import csv
import logging
from typing import Iterable, Iterator, List, Tuple

from ddgs import DDGS
from ddgs.exceptions import DDGSException

logger = logging.getLogger(__name__)


_TRENDS_COLUMN = "Trends"


def load_search_terms(file_path: str) -> List[str]:
    """Load search terms from a Google Trends CSV export.

    The export has the columns ``Trends,Search volume,Started,Ended,Trend
    breakdown,Explore link``; the ``Trends`` column holds the search term.
    Uses ``utf-8-sig`` to tolerate the BOM Google Trends prepends.
    """
    terms: List[str] = []
    with open(file_path, "r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or _TRENDS_COLUMN not in reader.fieldnames:
            raise ValueError(
                f"{file_path}: expected a Google Trends CSV with a {_TRENDS_COLUMN!r} "
                f"column, got headers {reader.fieldnames}"
            )
        for row in reader:
            value = (row.get(_TRENDS_COLUMN) or "").strip()
            if value:
                terms.append(value)
    return list(dict.fromkeys(terms))


def iter_search_results(
    terms: Iterable[str],
    max_results: int = 5,
    max_consecutive_failures: int = 5,
) -> Iterator[Tuple[str, List[str]]]:
    """Yield ``(term, urls)`` for each successfully searched term.

    Each term's search is isolated: a ``DDGSException`` (DuckDuckGo rate-limit or a
    transient network error) is logged and the term is skipped — it is *not* yielded, so
    the caller can leave it unmarked and retry it on a later run. After
    ``max_consecutive_failures`` failures in a row the search stops early: that streak is
    the signature of an IP-level rate-limit block, where every further request would just
    hammer a blocked endpoint. The caller resumes the remaining terms on a later run.

    Result URLs are yielded per term (not de-duplicated across terms); the store upserts
    by normalized URL, so cross-term duplicates collapse there. This generator does no
    progress reporting — the caller drives the (slower) per-URL enrichment and owns the bar.
    """
    consecutive_failures = 0
    with DDGS() as ddgs:
        for term in terms:
            try:
                results = list(ddgs.text(term, max_results=max_results))
            except DDGSException as exc:
                consecutive_failures += 1
                logger.warning(
                    "search failed for %r (%d consecutive failures): %s",
                    term, consecutive_failures, exc,
                )
                if consecutive_failures >= max_consecutive_failures:
                    logger.error(
                        "stopping search after %d consecutive failures (likely "
                        "rate-limited); rerun later to resume the remaining terms",
                        consecutive_failures,
                    )
                    break
                continue

            consecutive_failures = 0
            urls = [
                url
                for result in results
                if (url := result.get("href") or result.get("url") or result.get("link"))
            ]
            yield term, urls
