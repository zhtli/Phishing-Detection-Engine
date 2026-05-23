from __future__ import annotations

import csv
from typing import Iterable, List

from ddgs import DDGS


def load_search_terms(file_path: str) -> List[str]:
    terms: List[str] = []
    with open(file_path, "r", encoding="utf-8") as handle:
        text = handle.read().strip()
        if not text:
            return terms

    with open(file_path, "r", encoding="utf-8", newline="") as handle:
        try:
            reader = csv.reader(handle)
            for row in reader:
                if not row:
                    continue
                value = str(row[0]).strip()
                if value and value.lower() != "term":
                    terms.append(value)
        except csv.Error:
            pass

    if not terms:
        with open(file_path, "r", encoding="utf-8") as handle:
            for line in handle:
                value = line.strip()
                if value:
                    terms.append(value)

    return terms


def search_urls_for_terms(terms: Iterable[str], max_results: int = 5) -> List[str]:
    urls: List[str] = []
    with DDGS() as ddgs:
        for term in terms:
            for result in ddgs.text(term, max_results=max_results):
                url = result.get("href") or result.get("url") or result.get("link")
                if url:
                    urls.append(url)
    return list(dict.fromkeys(urls))
