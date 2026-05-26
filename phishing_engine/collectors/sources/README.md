# `collectors/sources/` — URL-list sources

Pull lists of URLs (with a label) from external feeds. Each module is a thin fetcher; the
`collect` CLI is what actually stores the results to MongoDB.

| File | Label | What it returns |
|------|-------|-----------------|
| `phishtank.py` | `phish` | `fetch_phishtank_urls(limit, days, since)` — verified phishing URLs from the PhishTank online-valid feed, optionally time-filtered. |
| `tranco.py` | `benign` | `load_tranco_domains(path)` / `sample_tranco_domains(path, n, seed)` — a random sample of domains from a Tranco top-sites list. |
| `search.py` | `benign` | `load_search_terms(file)` / `iter_search_results(terms, max_results)` — yields `(term, urls)` per term (benign URLs from DuckDuckGo via `ddgs`); isolates per-term failures and stops on a rate-limit streak so `collect search` can resume. |

These produce only `(url, label, source)`; the per-URL raw data (domain record, page content) is filled in automatically by the `collect` CLI after the URLs are stored.
