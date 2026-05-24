"""Collectors CLI — the ONLY component that writes raw data to MongoDB.

Each subcommand is self-contained and designed to be driven by a cronjob:

    # URL-list sources. As each URL is collected it is stored and its raw
    # data (domain record + page content)
    python -m phishing_engine.cli.collect phishtank --limit 1000
    python -m phishing_engine.cli.collect tranco --list-path tranco.csv --sample-size 500
    python -m phishing_engine.cli.collect search --terms-file terms.txt --max-results 10

Example crontab:
    */30 * * * * cd /srv/engine && python -m phishing_engine.cli.collect phishtank --limit 2000
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from phishing_engine.core.config import load_config
from phishing_engine.storage.mongo import MongoStore

_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "GeoLite2-DB"
DEFAULT_CITY_DB = str(_DATA_DIR / "GeoLite2-City.mmdb")
DEFAULT_ASN_DB = str(_DATA_DIR / "GeoLite2-ASN.mmdb")


def _store(args) -> MongoStore:
    """Open the MongoStore described by the config (the collectors' write handle)."""
    mongo = load_config(args.config).pipeline.mongo
    return MongoStore(mongo.uri, mongo.database, mongo.collection)


def cmd_phishtank(args) -> int:
    """Fetch phishing URLs from PhishTank, store them, and collect their raw data inline."""
    from phishing_engine.collectors.sources.phishtank import fetch_phishtank_urls

    store = _store(args)
    try:
        urls = fetch_phishtank_urls(limit=args.limit, days=args.days, since=args.since)
        _ingest(store, urls, label="phish", source="phishtank", limit=args.limit, args=args)
    finally:
        store.close()
    return 0


def cmd_tranco(args) -> int:
    """Sample benign domains from a Tranco list, store them, and collect their raw data inline."""
    from phishing_engine.collectors.sources.tranco import sample_tranco_domains

    store = _store(args)
    try:
        domains = sample_tranco_domains(args.list_path, args.sample_size, seed=args.seed)
        urls = [f"https://{domain}" for domain in domains]
        _ingest(store, urls, label="benign", source="tranco", limit=args.sample_size, args=args)
    finally:
        store.close()
    return 0


def cmd_search(args) -> int:
    """Search the given terms, store the benign URLs, and collect their raw data inline."""
    from phishing_engine.collectors.sources.search import load_search_terms, search_urls_for_terms

    store = _store(args)
    try:
        terms = load_search_terms(args.terms_file)
        if args.limit_terms:
            terms = terms[: args.limit_terms]
        urls = search_urls_for_terms(terms, max_results=args.max_results)
        _ingest(store, urls, label="benign", source="search", limit=args.limit_urls, args=args)
    finally:
        store.close()
    return 0


def _collect_for_url(store, url, normalized, args) -> tuple[bool, bool]:
    """Collect & store the raw domain record and page content for one freshly stored URL.

    The two fetches are independent — a failure on
    one is logged and skipped so the rest of the run keeps going.
    """
    from phishing_engine.collectors.content import collect_content
    from phishing_engine.collectors.domain_record import collect_domain_record_sync

    domain_ok = False
    try:
        record = collect_domain_record_sync(
            url,
            timeout=args.timeout,
            geoip_city_db=args.geoip_city_db,
            geoip_asn_db=args.geoip_asn_db,
            rtt_enabled=args.rtt,
        )
        store.store_domain_record(normalized, record)
        domain_ok = True
    except Exception as exc:
        print(f"collect-domain: failed {url}: {exc}", file=sys.stderr)

    content_ok = False
    try:
        content = collect_content(url, tls_timeout=args.tls_timeout, max_html_bytes=args.max_html_bytes)
        store.store_content(normalized, content)
        content_ok = True
    except Exception as exc:
        print(f"collect-content: failed {url}: {exc}", file=sys.stderr)

    return domain_ok, content_ok


def _ingest(store, urls, *, label, source, limit, args) -> int:
    """Store each URL and immediately collect its raw domain record + page content."""
    stored = 0
    domain_ok = 0
    content_ok = 0
    for url in urls:
        if not url:
            continue
        normalized = store.add_url(url, label=label, source=source)
        d, c = _collect_for_url(store, url, normalized, args)
        domain_ok += d
        content_ok += c
        stored += 1
        if limit and stored >= limit:
            break
    print(f"{source}: stored {stored} URLs (domain {domain_ok}, content {content_ok})")
    return stored


def _add_domain_collect_args(p) -> None:
    """Add the domain-record collection options used by inline enrichment."""
    p.add_argument("--timeout", type=float, default=5.0, help="DNS/RDAP timeout (s)")
    p.add_argument("--geoip-city-db", default=DEFAULT_CITY_DB, help="GeoLite2 City DB path")
    p.add_argument("--geoip-asn-db", default=DEFAULT_ASN_DB, help="GeoLite2 ASN DB path")
    p.add_argument("--rtt", action="store_true", help="Enable ICMP RTT measurement")


def _add_content_collect_args(p) -> None:
    """Add the page-content collection options used by inline enrichment."""
    p.add_argument("--tls-timeout", type=float, default=10.0, help="TLS handshake timeout (s)")
    p.add_argument("--max-html-bytes", type=int, help="Max HTML bytes to store")


def _add_collect_args(p) -> None:
    """Add the collection tuning options to a URL-collection subcommand."""
    _add_domain_collect_args(p)
    _add_content_collect_args(p)


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser with one subcommand per collector."""
    parser = argparse.ArgumentParser(description="Phishing detection — data collectors (write raw data to MongoDB)")
    parser.add_argument("--config", default="config/pipeline.json", help="Path to pipeline config JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("phishtank", help="Collect phishing URLs from PhishTank")
    p.add_argument("--days", type=int, default=None, help="Only URLs verified in the last N days")
    p.add_argument("--since", default=None, help="Only URLs verified since ISO timestamp")
    p.add_argument("--limit", type=int, default=None, help="Max URLs to collect")
    _add_collect_args(p)
    p.set_defaults(func=cmd_phishtank)

    p = sub.add_parser("tranco", help="Collect benign domains from a Tranco list")
    p.add_argument("--list-path", required=True, help="Path to Tranco list file")
    p.add_argument("--sample-size", type=int, default=100, help="Number of domains to sample")
    p.add_argument("--seed", type=int, default=None, help="Random seed")
    _add_collect_args(p)
    p.set_defaults(func=cmd_tranco)

    p = sub.add_parser("search", help="Collect benign URLs from search terms")
    p.add_argument("--terms-file", required=True, help="Path to search terms file")
    p.add_argument("--limit-terms", type=int, default=None, help="Limit number of search terms")
    p.add_argument("--max-results", type=int, default=10, help="Max results per term")
    p.add_argument("--limit-urls", type=int, default=None, help="Max URLs to collect")
    _add_collect_args(p)
    p.set_defaults(func=cmd_search)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint: dispatch to the chosen collector subcommand."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
