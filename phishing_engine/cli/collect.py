"""Collectors CLI — the ONLY component that writes raw data to MongoDB.

Each subcommand is self-contained and designed to be driven by a cronjob:

    # URL-list sources (label + source only)
    python -m phishing_engine.cli.collect phishtank --limit 1000
    python -m phishing_engine.cli.collect tranco --list-path tranco.csv --sample-size 500
    python -m phishing_engine.cli.collect search --terms-file terms.txt --max-results 10

    # Per-URL raw enrichment (stores raw domain records / page content)
    python -m phishing_engine.cli.collect enrich-domain --limit 200
    python -m phishing_engine.cli.collect enrich-content --limit 200

Example crontab:
    */30 * * * * cd /srv/engine && python -m phishing_engine.cli.collect phishtank --limit 2000
    15 * * * *   cd /srv/engine && python -m phishing_engine.cli.collect enrich-domain --limit 300
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
    """Fetch phishing URLs from PhishTank and store them labeled ``phish``."""
    from phishing_engine.collectors.sources.phishtank import fetch_phishtank_urls

    store = _store(args)
    try:
        urls = fetch_phishtank_urls(limit=args.limit, days=args.days, since=args.since)
        count = store.add_urls(urls, label="phish", source="phishtank", limit=args.limit)
        print(f"phishtank: stored {count} URLs")
    finally:
        store.close()
    return 0


def cmd_tranco(args) -> int:
    """Sample benign domains from a Tranco list and store them labeled ``benign``."""
    from phishing_engine.collectors.sources.tranco import sample_tranco_domains

    store = _store(args)
    try:
        domains = sample_tranco_domains(args.list_path, args.sample_size, seed=args.seed)
        urls = [f"http://{domain}" for domain in domains]
        count = store.add_urls(urls, label="benign", source="tranco", limit=args.sample_size)
        print(f"tranco: stored {count} URLs")
    finally:
        store.close()
    return 0


def cmd_search(args) -> int:
    """Search the given terms and store the resulting benign URLs labeled ``benign``."""
    from phishing_engine.collectors.sources.search import load_search_terms, search_urls_for_terms

    store = _store(args)
    try:
        terms = load_search_terms(args.terms_file)
        if args.limit_terms:
            terms = terms[: args.limit_terms]
        urls = search_urls_for_terms(terms, max_results=args.max_results)
        count = store.add_urls(urls, label="benign", source="search", limit=args.limit_urls)
        print(f"search: stored {count} URLs")
    finally:
        store.close()
    return 0


def cmd_enrich_domain(args) -> int:
    """For stored URLs missing a domain record, collect one and store it under raw.domain_record."""
    from phishing_engine.collectors.domain_record import collect_domain_record_sync

    store = _store(args)
    stored = 0
    failed = 0
    try:
        for document in store.iter_missing("domain_record", limit=args.limit):
            url = document.get("url") or document.get("_id")
            try:
                record = collect_domain_record_sync(
                    url,
                    timeout=args.timeout,
                    geoip_city_db=args.geoip_city_db,
                    geoip_asn_db=args.geoip_asn_db,
                    rtt_enabled=args.rtt,
                )
            except Exception as exc:  # cron resilience: skip and continue
                failed += 1
                print(f"enrich-domain: failed {url}: {exc}", file=sys.stderr)
                continue
            store.store_domain_record(document["_id"], record)
            stored += 1
        print(f"enrich-domain: stored {stored}, failed {failed}")
    finally:
        store.close()
    return 0


def cmd_enrich_content(args) -> int:
    """For stored URLs missing page content, fetch HTML+TLS and store it under raw.content."""
    from phishing_engine.collectors.content import collect_content

    store = _store(args)
    stored = 0
    failed = 0
    try:
        for document in store.iter_missing("content", limit=args.limit):
            url = document.get("url") or document.get("_id")
            try:
                content = collect_content(url, tls_timeout=args.tls_timeout, max_html_bytes=args.max_html_bytes)
            except Exception as exc:  # cron resilience: skip and continue
                failed += 1
                print(f"enrich-content: failed {url}: {exc}", file=sys.stderr)
                continue
            store.store_content(document["_id"], content)
            stored += 1
        print(f"enrich-content: stored {stored}, failed {failed}")
    finally:
        store.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser with one subcommand per collector."""
    parser = argparse.ArgumentParser(description="Phishing detection — data collectors (write raw data to MongoDB)")
    parser.add_argument("--config", default="config/pipeline.json", help="Path to pipeline config JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("phishtank", help="Collect phishing URLs from PhishTank")
    p.add_argument("--days", type=int, default=None, help="Only URLs verified in the last N days")
    p.add_argument("--since", default=None, help="Only URLs verified since ISO timestamp")
    p.add_argument("--limit", type=int, default=None, help="Max URLs to collect")
    p.set_defaults(func=cmd_phishtank)

    p = sub.add_parser("tranco", help="Collect benign domains from a Tranco list")
    p.add_argument("--list-path", required=True, help="Path to Tranco list file")
    p.add_argument("--sample-size", type=int, default=100, help="Number of domains to sample")
    p.add_argument("--seed", type=int, default=None, help="Random seed")
    p.set_defaults(func=cmd_tranco)

    p = sub.add_parser("search", help="Collect benign URLs from search terms")
    p.add_argument("--terms-file", required=True, help="Path to search terms file")
    p.add_argument("--limit-terms", type=int, default=None, help="Limit number of search terms")
    p.add_argument("--max-results", type=int, default=10, help="Max results per term")
    p.add_argument("--limit-urls", type=int, default=None, help="Max URLs to collect")
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("enrich-domain", help="Collect & store raw domain records for URLs missing them")
    p.add_argument("--limit", type=int, default=100, help="Max documents to enrich")
    p.add_argument("--timeout", type=float, default=5.0, help="DNS/RDAP timeout (s)")
    p.add_argument("--geoip-city-db", default=DEFAULT_CITY_DB, help="GeoLite2 City DB path")
    p.add_argument("--geoip-asn-db", default=DEFAULT_ASN_DB, help="GeoLite2 ASN DB path")
    p.add_argument("--rtt", action="store_true", help="Enable ICMP RTT measurement")
    p.set_defaults(func=cmd_enrich_domain)

    p = sub.add_parser("enrich-content", help="Collect & store raw page content (HTML+TLS) for URLs missing it")
    p.add_argument("--limit", type=int, default=100, help="Max documents to enrich")
    p.add_argument("--tls-timeout", type=float, default=10.0, help="TLS handshake timeout (s)")
    p.add_argument("--max-html-bytes", type=int, default=500000, help="Max HTML bytes to store")
    p.set_defaults(func=cmd_enrich_content)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint: dispatch to the chosen collector subcommand."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
