from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from phishing_engine.config import load_config
from phishing_engine.pipeline import Pipeline
from phishing_engine.registry import build_stages
from phishing_engine.storage.mongo import MongoStore
from phishing_engine.utils import result_to_dict
from phishing_engine.collectors.phishtank import fetch_phishtank_urls
from phishing_engine.collectors.tranco import sample_tranco_domains
from phishing_engine.collectors.search_terms import load_search_terms, search_urls_for_terms

import phishing_engine.stages  # noqa: F401


def build_pipeline(config_path: str, no_store: bool) -> Pipeline:
    config = load_config(config_path)
    stages = build_stages(config.pipeline.stages)
    store = None
    if not no_store:
        mongo = config.pipeline.mongo
        store = MongoStore(
            mongo.uri,
            mongo.database,
            mongo.collection,
            benign_collection=mongo.benign_collection,
            phish_collection=mongo.phish_collection,
        )
    return Pipeline(stages, store=store)


def cmd_predict(args) -> int:
    pipeline = build_pipeline(args.config, args.no_store)
    try:
        result = pipeline.run(args.url, mode="predict")
        print(json.dumps(result_to_dict(result), indent=2))
    finally:
        if pipeline.store:
            pipeline.store.close()
    return 0


def _collect_urls(urls: List[str], pipeline: Pipeline, label: str, source: str, limit: Optional[int]):
    count = 0
    for url in urls:
        pipeline.run(url, mode="collect", label=label, source=source)
        count += 1
        if limit and count >= limit:
            break


def cmd_collect_phishtank(args) -> int:
    pipeline = build_pipeline(args.config, args.no_store)
    try:
        urls = fetch_phishtank_urls(limit=args.limit, days=args.days, since=args.since)
        _collect_urls(urls, pipeline, label="phish", source="phishtank", limit=args.limit)
    finally:
        if pipeline.store:
            pipeline.store.close()
    return 0


def cmd_collect_tranco(args) -> int:
    pipeline = build_pipeline(args.config, args.no_store)
    try:
        domains = sample_tranco_domains(args.list_path, args.sample_size, seed=args.seed)
        urls = [f"http://{domain}" for domain in domains]
        _collect_urls(urls, pipeline, label="benign", source="tranco", limit=args.sample_size)
    finally:
        if pipeline.store:
            pipeline.store.close()
    return 0


def cmd_collect_search(args) -> int:
    pipeline = build_pipeline(args.config, args.no_store)
    try:
        terms = load_search_terms(args.terms_file)
        if args.limit_terms:
            terms = terms[: args.limit_terms]
        urls = search_urls_for_terms(terms, max_results=args.max_results)
        _collect_urls(urls, pipeline, label="benign", source="search", limit=args.limit_urls)
    finally:
        if pipeline.store:
            pipeline.store.close()
    return 0


def cmd_train(args) -> int:
    print("Training pipeline not implemented yet.")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Phishing detection engine CLI")
    parser.add_argument(
        "--config",
        default="config/pipeline.json",
        help="Path to pipeline config JSON",
    )
    parser.add_argument(
        "--no-store",
        action="store_true",
        help="Disable MongoDB storage",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    predict_parser = subparsers.add_parser("predict", help="Score a single URL")
    predict_parser.add_argument("--url", required=True, help="URL to score")
    predict_parser.set_defaults(func=cmd_predict)

    collect_parser = subparsers.add_parser("collect", help="Collect data for training")
    collect_sub = collect_parser.add_subparsers(dest="collector", required=True)

    phishtank_parser = collect_sub.add_parser("phishtank", help="Collect from PhishTank feed")
    phishtank_parser.add_argument("--days", type=int, default=None, help="Collect URLs from last N days")
    phishtank_parser.add_argument("--since", default=None, help="Collect URLs since ISO timestamp")
    phishtank_parser.add_argument("--limit", type=int, default=None, help="Max number of URLs to collect")
    phishtank_parser.set_defaults(func=cmd_collect_phishtank)

    tranco_parser = collect_sub.add_parser("tranco", help="Collect benign domains from Tranco list")
    tranco_parser.add_argument("--list-path", required=True, help="Path to Tranco list file")
    tranco_parser.add_argument("--sample-size", type=int, default=100, help="Number of domains to sample")
    tranco_parser.add_argument("--seed", type=int, default=None, help="Random seed")
    tranco_parser.set_defaults(func=cmd_collect_tranco)

    search_parser = collect_sub.add_parser("search", help="Collect benign URLs from search terms")
    search_parser.add_argument("--terms-file", required=True, help="Path to search terms file")
    search_parser.add_argument("--limit-terms", type=int, default=None, help="Limit number of search terms")
    search_parser.add_argument("--max-results", type=int, default=10, help="Max results per term")
    search_parser.add_argument("--limit-urls", type=int, default=None, help="Max URLs to collect")
    search_parser.set_defaults(func=cmd_collect_search)

    train_parser = subparsers.add_parser("train", help="Train or retrain models")
    train_parser.set_defaults(func=cmd_train)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
