import argparse
import csv
import json
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

import pandas as pd
from pycrtsh import Crtsh


def get_root_domain(hostname):
    if not hostname:
        return hostname

    hostname = hostname.strip(".").lower()
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def extract_unique_https_domains(dataset_path):
    dataset = pd.read_csv(dataset_path)
    if "url" not in dataset.columns:
        raise ValueError(f"Missing 'url' column in {dataset_path}")

    seen_domains = set()
    domain_sources = {}

    for url in dataset["url"]:
        if not (isinstance(url, str) and url.strip() and url.lower().startswith("https://")):
            continue

        hostname = urlparse(url).netloc.split("@")[ -1].split(":")[0].lower()
        domain = get_root_domain(hostname)
        if not domain or domain in seen_domains:
            continue

        seen_domains.add(domain)
        domain_sources[domain] = url

    return domain_sources


def load_domain_cache(cache_path):
    if not os.path.exists(cache_path):
        return set()

    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cached_domains = data.get("searched_domains", [])
        return set(d for d in cached_domains if isinstance(d, str) and d.strip())
    except Exception as e:
        print(f"Warning: failed to read cache file {cache_path}: {e}")
        return set()


def save_domain_cache(cache_path, searched_domains):
    cache_dir = os.path.dirname(cache_path)
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
    payload = {
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "count": len(searched_domains),
        "searched_domains": sorted(searched_domains),
    }
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def save_results(output_dir, cert_results, domain_sources):
    os.makedirs(output_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(output_dir, f"crtsh_results_{stamp}.json")
    summary_path = os.path.join(output_dir, f"crtsh_summary_{stamp}.csv")

    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "searched_domains": len(cert_results),
        "results": cert_results,
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["domain", "source_url", "cert_count", "status", "error"],
        )
        writer.writeheader()
        for domain, data in cert_results.items():
            writer.writerow(
                {
                    "domain": domain,
                    "source_url": domain_sources.get(domain, ""),
                    "cert_count": len(data.get("certs", [])),
                    "status": data.get("status", "unknown"),
                    "error": data.get("error", ""),
                }
            )

    return json_path, summary_path


def main():
    parser = argparse.ArgumentParser(
        description="Search crt.sh for unique HTTPS root domains in a dataset and save all certificate results."
    )
    parser.add_argument(
        "--dataset",
        default="data/dataset_20260412_203835.csv",
        help="Path to CSV dataset containing a 'url' column.",
    )
    parser.add_argument(
        "--output-dir",
        default="data/certs",
        help="Directory where crt.sh lookup outputs will be saved.",
    )
    parser.add_argument(
        "--cache-file",
        default="data/certs/searched_domains_cache.json",
        help="Path to persistent cache file for already-searched domains.",
    )
    parser.add_argument(
        "--ignore-cache",
        action="store_true",
        help="If set, search all domains even if they are in cache.",
    )
    args = parser.parse_args()

    domain_sources = extract_unique_https_domains(args.dataset)
    print(f"Unique HTTPS root domains found: {len(domain_sources)}")

    cached_domains = set() if args.ignore_cache else load_domain_cache(args.cache_file)
    domains_to_query = [
        (domain, source_url)
        for domain, source_url in domain_sources.items()
        if args.ignore_cache or domain not in cached_domains
    ]

    print(f"Cached domains loaded: {len(cached_domains)}")
    print(f"Domains to query this run: {len(domains_to_query)}")

    c = Crtsh()
    cert_results = {}

    for i, (domain, source_url) in enumerate(domains_to_query, start=1):
        try:
            certs = c.search(domain)
            cert_results[domain] = {
                "status": "ok",
                "source_url": source_url,
                "certs": certs,
                "error": "",
            }
            cached_domains.add(domain)
            save_domain_cache(args.cache_file, cached_domains)
            print(f"[{i}/{len(domains_to_query)}] {source_url} -> {domain} | crt.sh results: {len(certs)}")
        except Exception as e:
            cert_results[domain] = {
                "status": "error",
                "source_url": source_url,
                "certs": [],
                "error": str(e),
            }
            print(f"[{i}/{len(domains_to_query)}] {source_url} -> {domain} | crt.sh lookup failed: {e}")

    # Persist final cache state even if there were no new domains.
    save_domain_cache(args.cache_file, cached_domains)

    json_path, summary_path = save_results(args.output_dir, cert_results, domain_sources)
    print(f"Saved full certificate results to: {json_path}")
    print(f"Saved lookup summary to: {summary_path}")
    print(f"Saved domain cache to: {args.cache_file}")


if __name__ == "__main__":
    main()