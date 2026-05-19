import argparse
import csv
import json
import sys
from datetime import datetime, timezone

from ddgs import DDGS


def generate_session_id():
    now_utc = datetime.now(timezone.utc)
    return now_utc.strftime("%Y%m%d_%H%M%S")


def read_urls_from_file(path):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    if not content:
        return []

    try:
        data = json.loads(content)
        if not isinstance(data, list):
            raise ValueError("JSON input must be an array of URL strings.")

        urls = []
        for item in data:
            if isinstance(item, str):
                url = item.strip()
                if url:
                    urls.append(url)
            elif isinstance(item, dict) and "url" in item and isinstance(item["url"], str):
                url = item["url"].strip()
                if url:
                    urls.append(url)
        return urls
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in input file: {e}") from e


def read_terms_from_csv(path):
    terms = []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return terms
        if "Tendencias" not in reader.fieldnames:
            raise ValueError("CSV must include a 'Tendencias' column.")
        for row in reader:
            value = (row.get("Tendencias") or "").strip()
            if value:
                terms.append(value)
    return terms


def read_terms_from_file(path):
    lower_path = path.lower()
    if lower_path.endswith(".csv"):
        return read_terms_from_csv(path)
    terms = read_urls_from_file(path)
    return [t for t in terms if t]


def search_duckduckgo(term, max_results=10, timeout=10):
    results = []
    ddgs = DDGS(timeout=timeout)
    for result in ddgs.text(term, max_results=max_results):
        url = result.get("href") or result.get("url")
        if url and url not in results:
            results.append(url)
        if len(results) >= max_results:
            break
    return results


def main():
    parser = argparse.ArgumentParser(description="Search DuckDuckGo for terms and save URLs")
    parser.add_argument(
        "--file",
        required=True,
        help="Input file: JSON array or CSV with a Tendencias column",
    )
    parser.add_argument(
        "--results-per-term",
        type=int,
        default=10,
        help="Max URLs to fetch per search term",
    )
    parser.add_argument(
        "--output",
        help="Output JSON file for collected URLs",
    )
    args = parser.parse_args()

    try:
        terms = read_terms_from_file(args.file)
    except ValueError as e:
        print(f"Error reading search terms file: {e}")
        sys.exit(1)

    if not terms:
        print("No search terms to process.")
        return

    urls = []
    total_terms = len(terms)
    for idx, term in enumerate(terms, start=1):
        print(f"[{idx}/{total_terms}] Searching DuckDuckGo: {term}")
        try:
            results = search_duckduckgo(term, max_results=args.results_per_term)
            urls.extend(results)
            print(f"  Found {len(results)} URLs")
        except Exception as e:
            print(f"Warning: search failed for '{term}': {e}")

    unique_urls = []
    seen = set()
    for url in urls:
        if url and url not in seen:
            seen.add(url)
            unique_urls.append(url)

    output_path = args.output
    if not output_path:
        session_id = generate_session_id()
        output_path = f"search_urls_{session_id}.json"

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(unique_urls, f, ensure_ascii=False, indent=2)

    print(f"Saved {len(unique_urls)} URLs to {output_path}")


if __name__ == "__main__":
    main()
