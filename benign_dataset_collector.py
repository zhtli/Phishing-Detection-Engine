import os
import argparse
import csv
import json
import signal
import sys
import urllib3
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

from web_fetch import (
    get_script_hash,
    extract_script_name,
    fetch_website,
    save_certificate_file,
)

DATA_DIR = "benign_data"
SCRIPT_DIR = f"{DATA_DIR}/JS"
HTML_DIR = f"{DATA_DIR}/HTML"
CERT_DIR = f"{DATA_DIR}/CERT"
SCRIPT_CACHE_FILE = f"{SCRIPT_DIR}/.script_cache.json"
HTML_CACHE_FILE = f"{HTML_DIR}/.html_cache.json"
CERT_CACHE_FILE = f"{CERT_DIR}/.cert_cache.json"

# User agent profiles to rotate through
PROFILE_MUTATIONS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",  # Desktop
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",  # Android
    "bot",
    "amazonaws",
    "phishtank",
    "google",
    "curl",
]


@dataclass
class DatasetEntry:
    """Model for dataset metadata entries."""

    url: str
    final_url: str = ""
    status_code: int = 0
    reason: str = ""
    redirect_count: int = 0
    html_file: str = ""
    js_files: str = ""  # Pipe-separated list of JS filenames
    cert_file: str = ""
    cert_valid: bool = False
    cert_error_message: str = ""
    user_agent: str = ""  # User agent label used (e.g., 'desktop', 'android', 'bot')
    error: bool = False
    error_message: str = ""

    def to_dict(self) -> dict:
        """Convert entry to dictionary for CSV export."""
        return asdict(self)


# Global state for graceful shutdown
_dataset_entries = []
_script_cache = {}
_html_cache = {}
_cert_cache = {}
_current_total = 0
_session_id = ""

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(HTML_DIR, exist_ok=True)
os.makedirs(SCRIPT_DIR, exist_ok=True)
os.makedirs(CERT_DIR, exist_ok=True)


def generate_session_id():
    """Generate a session ID with UTC timestamp including seconds."""
    now_utc = datetime.now(timezone.utc)
    return now_utc.strftime("%Y%m%d_%H%M%S")


def load_cache(path):
    """Load a JSON cache file, returning an empty dict on failure."""
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load cache {path}: {e}")
    return {}


def save_cache(path, cache):
    """Save cache dictionary to a JSON file."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cache, f)
    except Exception as e:
        print(f"Warning: Could not save cache {path}: {e}")


def read_urls_from_file(path):
    """Read URLs from either a JSON array file"""
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in input file: {e}") from e

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

    urls = []
    for line in content.splitlines():
        url = line.strip()
        if not url or url.startswith("#"):
            continue
        urls.append(url)
    return urls


def get_user_agent_label(user_agent):
    """Map full user agent string to a label for storage."""
    if "Android" in user_agent:
        return "android"
    if "Windows" in user_agent:
        return "desktop"
    return user_agent


def create_entry(
    url,
    final_url="",
    status_code=0,
    redirect_count=0,
    html_file="",
    js_files=None,
    cert_file="",
    cert_valid=False,
    cert_error_message="",
    user_agent="",
    reason="",
    error=False,
    error_message="",
) -> DatasetEntry:
    """Create a metadata entry."""
    if js_files is None:
        js_files = []

    return DatasetEntry(
        url=url,
        final_url=final_url,
        status_code=status_code,
        reason=reason,
        redirect_count=redirect_count,
        html_file=html_file,
        js_files="|".join(js_files),
        cert_file=cert_file,
        cert_valid=cert_valid,
        cert_error_message=cert_error_message,
        user_agent=user_agent,
        error=error,
        error_message=error_message,
    )


def save_dataset_to_csv():
    """Save collected dataset entries to a CSV file."""
    global _dataset_entries, _session_id

    if not _dataset_entries:
        print("No data to save.")
        return

    csv_file = os.path.join(DATA_DIR, f"dataset_{_session_id}.csv")
    try:
        fieldnames = [f.name for f in _dataset_entries[0].__dataclass_fields__.values()]
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows([entry.to_dict() for entry in _dataset_entries])
        print(f"\nDataset saved to {csv_file} ({len(_dataset_entries)} entries)")
    except Exception as e:
        print(f"\nError saving dataset: {e}")


def save_and_exit(signum=None, frame=None):
    """Signal handler for graceful shutdown (Ctrl+C)."""
    print("\n\nReceived interrupt signal. Saving progress...")

    save_cache(SCRIPT_CACHE_FILE, _script_cache)
    print(f"Script cache updated with {len(_script_cache)} total entries")

    save_cache(HTML_CACHE_FILE, _html_cache)
    print(f"HTML cache updated with {len(_html_cache)} total entries")

    save_cache(CERT_CACHE_FILE, _cert_cache)
    print(f"Certificate cache updated with {len(_cert_cache)} total entries")

    save_dataset_to_csv()

    print(f"\nProcessed {len(_dataset_entries)} out of {_current_total} URLs before interruption.")
    sys.exit(0)


def truncate_filename_on_error(filename):
    """Truncate filename to fit within 255 byte filesystem limit."""
    max_length = 255
    if len(filename.encode("utf-8")) <= max_length:
        return filename

    file_hash = get_script_hash(filename)[:8]
    extension = filename[filename.rfind(".") :]
    base_name = filename[: filename.rfind(".")]

    reserved = len(file_hash) + 1 + len(extension)
    max_base = max_length - reserved

    if max_base > 10:
        truncated_base = base_name[:max_base]
        return f"{truncated_base}_{file_hash}{extension}"
    return f"{file_hash}{extension}"


def save_html_file(url, html, html_cache):
    """Save HTML file with deduplication."""
    html_file = ""

    if html:
        html_hash = get_script_hash(html)

        if html_hash in html_cache:
            html_file = html_cache[html_hash]
        else:
            safe_url = url.replace("://", "_").replace("/", "_")
            html_filename = f"{safe_url}.html"

            base_name = safe_url
            counter = 1
            full_filename = html_filename

            while os.path.exists(os.path.join(HTML_DIR, full_filename)):
                full_filename = f"{base_name}_html_{counter}.html"
                counter += 1

            html_filename = full_filename

            try:
                file_path = os.path.join(HTML_DIR, html_filename)
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(html)

                html_cache[html_hash] = html_filename
                html_file = html_filename
            except OSError as e:
                if getattr(e, "errno", None) == 36:
                    html_filename = truncate_filename_on_error(html_filename)
                    try:
                        file_path = os.path.join(HTML_DIR, html_filename)
                        with open(file_path, "w", encoding="utf-8") as f:
                            f.write(html)
                        html_cache[html_hash] = html_filename
                        html_file = html_filename
                    except Exception as retry_err:
                        print(f"  Error saving HTML {html_filename}: {retry_err}")
                else:
                    print(f"  Error saving HTML {html_filename}: {e}")

    return html_file, html_cache


def save_js_files(js_scripts, script_cache):
    """Save JavaScript files with deduplication."""
    saved_js_files = []

    for script_src, script_content in js_scripts:
        if not script_content or not script_content.strip():
            continue

        script_hash = get_script_hash(script_content)

        if script_hash in script_cache:
            saved_js_files.append(script_cache[script_hash])
        else:
            script_filename = extract_script_name(script_src)
            if not script_filename:
                script_filename = "script.js"

            base_name = script_filename[:-3] if script_filename.endswith(".js") else script_filename
            ext = ".js"
            counter = 1
            full_filename = script_filename

            while os.path.exists(os.path.join(SCRIPT_DIR, full_filename)):
                full_filename = f"{base_name}_{counter}{ext}"
                counter += 1

            script_filename = full_filename

            try:
                file_path = os.path.join(SCRIPT_DIR, script_filename)
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(script_content)

                script_cache[script_hash] = script_filename
                saved_js_files.append(script_filename)
            except OSError as e:
                if getattr(e, "errno", None) == 36:
                    script_filename = truncate_filename_on_error(script_filename)
                    try:
                        file_path = os.path.join(SCRIPT_DIR, script_filename)
                        with open(file_path, "w", encoding="utf-8") as f:
                            f.write(script_content)
                        script_cache[script_hash] = script_filename
                        saved_js_files.append(script_filename)
                    except Exception as retry_err:
                        print(f"  Error saving script {script_filename}: {retry_err}")
                else:
                    print(f"  Error saving script {script_filename}: {e}")

    return saved_js_files, script_cache


def save_data(
    url,
    html,
    js_scripts,
    status_code,
    redirect_count,
    final_url,
    reason,
    script_cache,
    html_cache,
    cert_cache,
    user_agent="",
):
    """Save HTML, JS, and certificate files, then return metadata entry."""
    html_file, html_cache = save_html_file(url, html, html_cache)
    saved_js_files, script_cache = save_js_files(js_scripts, script_cache)

    cert_target_url = final_url if final_url else url
    cert_file, cert_valid, cert_error, cert_cache = save_certificate_file(
        cert_target_url,
        cert_cache,
        CERT_DIR,
    )

    entry = create_entry(
        url=url,
        final_url=final_url,
        status_code=status_code,
        redirect_count=redirect_count,
        html_file=html_file,
        js_files=saved_js_files,
        cert_file=cert_file,
        cert_valid=cert_valid,
        cert_error_message=cert_error,
        user_agent=user_agent,
        reason=reason,
    )

    return entry, script_cache, html_cache, cert_cache


def main():
    global _dataset_entries, _script_cache, _html_cache, _cert_cache, _current_total, _session_id

    _session_id = generate_session_id()
    print(f"Session ID: {_session_id}\n")

    signal.signal(signal.SIGINT, save_and_exit)

    parser = argparse.ArgumentParser(description="Collect benign dataset from URL lists")
    parser.add_argument(
        "--file",
        required=True,
        help="Input file: JSON array of URLs or plain text with one URL per line",
    )
    parser.add_argument("--limit", type=int, help="Max URLs to process")
    args = parser.parse_args()

    try:
        urls = read_urls_from_file(args.file)
    except ValueError as e:
        print(f"Error reading URL file: {e}")
        sys.exit(1)
    urls = [u for u in urls if u]

    total = min(args.limit, len(urls)) if args.limit else len(urls)

    if total == 0:
        print("No URLs to process.")
        return

    _current_total = total

    _script_cache = load_cache(SCRIPT_CACHE_FILE)
    print(f"Loaded script cache with {len(_script_cache)} entries")

    _html_cache = load_cache(HTML_CACHE_FILE)
    print(f"Loaded HTML cache with {len(_html_cache)} entries")

    _cert_cache = load_cache(CERT_CACHE_FILE)
    print(f"Loaded certificate cache with {len(_cert_cache)} entries")

    try:
        for idx, url in enumerate(urls[:total]):
            print(f"[{idx + 1}/{total}] Processing: {url}")

            for user_agent in PROFILE_MUTATIONS:
                user_agent_label = get_user_agent_label(user_agent)

                try:
                    html, js_scripts, status_code, redirect_count, final_url, reason = fetch_website(
                        url, user_agent=user_agent
                    )
                    entry, _script_cache, _html_cache, _cert_cache = save_data(
                        url=url,
                        html=html,
                        js_scripts=js_scripts,
                        status_code=status_code,
                        redirect_count=redirect_count,
                        final_url=final_url,
                        reason=reason,
                        script_cache=_script_cache,
                        html_cache=_html_cache,
                        cert_cache=_cert_cache,
                        user_agent=user_agent_label,
                    )
                    _dataset_entries.append(entry)
                except Exception as e:
                    print(f"Warning: {e}")
                    entry = create_entry(
                        url=url,
                        user_agent=user_agent_label,
                        error=True,
                        error_message=str(e),
                    )
                    _dataset_entries.append(entry)

    except KeyboardInterrupt:
        save_and_exit()

    save_cache(SCRIPT_CACHE_FILE, _script_cache)
    print(f"\nScript cache updated with {len(_script_cache)} total entries")

    save_cache(HTML_CACHE_FILE, _html_cache)
    print(f"HTML cache updated with {len(_html_cache)} total entries")

    save_cache(CERT_CACHE_FILE, _cert_cache)
    print(f"Certificate cache updated with {len(_cert_cache)} total entries")

    save_dataset_to_csv()


if __name__ == "__main__":
    urllib3.disable_warnings()
    main()
