import os
import requests
import argparse
import csv
import urllib3
from datetime import datetime, timedelta, timezone
import json
import signal
import sys
from dataclasses import dataclass, asdict
from src_code_manager import (
    load_script_cache,
    save_script_cache,
    get_script_hash,
    extract_script_name,
    fetch_website,
)

DATA_DIR = "data"
SCRIPT_DIR = f"{DATA_DIR}/JS"
HTML_DIR = f"{DATA_DIR}/HTML"
LAST_ANALYSIS_FILE = ".last_analysis_time.json"
SCRIPT_CACHE_FILE = f"{SCRIPT_DIR}/.script_cache.json"  # Maps content hashes to saved filenames
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
}
PHISHTANK_CSV_URL = "http://data.phishtank.com/data/online-valid.csv"
PHISHTANK_HEADERS = {
    "User-Agent": "phishtank"
}

@dataclass
class DatasetEntry:
    """Model for dataset metadata entries."""
    url: str
    final_url: str = ''
    status_code: int = 0
    reason: str = ''
    redirect_count: int = 0
    html_file: str = ''
    js_files: str = ''  # Pipe-separated list of JS filenames
    error: bool = False
    error_message: str = ''
    
    def to_dict(self) -> dict:
        """Convert entry to dictionary for CSV export."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'DatasetEntry':
        """Create entry from dictionary."""
        # Only include fields that exist in the dataclass
        fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in fields}
        return cls(**filtered_data)


# Global state for graceful shutdown
_dataset_entries = []
_script_cache = {}
_current_total = 0
_session_id = ""  # Will be set at runtime with UTC timestamp including seconds

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(HTML_DIR, exist_ok=True)
os.makedirs(SCRIPT_DIR, exist_ok=True)


def generate_session_id():
    """Generate a session ID with UTC timestamp including seconds."""
    now_utc = datetime.now(timezone.utc)
    # Format: YYYYMMDD_HHMMSS (e.g., 20260407_143052)
    return now_utc.strftime("%Y%m%d_%H%M%S")


def download_phishtank_csv():
    """Download the PhishTank online-valid.csv file."""
    try:
        print(f"Downloading PhishTank CSV from {PHISHTANK_CSV_URL}...")
        resp = requests.get(PHISHTANK_CSV_URL, headers=PHISHTANK_HEADERS, timeout=30, verify=False)
        resp.raise_for_status()
        
        output_path = "phishtank-dataset.csv"
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(resp.text)
        
        print(f"PhishTank CSV saved to {output_path}")
        return output_path
    except Exception as e:
        print(f"Error downloading PhishTank CSV: {e}")
        raise Exception(f"Failed to download from {PHISHTANK_CSV_URL}: {e}")


def parse_iso_datetime(datetime_str):
    """Parse ISO 8601 datetime string with timezone."""
    # Handle format like "2026-04-06T10:12:29+00:00"
    return datetime.fromisoformat(datetime_str.replace('Z', '+00:00'))

def get_last_analysis_time():
    """Load the last analysis timestamp from file."""
    if os.path.exists(LAST_ANALYSIS_FILE):
        try:
            with open(LAST_ANALYSIS_FILE, 'r') as f:
                data = json.load(f)
                return data.get('last_time')
        except Exception as e:
            print(f"Warning: Could not load last analysis time: {e}")
    return None

def save_last_analysis_time(timestamp):
    """Save the current analysis timestamp to file."""
    try:
        with open(LAST_ANALYSIS_FILE, 'w') as f:
            json.dump({'last_time': timestamp}, f)
    except Exception as e:
        print(f"Warning: Could not save last analysis time: {e}")



def read_urls_from_file(path, days=None, since=None):
    """
    Read URLs from file with optional time-based filtering.
    
    Args:
        path: Path to CSV file
        days: Process URLs from the last x days (optional)
        since: Process URLs since this timestamp in ISO format (optional)
    
    Returns:
        List of (url, verification_time) tuples filtered by time criteria
    """
    urls_with_time = []
    cutoff_time = None
    
    # Determine cutoff time
    if since:
        try:
            cutoff_time = parse_iso_datetime(since)
            print(f"Filtering URLs since: {cutoff_time}")
        except Exception as e:
            print(f"Error parsing since timestamp: {e}")
            return urls_with_time
    elif days:
        cutoff_time = datetime.now(datetime.now().astimezone().tzinfo) - timedelta(days=days)
        print(f"Filtering URLs from the last {days} days (since: {cutoff_time})")
    
    with open(path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get('url')
            verification_time_str = row.get('verification_time')
            
            if not url:
                continue
            
            # Apply time filtering
            if cutoff_time and verification_time_str:
                try:
                    verification_time = parse_iso_datetime(verification_time_str)
                    if verification_time < cutoff_time:
                        continue
                except Exception as e:
                    print(f"Warning: Could not parse verification_time '{verification_time_str}': {e}")
                    continue
            
            urls_with_time.append((url, verification_time_str))
    
    return urls_with_time



def create_entry(url, final_url='', status_code=0, redirect_count=0, html_file='', js_files=None, reason='', error=False, error_message='') -> DatasetEntry:
    """Create a metadata entry.
    
    Args:
        url: The original URL
        final_url: The final URL after redirects
        status_code: HTTP status code
        redirect_count: Number of redirects
        html_file: Filename of saved HTML file
        js_files: List of JS file paths referenced by this URL
        reason: HTTP response reason phrase
        error: Whether an error occurred
        error_message: Error message if error occurred
    
    Returns:
        DatasetEntry: The created entry model
    """
    if js_files is None:
        js_files = []
    
    return DatasetEntry(
        url=url,
        final_url=final_url,
        status_code=status_code,
        reason=reason,
        redirect_count=redirect_count,
        html_file=html_file,
        js_files='|'.join(js_files),  # Store as pipe-separated list
        error=error,
        error_message=error_message
    )

def save_dataset_to_csv():
    """Save collected dataset entries to CSV file."""
    global _dataset_entries, _session_id
    
    if not _dataset_entries:
        print("No data to save.")
        return
    
    csv_file = os.path.join(DATA_DIR, f'dataset_{_session_id}.csv')
    try:
        # Get fieldnames from the DatasetEntry dataclass
        fieldnames = [f.name for f in _dataset_entries[0].__dataclass_fields__.values()]
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            # Convert DatasetEntry objects to dictionaries
            writer.writerows([entry.to_dict() for entry in _dataset_entries])
        print(f"\nMetadata saved to {csv_file} ({len(_dataset_entries)} entries)")
    except Exception as e:
        print(f"\n✗ Error saving dataset: {e}")

def save_and_exit(signum=None, frame=None):
    """Signal handler for graceful shutdown (Ctrl+C)."""
    print("\n\nReceived interrupt signal. Saving progress...")
    
    # Save script cache
    save_script_cache(_script_cache)
    print(f"Script cache updated with {len(_script_cache)} total entries")
    
    # Save dataset
    save_dataset_to_csv()
    
    # Save the current analysis timestamp
    current_time = datetime.now(datetime.now().astimezone().tzinfo).isoformat()
    save_last_analysis_time(current_time)
    print(f"Analysis timestamp saved.")
    
    print(f"\nProcessed {len(_dataset_entries)} out of {_current_total} URLs before interruption.")
    sys.exit(0)


def save_data(url, html, js_scripts, status_code, redirect_count, final_url, reason, script_cache):
    """Save HTML and JS files, return metadata entry.
    
    Args:
        js_scripts: List of tuples (script_src, script_content)
        reason: HTTP response reason phrase
        script_cache: Dictionary mapping content hashes to saved filenames
    
    Returns:
        Tuple: (entry, updated_script_cache)
    """
    safe_url = url.replace('://', '_').replace('/', '_')
    
    if status_code >= 400:
        entry = create_entry(
            url=url,
            final_url=final_url,
            status_code=status_code,
            redirect_count=redirect_count,
            reason=reason
        )
        return entry, script_cache
    
    # Save HTML file
    with open(os.path.join(HTML_DIR, f'{safe_url}.html'), 'w', encoding='utf-8') as f:
        f.write(html)
    
    # Process and save individual JS files with deduplication
    saved_js_files = []
    
    for script_src, script_content in js_scripts:
        if not script_content or not script_content.strip():
            continue
        
        # Calculate hash for deduplication
        script_hash = get_script_hash(script_content)
        
        # Check if we've already saved this exact script
        if script_hash in script_cache:
            saved_js_files.append(script_cache[script_hash])
        else:
            # Extract meaningful filename from script src
            script_filename = extract_script_name(script_src)
            
            if not script_filename:
                # Fallback for inline/data scripts
                script_filename = f"{safe_url}_inline_{len(saved_js_files)}.js"
            else:
                # Ensure uniqueness in the data directory
                base_name = script_filename[:-3]  # Remove .js
                ext = '.js'
                counter = 1
                full_filename = script_filename
                
                while os.path.exists(os.path.join(SCRIPT_DIR, full_filename)):
                    full_filename = f"{base_name}_{counter}{ext}"
                    counter += 1
                
                script_filename = full_filename
            
            # Save the script file
            try:
                file_path = os.path.join(SCRIPT_DIR, script_filename)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(script_content)
                
                # Update cache
                script_cache[script_hash] = script_filename
                saved_js_files.append(script_filename)
            except Exception as e:
                print(f"  Error saving script {script_filename}: {e}")
    
    entry = create_entry(
        url=url,
        final_url=final_url,
        status_code=status_code,
        redirect_count=redirect_count,
        html_file=f'{safe_url}.html',
        js_files=saved_js_files,
        reason=reason
    )
    
    return entry, script_cache

def main():
    global _dataset_entries, _script_cache, _current_total, _session_id
    
    # Generate session ID with UTC timestamp
    _session_id = generate_session_id()
    print(f"Session ID: {_session_id}\n")
    
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, save_and_exit)
    
    parser = argparse.ArgumentParser(description='Collect phishing dataset from URL list')
    parser.add_argument('--file', help='Input file containing URLs')
    parser.add_argument('--download', action='store_true', help='Download PhishTank CSV from online-valid.csv')
    parser.add_argument('--limit', type=int, default=10, help='Max URLs to process')
    parser.add_argument('--format', choices=['phishtank'], default='phishtank', help='Input format (default: phishtank)')
    parser.add_argument('-a', '--all', action='store_true', help='Process all URLs')
    parser.add_argument('--days', type=int, help='Process URLs from the last x days')
    parser.add_argument('--since', type=str, help='Process URLs since this timestamp (ISO format: 2026-04-06T10:12:29+00:00)')
    parser.add_argument('--use-last', action='store_true', help='Use the last analysis time as reference')
    args = parser.parse_args()

    if args.format == 'phishtank':
        print("Reading URLs from PhishTank CSV...")
        
        # Determine which file to use
        file_path = None
        if args.download:
            file_path = download_phishtank_csv()
        elif args.file:
            file_path = args.file
        else:
            print("Error: Either --file or --download must be provided")
            exit(1)
        
        # Determine time filter
        since_time = None
        if args.use_last:
            since_time = get_last_analysis_time()
            if since_time:
                print(f"Using last analysis time: {since_time}")
            else:
                print("No previous analysis time found. Processing all URLs.")
        elif args.since:
            since_time = args.since
        
        # Read URLs with optional time filtering
        urls_with_time = read_urls_from_file(file_path, days=args.days, since=since_time)
        urls = [url for url, _ in urls_with_time]
    else:
        print("Not implemented yet for other formats")
        exit(1)

    urls = [u for u in urls if u]
    # Process all filtered URLs if using time-based filters or --all flag
    if args.all or args.days or args.since or args.use_last:
        total = len(urls)
    else: 
        total = min(args.limit, len(urls))
    
    if total == 0:
        print("No URLs to process with the given filters.")
        return
    
    _current_total = total
    
    # Load script cache for deduplication
    _script_cache = load_script_cache()
    print(f"Loaded script cache with {len(_script_cache)} entries")
    
    try:
        for idx, url in enumerate(urls[:total]):
            print(f"[{idx+1}/{total}] Processing: {url}")
            try:
                html, js_scripts, status_code, redirect_count, final_url, reason = fetch_website(url)
                entry, _script_cache = save_data(
                    url=url, 
                    html=html, 
                    js_scripts=js_scripts, 
                    status_code=status_code, 
                    redirect_count=redirect_count, 
                    final_url=final_url,
                    reason=reason,
                    script_cache=_script_cache
                )
                _dataset_entries.append(entry)
            except Exception as e:
                print(f"Error processing {url}: {e}")
                entry = create_entry(
                    url=url,
                    error=True,
                    error_message=str(e)
                )
                _dataset_entries.append(entry)
    
    except KeyboardInterrupt:
        # This shouldn't normally trigger since signal handler catches it,
        # but kept as a fallback
        save_and_exit()
    
    # Save script cache
    save_script_cache(_script_cache)
    print(f"\nScript cache updated with {len(_script_cache)} total entries")
    
    # Save dataset
    save_dataset_to_csv()
    
    # Save the current analysis timestamp
    if not args.limit:
        current_time = datetime.now(datetime.now().astimezone().tzinfo).isoformat()
        save_last_analysis_time(current_time)
        print(f"Analysis timestamp saved. Next time, use --use-last to continue from here.")

if __name__ == "__main__":
    urllib3.disable_warnings()
    main()
