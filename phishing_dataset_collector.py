import os
from bs4 import BeautifulSoup
import requests
import argparse
import csv
from urllib.parse import urlparse
import urllib3
from datetime import datetime, timedelta
import json
import hashlib
import signal
import sys

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

# Global state for graceful shutdown
_dataset_entries = []
_script_cache = {}
_current_total = 0

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(HTML_DIR, exist_ok=True)
os.makedirs(SCRIPT_DIR, exist_ok=True)


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

def load_script_cache():
    """Load the script cache mapping (hash -> filename)."""
    if os.path.exists(SCRIPT_CACHE_FILE):
        try:
            with open(SCRIPT_CACHE_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load script cache: {e}")
    return {}

def save_script_cache(cache):
    """Save the script cache mapping."""
    try:
        with open(SCRIPT_CACHE_FILE, 'w') as f:
            json.dump(cache, f)
    except Exception as e:
        print(f"Warning: Could not save script cache: {e}")

def get_script_hash(content):
    """Calculate SHA256 hash of script content."""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def extract_script_name(src_url):
    """Extract a meaningful filename from script src URL."""
    # Handle inline scripts
    if not src_url or src_url.startswith('data:'):
        return None
    
    # Parse the URL
    parsed = urlparse(src_url)
    
    # Get the filename from the path
    filename = os.path.basename(parsed.path)
    
    # If no filename, use the domain
    if not filename or filename == '':
        filename = parsed.netloc.replace('.', '_')
    
    # Handle query strings - remove them but keep the base filename
    if '?' in filename:
        filename = filename.split('?')[0]
    
    # Ensure it ends with .js
    if not filename.endswith('.js'):
        filename += '.js'
    
    return filename

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

def extract_and_fetch_scripts(html, base_url):
    """Extract external script sources and fetch their content.
    
    Returns:
        List of tuples: (script_src, script_content)
    """
    soup = BeautifulSoup(html, 'html.parser')
    js_scripts = []
    
    for script in soup.find_all('script'):
        if script.get('src'):
            src = script['src']
            js_url = src if src.startswith('http') else urlparse(base_url)._replace(path=src).geturl()
            try:
                js_resp = requests.get(js_url, headers=HEADERS, timeout=5, verify=False)
                js_scripts.append((src, js_resp.text))
            except Exception as e:
                print(f"// Error fetching {src}: {e}")
    
    return js_scripts

def fetch_website(url):
    """Fetch website HTML and associated JavaScript files."""
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        html = resp.text
        status_code = resp.status_code
        redirect_count = len(resp.history)
        final_url = resp.url
        reason = resp.reason
        js_scripts = extract_and_fetch_scripts(html, url)
        return html, js_scripts, status_code, redirect_count, final_url, reason
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        raise Exception(f"Failed to fetch {url}: {e}")

def create_entry(url, final_url, status_code, redirect_count, html_file='', js_files=None, reason='', error=False, error_message=''):
    """Create a metadata entry dictionary.
    
    Args:
        js_files: List of JS file paths referenced by this URL
        reason: HTTP response reason phrase
    """
    if js_files is None:
        js_files = []
    
    return {
        'url': url,
        'final_url': final_url,
        'status_code': status_code,
        'reason': reason,
        'redirect_count': redirect_count,
        'html_file': html_file,
        'js_files': '|'.join(js_files),  # Store as pipe-separated list
        'error': error,
        'error_message': error_message
    }

def save_dataset_to_csv():
    """Save collected dataset entries to CSV file."""
    global _dataset_entries
    
    if not _dataset_entries:
        print("No data to save.")
        return
    
    csv_file = os.path.join(DATA_DIR, 'dataset.csv')
    try:
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['url', 'final_url', 'status_code', 'reason', 'redirect_count', 'html_file', 'js_files', 'error', 'error_message'])
            writer.writeheader()
            writer.writerows(_dataset_entries)
        print(f"\n✓ Metadata saved to {csv_file} ({len(_dataset_entries)} entries)")
    except Exception as e:
        print(f"\n✗ Error saving dataset: {e}")

def save_and_exit(signum=None, frame=None):
    """Signal handler for graceful shutdown (Ctrl+C)."""
    print("\n\nReceived interrupt signal. Saving progress...")
    
    # Save script cache
    save_script_cache(_script_cache)
    print(f"✓ Script cache updated with {len(_script_cache)} total entries")
    
    # Save dataset
    save_dataset_to_csv()
    
    # Save the current analysis timestamp
    current_time = datetime.now(datetime.now().astimezone().tzinfo).isoformat()
    save_last_analysis_time(current_time)
    print(f"✓ Analysis timestamp saved.")
    
    print(f"\nProcessed {len(_dataset_entries)} out of {_current_total} URLs before interruption.")
    print("Use --use-last to continue from here next time.")
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
    global _dataset_entries, _script_cache, _current_total
    
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
    current_time = datetime.now(datetime.now().astimezone().tzinfo).isoformat()
    save_last_analysis_time(current_time)
    print(f"✓ Analysis timestamp saved. Next time, use --use-last to continue from here.")

if __name__ == "__main__":
    urllib3.disable_warnings()
    main()
