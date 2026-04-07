import os
from bs4 import BeautifulSoup
import requests
import argparse
import csv
from urllib.parse import urlparse
import urllib3
from datetime import datetime, timedelta
import json

DATA_DIR = "data"
LAST_ANALYSIS_FILE = ".last_analysis_time.json"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
}
PHISHTANK_CSV_URL = "http://data.phishtank.com/data/online-valid.csv"
PHISHTANK_HEADERS = {
    "User-Agent": "phishtank"
}

os.makedirs(DATA_DIR, exist_ok=True)


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

def extract_and_fetch_scripts(html, base_url):
    """Extract external script sources and fetch their content."""
    soup = BeautifulSoup(html, 'html.parser')
    js_scripts = []
    for script in soup.find_all('script'):
        if script.get('src'):
            src = script['src']
            js_url = src if src.startswith('http') else urlparse(base_url)._replace(path=src).geturl()
            try:
                js_resp = requests.get(js_url, headers=HEADERS, timeout=5, verify=False)
                js_scripts.append(js_resp.text)
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
        js_scripts = extract_and_fetch_scripts(html, url)
        return html, js_scripts, status_code, redirect_count, final_url
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        raise Exception(f"Failed to fetch {url}: {e}")

def create_entry(url, final_url, status_code, redirect_count, html_file='', js_file='', error=False, error_message=''):
    """Create a metadata entry dictionary."""
    return {
        'url': url,
        'final_url': final_url,
        'status_code': status_code,
        'redirect_count': redirect_count,
        'html_file': html_file,
        'js_file': js_file,
        'error': error,
        'error_message': error_message
    }

def save_data(url, html, js_scripts, status_code, redirect_count, final_url):
    """Save HTML and JS files, return metadata entry."""
    safe_url = url.replace('://', '_').replace('/', '_')
    
    if status_code >= 400:
        entry = create_entry(
            url=url,
            final_url=final_url,
            status_code=status_code,
            redirect_count=redirect_count
        )
    else:
        # Save HTML file
        with open(os.path.join(DATA_DIR, f'{safe_url}.html'), 'w', encoding='utf-8') as f:
            f.write(html)
        
        # Save JS files
        js_file = f'{safe_url}.js' if len(js_scripts) > 0 else ''
        if js_file:
            with open(os.path.join(DATA_DIR, js_file), 'w', encoding='utf-8') as f:
                for js_code in js_scripts:
                    f.write(js_code)
        
        entry = create_entry(
            url=url,
            final_url=final_url,
            status_code=status_code,
            redirect_count=redirect_count,
            html_file=f'{safe_url}.html',
            js_file=js_file
        )
    
    return entry

def main():
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
    
    dataset_entries = []
    
    for idx, url in enumerate(urls[:total]):
        print(f"[{idx+1}/{total}] Processing: {url}")
        try:
            html, js_scripts, status_code, redirect_count, final_url = fetch_website(url)
            entry = save_data(url=url, html=html, js_scripts=js_scripts, status_code=status_code, redirect_count=redirect_count, final_url=final_url)
            dataset_entries.append(entry)
        except Exception as e:
            print(f"Error processing {url}: {e}")
            entry = create_entry(
                url=url,
                error=True,
                error_message=str(e)
            )
            dataset_entries.append(entry)
    
    csv_file = os.path.join(DATA_DIR, 'dataset.csv')
    if dataset_entries:
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['url', 'final_url', 'status_code', 'redirect_count', 'html_file', 'js_file', 'error', 'error_message'])
            writer.writeheader()
            writer.writerows(dataset_entries)
        print(f"\nMetadata saved to {csv_file}")
        
        # Save the current analysis timestamp
        current_time = datetime.now(datetime.now().astimezone().tzinfo).isoformat()
        save_last_analysis_time(current_time)
        print(f"Analysis timestamp saved. Next time, use --use-last to continue from here.")

if __name__ == "__main__":
    urllib3.disable_warnings()
    main()
