import os
import requests
import argparse
import csv
from urllib.parse import urlparse
import urllib3

DATA_DIR = "data"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
}

os.makedirs(DATA_DIR, exist_ok=True)


def read_urls_from_file(path):
    urls = []
    with open(path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            urls.append(row['url'])
    return urls

def fetch_html_and_js(url):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        html = resp.text
        status_code = resp.status_code

        return html, status_code
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        raise Exception(f"Failed to fetch {url}: {e}")

def save_data(url, html, status_code):
    safe_url = url.replace('://', '_').replace('/', '_')
    if status_code >= 400:
        entry = {
            'url': url,
            'status_code': status_code,
            'html_file': '',
            'error': False,
            'error_message': ''
        }
    else:
        entry = {
            'url': url,
            'status_code': status_code,
            'html_file': f'{safe_url}.html',
            'error': False,
            'error_message': ''
        }
        with open(os.path.join(DATA_DIR, f'{safe_url}.html'), 'w', encoding='utf-8') as f:
            f.write(html)

    return entry

def main():
    parser = argparse.ArgumentParser(description='Collect phishing dataset from URL list')
    parser.add_argument('--file', required=True, help='Input file containing URLs')
    parser.add_argument('--limit', type=int, default=10, help='Max URLs to process')
    parser.add_argument('--format', choices=['phishtank'], default='phishtank', help='Input format (default: phishtank)')
    parser.add_argument('-a', '--all', action='store_true') 
    args = parser.parse_args()

    if args.format == 'phishtank':
        print("Reading URLs from PhishTank CSV...")
        urls = read_urls_from_file(args.file)
    else:
        print("Not implemented yet for url_list format")
        exit(1)

    urls = [u for u in urls if u]
    if args.all:
        total = len(urls)
    else: 
        total = min(args.limit, len(urls))
    
    metadata_entries = []
    urllib3.disable_warnings()

    for idx, url in enumerate(urls[:total]):
        print(f"[{idx+1}/{total}] Processing: {url}")
        try:
            html, status_code = fetch_html_and_js(url)
            entry = save_data(url=url, html=html, status_code=status_code)
            metadata_entries.append(entry)
        except Exception as e:
            print(f"Error processing {url}: {e}")
            entry = {
                'url': url,
                'status_code': None,
                'html_file': '',
                'error': True,
                'error_message': str(e)
            }
            metadata_entries.append(entry)
    
    csv_file = os.path.join(DATA_DIR, 'metadata.csv')
    if metadata_entries:
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['url', 'status_code', 'html_file', 'error', 'error_message'])
            writer.writeheader()
            writer.writerows(metadata_entries)
        print(f"\nMetadata saved to {csv_file}")

if __name__ == "__main__":
    main()
