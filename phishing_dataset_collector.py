import os
import requests
import argparse
import csv
from urllib.parse import urlparse
import urllib3
from bs4 import BeautifulSoup

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
        soup = BeautifulSoup(html, 'html.parser')
        js_scripts = []
        # Inline JS
        for script in soup.find_all('script'):
            if script.string:
                js_scripts.append(script.string)
            elif script.get('src'):
                src = script['src']
                js_url = src if src.startswith('http') else urlparse(url)._replace(path=src).geturl()
                try:
                    js_resp = requests.get(js_url, headers=HEADERS, timeout=5, verify=False)
                    js_scripts.append(js_resp.text)
                except Exception as e:
                    js_scripts.append(f"// Error fetching {src}: {e}")
        return html, js_scripts, status_code
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        raise Exception(f"Failed to fetch {url}: {e}")

def save_data(url, html, js, status_code):
    safe_url = url.replace('://', '_').replace('/', '_')
    if status_code >= 400:
        entry = {
            'url': url,
            'status_code': status_code,
            'html_file': '',
            'js_files': '',
            'error': False,
            'error_message': ''
        }
    else:
        js_files = f'{safe_url}_js.js'
        entry = {
            'url': url,
            'status_code': status_code,
            'html_file': f'{safe_url}.html',
            'js_files': js_files,
            'error': False,
            'error_message': ''
        }
        with open(os.path.join(DATA_DIR, f'{safe_url}.html'), 'w', encoding='utf-8') as f:
            f.write(html)
        if len(js) > 0:
            with open(os.path.join(DATA_DIR, f'{safe_url}.js'), 'w', encoding='utf-8') as f:
                for js_code in js:
                    f.write(js_code)

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
            html, js, status_code = fetch_html_and_js(url)
            entry = save_data(url=url, html=html, js=js, status_code=status_code)
        except Exception as e:
            print(f"Error processing {url}: {e}")
            entry = {
                'url': url,
                'status_code': None,
                'html_file': '',
                'js_files': '',
                'error': True,
                'error_message': str(e)
            }
        metadata_entries.append(entry)
    
    csv_file = os.path.join(DATA_DIR, 'metadata.csv')
    if metadata_entries:
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['url', 'status_code', 'html_file', 'js_files'])
            writer.writeheader()
            writer.writerows(metadata_entries)
        print(f"\nMetadata saved to {csv_file}")

if __name__ == "__main__":
    main()
