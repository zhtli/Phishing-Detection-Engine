import os
import requests
import argparse
import sys
import csv
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import json

DATA_DIR = "data"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
}

os.makedirs(DATA_DIR, exist_ok=True)


def read_urls_from_file(path):
    if path == "-":
        content = sys.stdin.read()
        file_obj = content.splitlines()
    else:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        file_obj = content.splitlines()
    
    urls = []
    
    reader = csv.reader(file_obj)
    for row in reader:
        url = row[1].strip().strip('"')
        if url:
            urls.append(url)

    
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
        return '', [f'// Error fetching HTML/JS: {e}'], None

def save_data(url, html, js, status_code=None):
    safe_url = url.replace('://', '_').replace('/', '_')
    entry = {
        'url': url,
        'status_code': status_code,
        'html_file': f'{safe_url}.html',
        'js_files': [f'{safe_url}_js_{i}.js' for i in range(len(js))]
    }
    with open(os.path.join(DATA_DIR, f'{safe_url}.meta.json'), 'w', encoding='utf-8') as f:
        json.dump(entry, f, indent=2)
    with open(os.path.join(DATA_DIR, f'{safe_url}.html'), 'w', encoding='utf-8') as f:
        f.write(html)
    for i, js_code in enumerate(js):
        with open(os.path.join(DATA_DIR, f'{safe_url}_js_{i}.js'), 'w', encoding='utf-8') as f:
            f.write(js_code or '')

def main():
    parser = argparse.ArgumentParser(description='Collect phishing dataset from URL list')
    parser.add_argument('--file',required=True, help='Input file containing URLs')
    parser.add_argument('--limit', type=int, default=50, help='Max URLs to process')
    parser.add_argument('--format', choices=['phishtank', 'url_list'], default='phishtank', help='Input format (default: phishtank)')
    args = parser.parse_args()

    if args.format == 'phishtank':
        print("Reading URLs from PhishTank CSV...")
        urls = read_urls_from_file(args.file)
    else:
        print("Not implemented yet for url_list format")
        exit(1)

    urls = [u for u in urls if u]
    total = min(args.limit, len(urls))

    for idx, url in enumerate(urls[:total]):
        print(f"[{idx+1}/{total}] Processing: {url}")
        html, js, status_code = fetch_html_and_js(url)
        save_data(url=url, html=html, js=js, status_code=status_code)

if __name__ == "__main__":
    main()
