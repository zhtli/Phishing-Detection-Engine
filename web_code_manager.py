"""Script management module for handling script caching and web fetching."""

import os
import json
import hashlib
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Configuration
SCRIPT_DIR = "data/JS"
SCRIPT_CACHE_FILE = f"{SCRIPT_DIR}/.script_cache.json"
HTML_CACHE_FILE = "data/.html_cache.json"  # Maps content hashes to saved filenames



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


def load_html_cache():
    """Load the HTML cache mapping (hash -> filename)."""
    if os.path.exists(HTML_CACHE_FILE):
        try:
            with open(HTML_CACHE_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load HTML cache: {e}")
    return {}


def save_html_cache(cache):
    """Save the HTML cache mapping."""
    try:
        os.makedirs(os.path.dirname(HTML_CACHE_FILE), exist_ok=True)
        with open(HTML_CACHE_FILE, 'w') as f:
            json.dump(cache, f)
    except Exception as e:
        print(f"Warning: Could not save HTML cache: {e}")


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


def extract_and_fetch_scripts(html, base_url, headers):
    """Extract external script sources and fetch their content.
    
    Args:
        html: HTML content to parse
        base_url: Base URL for resolving relative script URLs
        headers: Custom headers to use for requests (defaults to HEADERS)
    
    Returns:
        List of tuples: (script_src, script_content)
    """
    
    soup = BeautifulSoup(html, 'html.parser')
    js_scripts = []
    
    for script in soup.find_all('script'):
        if script.get('src'):
            src = script['src']
            
            # Skip inline scripts (data URIs)
            if src.startswith('data:'):
                continue
            
            # Determine the full URL based on the src format
            if src.startswith(('http://', 'https://')):
                # Absolute URL
                js_url = src
            elif src.startswith('//'):
                # Protocol-relative URL
                parsed_base = urlparse(base_url)
                js_url = f"{parsed_base.scheme}:{src}"
            else:
                # Relative URL
                js_url = urlparse(base_url)._replace(path=src).geturl()
            
            try:
                js_resp = requests.get(js_url, headers=headers, timeout=5, verify=False)
                js_scripts.append((src, js_resp.text))
            except Exception as e:
                print(f"Error fetching {src}: {e}")
    
    return js_scripts


def fetch_website(url, user_agent=None):
    """Fetch website HTML and associated JavaScript files.
    
    Args:
        url: The URL to fetch
        user_agent: Custom user agent string (optional)
    
    Returns:
        Tuple: (html, js_scripts, status_code, redirect_count, final_url, reason)
    """
    headers = {}
    if user_agent:
        headers["User-Agent"] = user_agent
    
    try:
        resp = requests.get(url, headers=headers, timeout=10, verify=False)
        html = resp.text
        status_code = resp.status_code
        redirect_count = len(resp.history)
        final_url = resp.url
        reason = resp.reason
        js_scripts = extract_and_fetch_scripts(html, url, headers=headers)
        return html, js_scripts, status_code, redirect_count, final_url, reason
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        raise Exception(f"Failed to fetch {url}: {e}")
