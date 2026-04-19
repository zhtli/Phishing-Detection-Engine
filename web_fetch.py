"""Script management module for handling script caching and web fetching."""

import os
import json
import hashlib
import requests
import ssl
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup


def load_script_cache(cache_file):
    """Load the script cache mapping (hash -> filename)."""
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load script cache: {e}")
    return {}


def save_script_cache(cache, cache_file):
    """Save the script cache mapping."""
    try:
        cache_dir = os.path.dirname(cache_file)
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(cache, f)
    except Exception as e:
        print(f"Warning: Could not save script cache: {e}")


def load_html_cache(cache_file):
    """Load the HTML cache mapping (hash -> filename)."""
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load HTML cache: {e}")
    return {}


def save_html_cache(cache, cache_file):
    """Save the HTML cache mapping."""
    try:
        cache_dir = os.path.dirname(cache_file)
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(cache, f)
    except Exception as e:
        print(f"Warning: Could not save HTML cache: {e}")


def load_cert_cache(cache_file):
    """Load the certificate cache mapping (hash -> filename)."""
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load certificate cache: {e}")
    return {}


def save_cert_cache(cache, cache_file):
    """Save the certificate cache mapping."""
    try:
        cache_dir = os.path.dirname(cache_file)
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(cache, f)
    except Exception as e:
        print(f"Warning: Could not save certificate cache: {e}")


def get_script_hash(content):
    """Calculate SHA256 hash of script content."""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def get_certificate_fingerprint(cert_der):
    """Calculate SHA256 fingerprint for a DER-encoded certificate."""
    if not cert_der:
        return ''
    return hashlib.sha256(cert_der).hexdigest()


def fetch_certificate_for_url(url, timeout=10):
    """Fetch server certificate for an HTTPS URL and validate trust/time.

    Returns:
        Tuple: (cert_pem, cert_fingerprint, cert_valid, cert_error_message)
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() != 'https':
        return '', '', False, 'URL is not HTTPS'

    hostname = parsed.hostname
    if not hostname:
        return '', '', False, 'Could not parse hostname from URL'

    port = parsed.port if parsed.port else 443
    cert_der = None
    cert_dict = {}

    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert_der = tls_sock.getpeercert(binary_form=True)
        cert_pem = ssl.DER_cert_to_PEM_cert(cert_der) if cert_der else ''
        cert_fingerprint = get_certificate_fingerprint(cert_der)
        return cert_pem, cert_fingerprint, True, ''
    except ssl.SSLCertVerificationError as e:
        verification_error = f'Certificate verification failed: {e}'

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    cert_der = tls_sock.getpeercert(binary_form=True)
            cert_pem = ssl.DER_cert_to_PEM_cert(cert_der) if cert_der else ''
            cert_fingerprint = get_certificate_fingerprint(cert_der)
            return cert_pem, cert_fingerprint, False, verification_error
        except Exception as inner_e:
            return '', '', False, f'{verification_error}; retrieval also failed: {inner_e}'
    except Exception as e:
        return '', '', False, f'Certificate retrieval failed: {e}'


def save_certificate_file(url, cert_cache, cert_dir):
    """Save certificate as PEM file with deduplication.

    Returns:
        Tuple: (cert_file, cert_valid, cert_error_message, updated_cert_cache)
    """
    cert_pem, cert_fingerprint, cert_valid, cert_error = fetch_certificate_for_url(url)

    if not cert_pem:
        return '', cert_valid, cert_error, cert_cache

    if cert_fingerprint in cert_cache:
        return cert_cache[cert_fingerprint], cert_valid, cert_error, cert_cache

    os.makedirs(cert_dir, exist_ok=True)
    parsed = urlparse(url)
    host_name = parsed.hostname if parsed.hostname else 'unknown_host'
    cert_filename = f'{host_name}.pem'
    base_name = host_name
    counter = 1
    full_filename = cert_filename

    while os.path.exists(os.path.join(cert_dir, full_filename)):
        full_filename = f"{base_name}_{counter}.pem"
        counter += 1

    cert_filename = full_filename

    try:
        cert_path = os.path.join(cert_dir, cert_filename)
        with open(cert_path, 'w', encoding='utf-8') as f:
            f.write(cert_pem)
        cert_cache[cert_fingerprint] = cert_filename
        return cert_filename, cert_valid, cert_error, cert_cache
    except OSError as e:
        return '', cert_valid, f'{cert_error}; error saving certificate: {e}', cert_cache


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
        content_type = (resp.headers.get('Content-Type') or '').lower()
        is_html = ('text/html' in content_type) or ('application/xhtml+xml' in content_type)

        if not is_html:
            print(f"Non-HTML content type received: '{content_type or 'unknown'}'")
            raise ValueError(
                f"Non-HTML content type received: '{content_type or 'unknown'}'"
            )

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
