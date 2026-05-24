"""Collects a raw domain record (DNS / IP / RDAP / WHOIS) for a URL.

Used both by the collect CLI (which stores the record in MongoDB) and by the
prediction pipeline's domain stage (which collects in-memory and never stores).
"""
from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, UTC
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import asyncwhois
import dns.asyncresolver
import httpx
import whodap
from geoip2.database import Reader as GeoIPReader

from phishing_engine.collectors.dns import collect_dns, find_zone_info
from phishing_engine.collectors.ip import collect_ip_entries
from phishing_engine.collectors.rdap import fetch_domain_rdap

DEFAULT_TIMEOUT = 5.0
DEFAULT_RTT_COUNT = 3
DEFAULT_RTT_INTERVAL = 0.2
DEFAULT_RTT_TIMEOUT = 1.0


def _now_utc() -> datetime:
    """Current time, timezone-aware in UTC."""
    return datetime.now(UTC)


def extract_domain(url: str) -> str:
    """Extract the IDNA-encoded registrable host from a URL (adds a scheme if missing)."""
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    host = parsed.hostname or parsed.path
    host = (host or "").strip().strip(".")
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, AttributeError):
        return host


def _make_ssl_context() -> ssl.SSLContext:
    """Permissive TLS context for the RDAP HTTP client (lowered security level)."""
    context = ssl.create_default_context()
    context.set_ciphers("ALL:@SECLEVEL=1")
    return context


async def collect_domain_record(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    geo_reader: Optional[GeoIPReader] = None,
    asn_reader: Optional[GeoIPReader] = None,
    rtt_enabled: bool = False,
    rtt_privileged: bool = False,
    rtt_count: int = DEFAULT_RTT_COUNT,
    rtt_timeout: float = DEFAULT_RTT_TIMEOUT,
    rtt_interval: float = DEFAULT_RTT_INTERVAL,
) -> dict:
    """Asynchronously gather DNS, IP (RDAP/ASN/Geo/RTT) and domain RDAP/WHOIS data.

    Returns the canonical raw domain-record dict consumed by the domain feature
    extractor — the same shape the collect CLI stores in MongoDB. ``geo_reader``
    /``asn_reader`` are open GeoLite2 readers (or None); RTT pings are opt-in.
    """
    domain_name = extract_domain(url)
    resolver = dns.asyncresolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout

    zone, soa, has_dnskey = await find_zone_info(domain_name, resolver)
    dns_data, ip_sources = await collect_dns(domain_name, resolver, zone, soa, has_dnskey)

    now = _now_utc()
    httpx_client = httpx.AsyncClient(
        verify=_make_ssl_context(),
        follow_redirects=True,
        timeout=timeout,
    )
    dns_client = await whodap.DNSClient.new_aio_client(httpx_client=httpx_client)
    ipv4_client = await whodap.IPv4Client.new_aio_client(httpx_client=httpx_client)
    ipv6_client = await whodap.IPv6Client.new_aio_client(httpx_client=httpx_client)
    whois_client = asyncwhois.client.DomainClient()

    try:
        rdap_data = await fetch_domain_rdap(domain_name, zone, dns_client, whois_client)
        ip_entries = await collect_ip_entries(
            ip_sources,
            ipv4_client,
            ipv6_client,
            geo_reader,
            asn_reader,
            rtt_enabled,
            rtt_privileged,
            rtt_count,
            rtt_timeout,
            rtt_interval,
        )
    finally:
        await dns_client.aio_close()
        await ipv4_client.aio_close()
        await ipv6_client.aio_close()
        await httpx_client.aclose()

    return {
        "domain_name": domain_name,
        "url": url,
        "evaluated_on": now,
        "sourced_on": now,
        "dns": dns_data,
        "rdap": rdap_data,
        "tls": None,
        "ip_data": ip_entries,
        "remarks": {
            "dns_evaluated_on": now,
            "dns_had_no_ips": len(ip_entries) == 0,
            "rdap_evaluated_on": now,
            "tls_evaluated_on": now,
        },
    }


def collect_domain_record_sync(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    geoip_city_db: Optional[str] = None,
    geoip_asn_db: Optional[str] = None,
    rtt_enabled: bool = False,
    rtt_privileged: bool = False,
    rtt_count: int = DEFAULT_RTT_COUNT,
    rtt_timeout: float = DEFAULT_RTT_TIMEOUT,
    rtt_interval: float = DEFAULT_RTT_INTERVAL,
) -> dict:
    """Blocking wrapper that manages GeoIP readers and runs the async collection."""
    geo_reader = GeoIPReader(geoip_city_db) if geoip_city_db and Path(geoip_city_db).exists() else None
    asn_reader = GeoIPReader(geoip_asn_db) if geoip_asn_db and Path(geoip_asn_db).exists() else None
    try:
        return asyncio.run(
            collect_domain_record(
                url,
                timeout=timeout,
                geo_reader=geo_reader,
                asn_reader=asn_reader,
                rtt_enabled=rtt_enabled,
                rtt_privileged=rtt_privileged,
                rtt_count=rtt_count,
                rtt_timeout=rtt_timeout,
                rtt_interval=rtt_interval,
            )
        )
    finally:
        if geo_reader:
            geo_reader.close()
        if asn_reader:
            asn_reader.close()
