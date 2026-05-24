"""IP RDAP/ASN/Geo/RTT collection helpers for the domain analyzer."""

import ipaddress
from datetime import datetime, UTC

from geoip2.database import Reader as GeoIPReader
from icmplib import async_ping, ICMPSocketError, DestinationUnreachable, TimeExceeded


def _now_utc() -> datetime:
    return datetime.now(UTC)


def _lookup_geo(reader: GeoIPReader | None, ip_value: str) -> dict | None:
    if reader is None:
        return None
    try:
        response = reader.city(ip_value)
    except Exception:
        return None

    subdivision = response.subdivisions.most_specific
    return {
        "country": response.country.name,
        "country_code": response.country.iso_code,
        "region": subdivision.name,
        "region_code": subdivision.iso_code,
        "city": response.city.name,
        "postal_code": response.postal.code,
        "latitude": response.location.latitude,
        "longitude": response.location.longitude,
        "timezone": response.location.time_zone,
        "isp": None,
        "org": None,
    }


def _lookup_asn(reader: GeoIPReader | None, ip_value: str) -> dict | None:
    if reader is None:
        return None
    try:
        response = reader.asn(ip_value)
    except Exception:
        return None

    return {
        "asn": response.autonomous_system_number,
        "as_org": response.autonomous_system_organization,
        "network_address": str(response.network.network_address),
        "prefix_len": response.network.prefixlen,
    }


async def _measure_rtt(ip_value: str, count: int, timeout: float, interval: float, privileged: bool):
    try:
        result = await async_ping(
            ip_value,
            count=count,
            timeout=timeout,
            interval=interval,
            privileged=privileged,
        )
        if result is None:
            return 0.0, False
        return float(result.avg_rtt or 0.0), bool(result.is_alive)
    except (ICMPSocketError, DestinationUnreachable, TimeExceeded):
        return 0.0, False
    except Exception:
        return 0.0, False


def _normalize_rdap_ip(rdap_data: dict | None, ip_value: str) -> dict | None:
    if rdap_data is None:
        return None

    normalized = dict(rdap_data)

    ip_version = normalized.get("ip_version")
    if ip_version is None and "ipVersion" in normalized:
        ip_version = normalized.get("ipVersion")
    if ip_version is None:
        try:
            ip_version = ipaddress.ip_address(ip_value).version
        except ValueError:
            ip_version = None

    normalized["ip_version"] = int(ip_version) if ip_version is not None else None
    if "network" not in normalized:
        normalized["network"] = None
    if "entities" not in normalized:
        normalized["entities"] = None

    return normalized


async def _fetch_ip_rdap(ip_value: str, ipv4_client, ipv6_client):
    try:
        ip_obj = ipaddress.ip_address(ip_value)
    except ValueError:
        return None
    try:
        if ip_obj.version == 4:
            rdap_response = await ipv4_client.aio_lookup(ip_value)
        else:
            rdap_response = await ipv6_client.aio_lookup(ip_value)
        return _normalize_rdap_ip(rdap_response.to_dict(), ip_value)
    except Exception:
        return None


async def collect_ip_entries(
    ip_sources: dict,
    ipv4_client,
    ipv6_client,
    geo_reader,
    asn_reader,
    rtt_enabled: bool,
    rtt_privileged: bool,
    rtt_count: int,
    rtt_timeout: float,
    rtt_interval: float,
):
    now = _now_utc()
    entries = []

    async def build_entry(ip_value: str, source: str):
        rdap_data = await _fetch_ip_rdap(ip_value, ipv4_client, ipv6_client)
        asn_data = _lookup_asn(asn_reader, ip_value)
        geo_data = _lookup_geo(geo_reader, ip_value)

        average_rtt = 0.0
        is_alive = False
        icmp_time = None
        if rtt_enabled:
            average_rtt, is_alive = await _measure_rtt(
                ip_value,
                count=rtt_count,
                timeout=rtt_timeout,
                interval=rtt_interval,
                privileged=rtt_privileged,
            )
            icmp_time = now

        return {
            "ip": ip_value,
            "from_record": source,
            "remarks": {
                "rdap_evaluated_on": now,
                "asn_evaluated_on": now,
                "geo_evaluated_on": now,
                "icmp_evaluated_on": icmp_time,
                "is_alive": is_alive,
                "average_rtt": average_rtt,
            },
            "rdap": rdap_data,
            "asn": asn_data,
            "geo": geo_data
        }

    for ip_value, source in ip_sources.items():
        entries.append(await build_entry(ip_value, source))

    return entries
