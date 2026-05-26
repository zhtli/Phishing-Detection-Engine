"""IP RDAP/ASN/Geo collection helpers for the domain analyzer."""

import ipaddress
import logging
from datetime import datetime, UTC

from geoip2.database import Reader as GeoIPReader

logger = logging.getLogger(__name__)


def _now_utc() -> datetime:
    return datetime.now(UTC)


def _lookup_geo(reader: GeoIPReader | None, ip_value: str) -> dict | None:
    if reader is None:
        return None
    try:
        response = reader.city(ip_value)
    except Exception as exc:
        logger.debug("GeoIP city lookup failed for %s: %s", ip_value, exc)
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
    except Exception as exc:
        logger.debug("GeoIP ASN lookup failed for %s: %s", ip_value, exc)
        return None

    return {
        "asn": response.autonomous_system_number,
        "as_org": response.autonomous_system_organization,
        "network_address": str(response.network.network_address),
        "prefix_len": response.network.prefixlen,
    }


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
        logger.debug("invalid IP address for RDAP lookup: %s", ip_value)
        return None
    try:
        if ip_obj.version == 4:
            rdap_response = await ipv4_client.aio_lookup(ip_value)
        else:
            rdap_response = await ipv6_client.aio_lookup(ip_value)
        return _normalize_rdap_ip(rdap_response.to_dict(), ip_value)
    except Exception as exc:
        logger.debug("IP RDAP lookup failed for %s: %s", ip_value, exc)
        return None


async def collect_ip_entries(
    ip_sources: dict,
    ipv4_client,
    ipv6_client,
    geo_reader,
    asn_reader,
):
    now = _now_utc()
    entries = []

    async def build_entry(ip_value: str, source: str):
        rdap_data = await _fetch_ip_rdap(ip_value, ipv4_client, ipv6_client)
        asn_data = _lookup_asn(asn_reader, ip_value)
        geo_data = _lookup_geo(geo_reader, ip_value)

        return {
            "ip": ip_value,
            "from_record": source,
            "remarks": {
                "rdap_evaluated_on": now,
                "asn_evaluated_on": now,
                "geo_evaluated_on": now,
            },
            "rdap": rdap_data,
            "asn": asn_data,
            "geo": geo_data
        }

    for ip_value, source in ip_sources.items():
        entries.append(await build_entry(ip_value, source))

    return entries
