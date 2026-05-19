#!/usr/bin/env python3
"""predict_domain.py: In-process domain pipeline for the domain_analyzer model."""

import argparse
import asyncio
import ipaddress
import json
import os
import ssl
import sys
from datetime import datetime, UTC
from pathlib import Path
from urllib.parse import urlparse

import asyncwhois
import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.rdatatype as rdt
import httpx
import joblib
import pandas as pd
import tldextract
import whodap
from geoip2.database import Reader as GeoIPReader
from icmplib import async_ping, ICMPSocketError, DestinationUnreachable, TimeExceeded

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
EXTRACTOR_DIR = BASE_DIR / "extractor"
EXTRACTOR_DATA_DIR = EXTRACTOR_DIR / "data"
DEFAULT_GEOIP_DIR = BASE_DIR / "GeoLite2-DB"
DEFAULT_CITY_DB = DEFAULT_GEOIP_DIR / "GeoLite2-City.mmdb"
DEFAULT_ASN_DB = DEFAULT_GEOIP_DIR / "GeoLite2-ASN.mmdb"

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
if str(EXTRACTOR_DIR) not in sys.path:
    sys.path.insert(0, str(EXTRACTOR_DIR))

import extractor as domain_extractor


DEFAULT_TIMEOUT = 5.0
DEFAULT_RTT_COUNT = 3
DEFAULT_RTT_INTERVAL = 0.2
DEFAULT_MAX_RTT = 1.0


def _now_utc() -> datetime:
    return datetime.now(UTC)


def _normalize_url(url: str) -> str:
    if "://" not in url:
        return "http://" + url
    return url


def _extract_domain(url: str) -> str:
    normalized = _normalize_url(url)
    parsed = urlparse(normalized)
    host = parsed.hostname or parsed.path
    host = host.strip().strip(".")
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, AttributeError):
        return host


def _parse_rdap_datetime(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def _extract_event_date(events, keywords) -> datetime | None:
    if not events:
        return None
    for event in events:
        action = str(event.get("eventAction", "")).lower()
        if any(key in action for key in keywords):
            return _parse_rdap_datetime(event.get("eventDate"))
    return None


def _extract_vcard(entity: dict) -> tuple[str | None, str | None]:
    vcard = entity.get("vcardArray")
    if not vcard or len(vcard) < 2:
        return None, None
    entries = vcard[1]
    name = None
    email = None
    for item in entries:
        if not isinstance(item, list) or len(item) < 4:
            continue
        field = item[0]
        value = item[3]
        if field == "fn" and isinstance(value, str):
            name = value
        if field == "email" and isinstance(value, str):
            email = value
    return name, email


def _map_rdap_entities(entities) -> dict:
    if not entities:
        return {}
    mapped = {"registrar": [], "registrant": [], "administrative": []}
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles") or []
        name, email = _extract_vcard(entity)
        entry = {}
        if name:
            entry["name"] = name
        if email:
            entry["email"] = email
        if not entry:
            continue
        for role in roles:
            role_lower = str(role).lower()
            if "registrar" in role_lower:
                mapped["registrar"].append(entry)
            if "registrant" in role_lower:
                mapped["registrant"].append(entry)
            if "administrative" in role_lower or "admin" in role_lower:
                mapped["administrative"].append(entry)
    return {k: v for k, v in mapped.items() if v}


def _make_ssl_context():
    context = ssl.create_default_context()
    context.set_ciphers("ALL:@SECLEVEL=1")
    return context


def _extract_known_tld(domain_name: str, client: whodap.DNSClient) -> tuple[str | None, str | None, str | None]:
    parts = domain_name.split(".")
    if len(parts) < 2:
        return None, None, None

    domain = ".".join(parts[:-2])
    tld = ".".join(parts[-2:])

    iana_tlds = client.iana_dns_server_map
    if tld not in iana_tlds:
        domain = ".".join(parts[:-1])
        tld = parts[-1]

    if tld not in iana_tlds:
        return None, None, None

    return domain, tld, iana_tlds.get(tld)


def _soa_to_dict(soa_record) -> dict | None:
    if soa_record is None:
        return None
    return {
        "primary_ns": soa_record.mname.to_text(True),
        "resp_mailbox_dname": soa_record.rname.to_text(True),
        "serial": int(soa_record.serial),
        "refresh": int(soa_record.refresh),
        "retry": int(soa_record.retry),
        "expire": int(soa_record.expire),
        "min_ttl": int(soa_record.minimum),
    }


async def _find_zone_info(domain_name: str, resolver: dns.asyncresolver.Resolver) -> tuple[str | None, dict | None, bool | None]:
    ext = tldextract.extract(domain_name)
    if ext.ipv4 or ext.ipv6:
        return None, None, None

    if ext.domain and ext.suffix:
        base = f"{ext.domain}.{ext.suffix}"
        labels = domain_name.split(".")
        base_labels = base.split(".")
        start = max(0, len(labels) - len(base_labels))
        candidates = [".".join(labels[i:]) for i in range(start)] + [base]
    elif ext.suffix:
        candidates = [ext.suffix]
    else:
        return None, None, None

    zone = None
    soa = None
    for candidate in candidates:
        try:
            answer = await resolver.resolve(candidate, rdt.SOA)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except dns.exception.DNSException:
            continue
        if answer and len(answer) > 0 and answer[0].rdtype == rdt.SOA:
            zone = candidate
            soa = answer[0]

    if zone is None:
        return None, None, None

    has_dnskey = None
    try:
        dnskey = await resolver.resolve(zone, rdt.DNSKEY)
        has_dnskey = bool(dnskey and len(dnskey) > 0)
    except dns.resolver.NoAnswer:
        has_dnskey = False
    except dns.exception.DNSException:
        has_dnskey = None

    return zone, _soa_to_dict(soa), has_dnskey


async def _resolve_record(resolver: dns.asyncresolver.Resolver, name: str, rtype: str):
    try:
        answer = await resolver.resolve(name, rtype)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None, None, None
    except dns.exception.Timeout:
        return None, None, "timeout"
    except dns.exception.DNSException as exc:
        return None, None, str(exc)

    ttl = answer.rrset.ttl if answer.rrset else None
    values = []
    if rtype in ("A", "AAAA"):
        values = [item.address for item in answer]
    elif rtype == "TXT":
        for item in answer:
            if hasattr(item, "strings"):
                raw = b"".join(item.strings)
                values.append(raw.decode("utf-8", errors="replace"))
    elif rtype == "CNAME":
        values = [item.target.to_text(True) for item in answer]
    elif rtype == "MX":
        values = [(item.exchange.to_text(True), int(item.preference)) for item in answer]
    elif rtype == "NS":
        values = [item.target.to_text(True) for item in answer]

    return values, ttl, None


async def _resolve_ips(resolver: dns.asyncresolver.Resolver, hostname: str):
    related = []
    for rtype in ("A", "AAAA"):
        values, ttl, _ = await _resolve_record(resolver, hostname, rtype)
        if not values:
            continue
        for ip_value in values:
            related.append({"ttl": ttl or 0, "value": ip_value})
    return related


def _txt_flags(txt_records: list[str] | None) -> dict:
    flags = {"has_spf": False, "has_dkim": False, "has_dmarc": False}
    if not txt_records:
        return flags
    for record in txt_records:
        lower = record.lower()
        if "v=spf1" in lower:
            flags["has_spf"] = True
        if "dkim" in lower:
            flags["has_dkim"] = True
        if "dmarc" in lower:
            flags["has_dmarc"] = True
    return flags


def _add_ip(ip_sources: dict, ip_value: str, source: str):
    if ip_value not in ip_sources:
        ip_sources[ip_value] = source


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


async def _fetch_domain_rdap(domain_name: str, zone: str | None, dns_client, whois_client):
    rdap_target = zone or domain_name
    rdap_data = None
    rdap_entities = None

    domain, tld, _ = _extract_known_tld(rdap_target, dns_client)
    if domain is not None and tld is not None:
        try:
            rdap_response = await dns_client.aio_lookup(domain, tld)
            rdap_dict = rdap_response.to_dict()
            rdap_data = rdap_dict
            rdap_entities = _map_rdap_entities(rdap_dict.get("entities"))
        except Exception:
            rdap_data = None

    if rdap_data is None:
        ext = tldextract.extract(rdap_target)
        if ext.domain and ext.suffix:
            reg_domain = f"{ext.domain}.{ext.suffix}"
            if reg_domain != rdap_target:
                domain, tld, _ = _extract_known_tld(reg_domain, dns_client)
                if domain is not None and tld is not None:
                    try:
                        rdap_response = await dns_client.aio_lookup(domain, tld)
                        rdap_dict = rdap_response.to_dict()
                        rdap_data = rdap_dict
                        rdap_entities = _map_rdap_entities(rdap_dict.get("entities"))
                    except Exception:
                        rdap_data = None

    whois_raw = None
    whois_parsed = None
    if rdap_data is None:
        try:
            whois_raw, whois_parsed = await whois_client.aio_whois(rdap_target)
        except Exception:
            whois_raw = None
            whois_parsed = None

    events = rdap_data.get("events") if isinstance(rdap_data, dict) else None
    registration_date = _extract_event_date(events, ["registration", "registered"]) if events else None
    expiration_date = _extract_event_date(events, ["expiration", "expiry"]) if events else None
    last_changed_date = _extract_event_date(events, ["last changed", "last update", "changed"]) if events else None

    if rdap_data is None and whois_parsed:
        registration_date = registration_date or _parse_rdap_datetime(
            _select_whois_value(whois_parsed, ["creation_date", "created_date", "created"]))
        expiration_date = expiration_date or _parse_rdap_datetime(
            _select_whois_value(whois_parsed, ["expiration_date", "expires_date", "expiry_date"]))
        last_changed_date = last_changed_date or _parse_rdap_datetime(
            _select_whois_value(whois_parsed, ["updated_date", "last_updated", "updated"]))

    dnssec = None
    if isinstance(rdap_data, dict):
        dnssec = rdap_data.get("secureDNS") or rdap_data.get("dnssec")

    return {
        "registration_date": registration_date,
        "expiration_date": expiration_date,
        "last_changed_date": last_changed_date,
        "dnssec": dnssec,
        "entities": rdap_entities,
    }


def _select_whois_value(parsed: dict, keys: list[str]):
    for key in keys:
        if key in parsed:
            value = parsed.get(key)
            if isinstance(value, list):
                return value[0] if value else None
            return value
    return None


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


async def _collect_dns(domain_name: str, resolver: dns.asyncresolver.Resolver, zone: str | None, soa: dict | None,
                       has_dnskey: bool | None):
    ip_sources = {}
    errors = {}
    ttls = {}

    dns_data = {
        "A": None,
        "AAAA": None,
        "CNAME": None,
        "MX": None,
        "NS": None,
        "TXT": None,
        "SOA": None,
        "zone_SOA": None,
        "ttls": ttls,
        "errors": errors,
        "remarks": {
            "zone": zone,
            "has_dnskey": bool(has_dnskey) if has_dnskey is not None else False,
        },
    }

    values, ttl, err = await _resolve_record(resolver, domain_name, "A")
    if err:
        errors["A"] = err
    if values:
        dns_data["A"] = values
        ttls["A"] = ttl
        for ip_value in values:
            _add_ip(ip_sources, ip_value, "A")

    values, ttl, err = await _resolve_record(resolver, domain_name, "AAAA")
    if err:
        errors["AAAA"] = err
    if values:
        dns_data["AAAA"] = values
        ttls["AAAA"] = ttl
        for ip_value in values:
            _add_ip(ip_sources, ip_value, "AAAA")

    cname_values, ttl, err = await _resolve_record(resolver, domain_name, "CNAME")
    if err:
        errors["CNAME"] = err
    if cname_values:
        cname_target = cname_values[0]
        related_ips = await _resolve_ips(resolver, cname_target)
        dns_data["CNAME"] = {
            "value": cname_target,
            "related_ips": related_ips,
        }
        ttls["CNAME"] = ttl
        for related in related_ips:
            _add_ip(ip_sources, related["value"], "CNAME")

    mx_values, ttl, err = await _resolve_record(resolver, domain_name, "MX")
    if err:
        errors["MX"] = err
    if mx_values:
        mx_dict = {}
        for host, preference in mx_values:
            related_ips = await _resolve_ips(resolver, host)
            mx_dict[host] = {
                "priority": preference,
                "related_ips": related_ips,
            }
            for related in related_ips:
                _add_ip(ip_sources, related["value"], "MX")
        dns_data["MX"] = mx_dict
        ttls["MX"] = ttl

    ns_values, ttl, err = await _resolve_record(resolver, domain_name, "NS")
    if err:
        errors["NS"] = err
    if ns_values:
        ns_dict = {}
        for host in ns_values:
            related_ips = await _resolve_ips(resolver, host)
            ns_dict[host] = {"related_ips": related_ips}
            for related in related_ips:
                _add_ip(ip_sources, related["value"], "NS")
        dns_data["NS"] = ns_dict
        ttls["NS"] = ttl

    txt_values, ttl, err = await _resolve_record(resolver, domain_name, "TXT")
    if err:
        errors["TXT"] = err
    if txt_values:
        dns_data["TXT"] = txt_values
        ttls["TXT"] = ttl
        flags = _txt_flags(txt_values)
        dns_data["remarks"].update(flags)

    if soa:
        if zone and zone != domain_name:
            dns_data["zone_SOA"] = soa
            dns_data["SOA"] = None
        else:
            dns_data["SOA"] = soa

    return dns_data, ip_sources


async def _collect_ip_entries(ip_sources: dict, ipv4_client, ipv6_client, geo_reader, asn_reader,
                              rtt_enabled: bool, rtt_privileged: bool, rtt_count: int, rtt_timeout: float,
                              rtt_interval: float):
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
            "geo": geo_data,
            "nerd_rep": -1,
        }

    for ip_value, source in ip_sources.items():
        entries.append(await build_entry(ip_value, source))

    return entries


async def collect_domain_record(url: str, timeout: float, geo_reader, asn_reader, rtt_enabled: bool,
                                rtt_privileged: bool, rtt_count: int, rtt_timeout: float, rtt_interval: float):
    domain_name = _extract_domain(url)
    resolver = dns.asyncresolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout

    zone, soa, has_dnskey = await _find_zone_info(domain_name, resolver)
    dns_data, ip_sources = await _collect_dns(domain_name, resolver, zone, soa, has_dnskey)

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
        rdap_data = await _fetch_domain_rdap(domain_name, zone, dns_client, whois_client)
        ip_entries = await _collect_ip_entries(
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

    record = {
        "domain_name": domain_name,
        "url": url,
        "evaluated_on": now,
        "source": "cli",
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

    return record


def _resolve_model_path(model_arg: str | None) -> Path:
    if model_arg:
        model_path = Path(model_arg)
        if not model_path.is_absolute():
            model_path = BASE_DIR / model_path
    else:
        model_path = BASE_DIR / "models" / "best_model_XGBoost.joblib"
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")
    return model_path


def _load_model(model_path: Path):
    return joblib.load(model_path)


def _model_feature_names(model) -> list[str] | None:
    if hasattr(model, "feature_names_in_"):
        return list(model.feature_names_in_)
    if hasattr(model, "named_steps"):
        for step in model.named_steps.values():
            if hasattr(step, "feature_names_in_"):
                return list(step.feature_names_in_)
    return None


def _align_features(df: pd.DataFrame, model):
    missing = []
    extra = []
    feature_names = _model_feature_names(model)
    if not feature_names:
        return df, missing, extra

    for name in feature_names:
        if name not in df.columns:
            df[name] = pd.NA
            missing.append(name)

    for name in df.columns:
        if name not in feature_names:
            extra.append(name)

    df = df[feature_names]
    return df, missing, extra


def _predict(model, features: pd.DataFrame):
    proba = None
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(features)[0]
    pred = model.predict(features)[0]
    return pred, proba


def main():
    parser = argparse.ArgumentParser(
        description="Predict phishing for a URL using the domain analyzer model.",
    )
    parser.add_argument("--url", required=True, help="URL or domain to score")
    parser.add_argument("--model", default=None, help="Path to joblib model (default: models/best_model_XGBoost.joblib)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="DNS/RDAP timeout in seconds")
    parser.add_argument("--geoip-city-db", default=os.getenv("GEOIP_CITY_DB") or str(DEFAULT_CITY_DB),
                        help="Path to GeoLite2 City database (env: GEOIP_CITY_DB)")
    parser.add_argument("--geoip-asn-db", default=os.getenv("GEOIP_ASN_DB") or str(DEFAULT_ASN_DB),
                        help="Path to GeoLite2 ASN database (env: GEOIP_ASN_DB)")
    parser.add_argument("--disable-rtt", action="store_true", help="Disable ICMP RTT checks")
    parser.add_argument("--rtt-privileged", action="store_true", help="Use privileged ICMP mode")
    parser.add_argument("--rtt-count", type=int, default=DEFAULT_RTT_COUNT, help="ICMP echo count")
    parser.add_argument("--rtt-timeout", type=float, default=DEFAULT_MAX_RTT, help="ICMP timeout in seconds")
    parser.add_argument("--rtt-interval", type=float, default=DEFAULT_RTT_INTERVAL, help="ICMP interval in seconds")
    args = parser.parse_args()

    if not EXTRACTOR_DATA_DIR.exists():
        raise FileNotFoundError(f"Extractor data directory not found: {EXTRACTOR_DATA_DIR}")

    domain_extractor.init_transformations({"data_dir": str(EXTRACTOR_DATA_DIR)})

    model_path = _resolve_model_path(args.model)
    model = _load_model(model_path)

    geo_path = Path(args.geoip_city_db) if args.geoip_city_db else None
    asn_path = Path(args.geoip_asn_db) if args.geoip_asn_db else None
    if geo_path and not geo_path.exists():
        raise FileNotFoundError(f"GeoLite2 City DB not found: {geo_path}")
    if asn_path and not asn_path.exists():
        raise FileNotFoundError(f"GeoLite2 ASN DB not found: {asn_path}")

    geo_reader = GeoIPReader(str(geo_path)) if geo_path else None
    asn_reader = GeoIPReader(str(asn_path)) if asn_path else None

    try:
        record = asyncio.run(
            collect_domain_record(
                args.url,
                timeout=args.timeout,
                geo_reader=geo_reader,
                asn_reader=asn_reader,
                rtt_enabled=not args.disable_rtt,
                rtt_privileged=args.rtt_privileged,
                rtt_count=args.rtt_count,
                rtt_timeout=args.rtt_timeout,
                rtt_interval=args.rtt_interval,
            )
        )
    finally:
        if geo_reader:
            geo_reader.close()
        if asn_reader:
            asn_reader.close()

    features, errors = domain_extractor.extract_features([record])
    if features is None:
        raise ValueError(f"Feature extraction failed: {errors}")

    if "class" in features.columns:
        features = features.drop(columns=["class"])
    if "domain_name" in features.columns:
        features = features.drop(columns=["domain_name"])

    features = features.replace({True: 1, False: 0})
    features = features.apply(pd.to_numeric, errors="coerce")

    features, missing, extra = _align_features(features, model)

    pred, proba = _predict(model, features)
    label_map = {0: "benign", 1: "phish"}
    label = label_map.get(int(pred), str(pred))

    output = {
        "url": args.url,
        "domain": record.get("domain_name"),
        "model": str(model_path),
        "label": label,
    }
    if proba is not None:
        class_names = list(getattr(model, "classes_", [0, 1]))
        probs = {str(name): round(float(prob), 6) for name, prob in zip(class_names, proba)}
        output["probabilities"] = probs

    if missing:
        output["missing_features"] = missing
    if extra:
        output["extra_features"] = extra

    print(json.dumps(output, default=str, indent=2))


if __name__ == "__main__":
    main()
