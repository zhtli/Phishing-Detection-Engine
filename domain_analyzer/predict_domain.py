#!/usr/bin/env python3
"""predict_domain.py: In-process domain pipeline for the domain_analyzer model."""

import argparse
import asyncio
import json
import os
import ssl
import sys
from datetime import datetime, UTC
from pathlib import Path
from urllib.parse import urlparse

import asyncwhois
import dns.asyncresolver
import httpx
import joblib
import pandas as pd
import whodap
from geoip2.database import Reader as GeoIPReader

from collectors.dns import collect_dns, find_zone_info
from collectors.ip import collect_ip_entries
from collectors.rdap import fetch_domain_rdap

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


def _make_ssl_context():
    context = ssl.create_default_context()
    context.set_ciphers("ALL:@SECLEVEL=1")
    return context


async def collect_domain_record(url: str, timeout: float, geo_reader, asn_reader, rtt_enabled: bool,
                                rtt_privileged: bool, rtt_count: int, rtt_timeout: float, rtt_interval: float):
    domain_name = _extract_domain(url)
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

    record = {
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

    features_row = features.iloc[0]
    features_payload = features_row.where(pd.notna(features_row), None).to_dict()

    output = {
        "url": args.url,
        "domain": record.get("domain_name"),
        "model": str(model_path),
        "label": label,
        "features": features_payload,
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
