"""RDAP/WHOIS collection helpers for the domain analyzer."""

import logging
from datetime import datetime, UTC

import tldextract
import whodap

logger = logging.getLogger(__name__)


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


def _select_whois_value(parsed: dict, keys: list[str]):
    for key in keys:
        if key in parsed:
            value = parsed.get(key)
            if isinstance(value, list):
                return value[0] if value else None
            return value
    return None


async def fetch_domain_rdap(domain_name: str, zone: str | None, dns_client, whois_client):
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
        except Exception as exc:
            logger.debug("RDAP lookup failed for %s.%s: %s", domain, tld, exc)
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
                    except Exception as exc:
                        logger.debug(
                            "RDAP fallback lookup failed for %s.%s: %s", domain, tld, exc
                        )
                        rdap_data = None

    whois_raw = None
    whois_parsed = None
    if rdap_data is None:
        try:
            whois_raw, whois_parsed = await whois_client.aio_whois(rdap_target)
        except Exception as exc:
            logger.debug("WHOIS lookup failed for %s: %s", rdap_target, exc)
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
