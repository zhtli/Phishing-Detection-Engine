"""DNS collection helpers for the domain analyzer."""

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.rdatatype as rdt
import tldextract


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


async def find_zone_info(
    domain_name: str,
    resolver: dns.asyncresolver.Resolver,
) -> tuple[str | None, dict | None, bool | None]:
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


async def collect_dns(
    domain_name: str,
    resolver: dns.asyncresolver.Resolver,
    zone: str | None,
    soa: dict | None,
    has_dnskey: bool | None,
):
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
