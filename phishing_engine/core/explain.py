"""Turn a stage's real features/artifacts into human-readable signals + extracted evidence.

The demo UI shows, per stage, a short list of "why" signals (``{label, value, weight,
detail}`` with ``weight`` in ``high|med|low|safe``) and an "extracted evidence" panel
(WHOIS / DNS / page facts). The engine itself produces numeric feature vectors and the raw
artifacts each collector gathered live; this module curates those into the small,
human-readable shapes the UI consumes — no fabricated data, only real values.

* ``url_signals`` / ``content_signals`` read the flat feature dicts the url/content stages
  produce (keys are the ``feature_columns`` in ``config/pipeline.json``).
* ``domain_signals`` / ``domain_evidence`` read the raw ``record`` the domain stage collected
  (``artifacts['record']`` — the DNS/IP/RDAP/WHOIS dict from ``collectors/domain_record.py``).
* ``content_evidence`` reads the content stage's artifacts (HTML / status / TLS from
  ``collectors/content.py``).
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

Signal = Dict[str, Optional[str]]


# --------------------------------------------------------------------------- helpers
def _num(mapping: Optional[Dict], key: str, default: float = 0.0) -> float:
    """Read ``mapping[key]`` coerced to ``float`` (``default`` when absent/uncoercible)."""
    if not mapping:
        return default
    value = mapping.get(key, default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _age_days(created) -> Optional[int]:
    """Whole days between a (tz-aware) registration datetime and now, or ``None``."""
    if not isinstance(created, datetime):
        return None
    when = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - when).days)


def _age_label(days: int) -> str:
    """Human label for a domain age in days (days → months → years)."""
    if days < 60:
        return f"{days} days"
    if days < 730:
        return f"{round(days / 30)} months"
    return f"{days / 365:.1f} years"


def _date_str(value) -> Optional[str]:
    """ISO ``YYYY-MM-DD`` for a datetime, else ``None``."""
    return value.date().isoformat() if isinstance(value, datetime) else None


def _registrar_name(record: Optional[Dict]) -> Optional[str]:
    """First registrar entity name from the RDAP/WHOIS record, if any."""
    entities = ((record or {}).get("rdap") or {}).get("entities") or {}
    registrars = entities.get("registrar") or []
    if registrars and isinstance(registrars[0], dict):
        return registrars[0].get("name")
    return None


def _privacy_masked(record: Optional[Dict]) -> bool:
    """True when the registrant identity looks masked (no name, or a privacy-guard name)."""
    entities = ((record or {}).get("rdap") or {}).get("entities") or {}
    registrants = entities.get("registrant") or []
    if not registrants or not isinstance(registrants[0], dict):
        return True
    name = (registrants[0].get("name") or "").lower()
    if not name:
        return True
    return any(token in name for token in ("privacy", "redacted", "protected", "withheld"))


def _hosting_geo(record: Optional[Dict]) -> Dict:
    """GeoLite2 geo block of the first hosting IP that resolved a country, else ``{}``."""
    for entry in (record or {}).get("ip_data") or []:
        geo = (entry or {}).get("geo") or {}
        if geo.get("country"):
            return geo
    return {}


def _dnssec_signed(rdap: Dict) -> bool:
    """Whether the RDAP record indicates a DNSSEC-signed delegation."""
    dnssec = rdap.get("dnssec")
    if isinstance(dnssec, dict):
        return bool(dnssec.get("delegationSigned"))
    return bool(dnssec)


def _page_title(html: Optional[str]) -> Optional[str]:
    """First ``<title>`` text from raw HTML (whitespace-collapsed, capped), else ``None``."""
    if not html:
        return None
    match = _TITLE_RE.search(html)
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:120] or None


def _cert_name_value(name, oid) -> Optional[str]:
    """First attribute value for ``oid`` in an x509 Name (issuer/subject), else ``None``."""
    try:
        attrs = name.get_attributes_for_oid(oid)
    except Exception:
        return None
    return attrs[0].value if attrs else None


def _tls_evidence(tls_artifact: Optional[Dict]) -> Dict[str, Any]:
    """Real TLS facts from the handshake: protocol/cipher + leaf-cert issuer & validity.

    ``tls_artifact`` is the serializable summary from ``collectors/tls.py``
    (``{protocol, cipher, certificates_der, count}``); ``None`` for a plain-HTTP site.
    """
    if not tls_artifact:
        return {"present": False}

    evidence: Dict[str, Any] = {
        "present": True,
        "protocol": tls_artifact.get("protocol") or None,
        "cipher": tls_artifact.get("cipher") or None,
        "issuer": None,
        "subject": None,
        "validFrom": None,
        "validTo": None,
    }

    ders = tls_artifact.get("certificates_der") or []
    if ders:
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID

            der = ders[0]
            if isinstance(der, str):
                der = bytes.fromhex(der)
            cert = x509.load_der_x509_certificate(der)
            evidence["issuer"] = (_cert_name_value(cert.issuer, NameOID.ORGANIZATION_NAME)
                                  or _cert_name_value(cert.issuer, NameOID.COMMON_NAME))
            evidence["subject"] = _cert_name_value(cert.subject, NameOID.COMMON_NAME)
            not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
            not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
            evidence["validFrom"] = _date_str(not_before)
            evidence["validTo"] = _date_str(not_after)
        except Exception as exc:
            logger.debug("failed to parse TLS leaf certificate: %s", exc)
    return evidence


# --------------------------------------------------------------------------- signals
def url_signals(features: Optional[Dict]) -> List[Signal]:
    """Lexical URL signals from the url stage's feature dict."""
    signals: List[Signal] = []
    if not features:
        return signals
    add = lambda **kw: signals.append(kw)  # noqa: E731

    if _num(features, "domain_in_brand_list") > 0:
        add(label="Recognized brand domain", value="allow-listed", weight="safe",
            detail="Domain is on the engine's known-brand list.")
    if _num(features, "punnyCode") > 0:
        add(label="Punycode / IDN host", value="xn--", weight="high",
            detail="Internationalized host can hide look-alike Unicode characters.")
    if _num(features, "@") > 0:
        add(label="'@' symbol in URL", value="present", weight="high",
            detail="Everything before '@' is ignored by the browser — classic obfuscation.")

    hyphens = _num(features, "-")
    if hyphens >= 2:
        add(label="Multiple hyphens in domain", value=f"{int(hyphens)} hyphens", weight="med",
            detail="Hyphen-stuffed domains imitate brand names.")

    subdomains = _num(features, "subDomainCount")
    if subdomains >= 3:
        add(label="Deep sub-domain nesting", value=f"{int(subdomains)} levels", weight="med",
            detail="Brand keywords are often hidden in deep sub-domains.")

    keywords = _num(features, "keyword_count") + _num(features, "target_keyword_count")
    if keywords > 0:
        add(label="Credential-themed keywords", value=f"{int(keywords)} match(es)",
            weight="high" if keywords > 1 else "med",
            detail="Phishing kits cluster around action words (login, verify, secure…).")

    brand_terms = _num(features, "target_brand_count") + _num(features, "similar_brand_count")
    if brand_terms > 0 and _num(features, "domain_in_brand_list") == 0:
        add(label="Brand look-alike terms", value=f"{int(brand_terms)} match(es)", weight="med",
            detail="Brand names appear in a domain the brand does not own.")

    if _num(features, "random_domain") > 0:
        add(label="Random-looking domain", value="high entropy", weight="med",
            detail="Algorithmically generated domains are common in phishing.")

    if "isKnownTld" in features and _num(features, "isKnownTld") == 0:
        add(label="Uncommon TLD", value="not in known set", weight="low",
            detail="The top-level domain is outside the common, well-policed set.")

    return signals


def content_signals(features: Optional[Dict]) -> List[Signal]:
    """HTML + TLS signals from the content stage's feature dict."""
    signals: List[Signal] = []
    if not features:
        return signals
    add = lambda **kw: signals.append(kw)  # noqa: E731

    passwords = _num(features, "html_num_of_input_password")
    if passwords > 0:
        add(label="Password input field", value=f"{int(passwords)} field(s)", weight="high",
            detail="The page collects credentials.")
    if _num(features, "html_malicious_form") > 0:
        add(label="Suspicious form action", value="flagged", weight="high",
            detail="A form posts to a suspicious or cross-origin target.")
    if _num(features, "html_num_of_form_http") > 0:
        add(label="Form posts over HTTP", value="insecure", weight="med",
            detail="Submitted data would travel unencrypted.")

    iframes = _num(features, "html_num_of_iframe")
    if iframes > 0:
        add(label="Embedded iframe(s)", value=f"{int(iframes)}", weight="med",
            detail="Iframes can load attacker-controlled content or overlays.")

    obfuscation = (_num(features, "html_eval") + _num(features, "html_unescape")
                   + _num(features, "html_from_char_code") + _num(features, "html_char_code_at"))
    if obfuscation > 0:
        add(label="Obfuscated inline script", value="eval / unescape / fromCharCode", weight="med",
            detail="Packed script in the HTML can hide redirect / exfiltration logic "
                   "(parsed, not executed).")

    if _num(features, "tls_has_tls") == 0:
        add(label="No TLS certificate", value="served over HTTP", weight="high",
            detail="A real login page would not be served without HTTPS.")
    else:
        if _num(features, "tls_is_self_signed") > 0:
            add(label="Self-signed certificate", value="untrusted", weight="high",
                detail="The certificate is not issued by a trusted CA.")
        if _num(features, "tls_expired_chain") > 0:
            add(label="Expired certificate chain", value="expired", weight="high",
                detail="The TLS certificate chain is past its validity window.")

    if not signals:
        add(label="No risky content markers", value="clean", weight="safe",
            detail="No credential forms, obfuscation, or TLS problems detected.")
    return signals


def domain_signals(record: Optional[Dict]) -> List[Signal]:
    """DNS / WHOIS signals from the domain stage's raw collected record."""
    signals: List[Signal] = []
    if not record:
        return signals
    add = lambda **kw: signals.append(kw)  # noqa: E731

    rdap = record.get("rdap") or {}
    days = _age_days(rdap.get("registration_date"))
    if days is not None:
        weight = "high" if days < 60 else "med" if days < 400 else "safe"
        add(label="Domain age", value=_age_label(days), weight=weight,
            detail="Freshly registered domains are the single strongest phishing signal."
            if days < 60 else "Established registration lowers risk.")

    registrar = _registrar_name(record)
    if registrar:
        add(label="Registrar", value=registrar, weight="low", detail=None)

    geo = _hosting_geo(record)
    if geo.get("country"):
        add(label="Hosting country", value=geo["country"], weight="low", detail=None)

    if _dnssec_signed(rdap):
        add(label="DNSSEC", value="enabled", weight="safe",
            detail="Signed DNS records — a small positive trust signal.")

    return signals


SIGNAL_BUILDERS = {"url": url_signals, "content": content_signals}


def stage_signals(stage_id: str, features: Optional[Dict], artifacts: Optional[Dict]) -> List[Signal]:
    """Dispatch to the right per-stage signal builder (domain reads its raw record)."""
    if stage_id == "domain":
        return domain_signals((artifacts or {}).get("record"))
    builder = SIGNAL_BUILDERS.get(stage_id)
    return builder(features) if builder else []


# --------------------------------------------------------------------------- evidence
def content_evidence(artifacts: Optional[Dict], features: Optional[Dict]) -> Dict:
    """Page facts (title / final URL / redirects / status / credential form) for the UI."""
    if not artifacts:
        return {}
    tls = _tls_evidence(artifacts.get("tls"))
    if tls.get("present"):
        tls["selfSigned"] = _num(features, "tls_is_self_signed") > 0
        tls["expired"] = _num(features, "tls_expired_chain") > 0
    return {
        "pageTitle": _page_title(artifacts.get("html")),
        "finalUrl": artifacts.get("final_url"),
        "redirects": int(_num(artifacts, "redirect_count")),
        "statusCode": artifacts.get("status_code") or "—",
        "hasPwForm": _num(features, "html_num_of_input_password") > 0,
        "tls": tls,
    }


def domain_evidence(record: Optional[Dict]) -> Dict:
    """WHOIS + DNS evidence (registrar / dates / age / country / records) for the UI."""
    if not record:
        return {}
    rdap = record.get("rdap") or {}
    created = rdap.get("registration_date")
    days = _age_days(created)
    geo = _hosting_geo(record)
    dns = record.get("dns") or {}

    a_records = dns.get("A")
    ns_records = dns.get("NS")
    mx_records = dns.get("MX")
    dns_rows = [
        {"type": "A", "value": ", ".join(a_records[:3]) if a_records else "none"},
        {"type": "NS", "value": next(iter(ns_records), "none") if isinstance(ns_records, dict) and ns_records else "none"},
        {"type": "MX", "value": next(iter(mx_records), "none") if isinstance(mx_records, dict) and mx_records else "none"},
    ]

    return {
        "whois": {
            "registrar": _registrar_name(record) or "unknown",
            "created": _date_str(created) or "unknown",
            "expires": _date_str(rdap.get("expiration_date")) or "unknown",
            "ageDays": days,
            "ageLabel": _age_label(days) if days is not None else "unknown",
            "country": geo.get("country") or "unknown",
            "privacy": _privacy_masked(record),
        },
        "dns": dns_rows,
    }
