# `features/domainradar/transformations/` — feature transformations

> **Vendored code.** Each transformation subclasses `Transformation` (from
> `base_transformation.py`): it exposes a `features` property (the columns it adds, with
> dtypes) and a `transform(df)` method that fills those columns. `extractor.py` chains the
> enabled ones; the content stage uses `html.py` / `tls.py` standalone.

| File | Adds features about |
|------|---------------------|
| `base_transformation.py` | `Transformation` abstract base (the `features` + `transform` contract). |
| `_helpers.py` | Shared math helpers: entropy, simhash, mean/stddev/min/max, md5 hashing, date helpers. |
| `dns.py` | `DNSTransformation` — record presence/counts, TTLs, SOA, DNSSEC, SPF/DKIM/DMARC flags. |
| `ip.py` | `IPTransformation` — per-domain IP counts, IPv4 ratio, address/ASN entropy. |
| `geo.py` | `GeoTransformation` — geographic spread of the resolved IPs (country/lat/long stats). |
| `lexical.py` | `LexicalTransformation` — domain-name lexical features incl. n-gram likelihoods (uses `../data/ngram_freq*.json`). |
| `rdap_dn.py` | `RDAPDomainTransformation` — domain registration age/dates, registrar/entity features. |
| `rdap_ip.py` | `RDAPAddressTransformation` — IP-block RDAP features (prefix, entropy, ...). |
| `drop_columns.py` | `DropColumnsTransformation` — removes temporary/intermediate columns at the end. |
| `html.py` | `HTMLTransformation` — ~85 `html_*` features (tag/script/form/anchor counts, obfuscation-API regex hits, ...). Used by the content stage. |
| `tls.py` | `TLSTransformation` — `tls_*` certificate-chain features (validity, chain/extension/policy stats, SANs). Used by the content stage. |
