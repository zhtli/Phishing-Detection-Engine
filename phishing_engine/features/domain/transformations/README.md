# `features/domain/transformations/` — domain feature transformations

> Each transformation subclasses `Transformation` (from [`../../common/base.py`](../../common/base.py)):
> it exposes a `features` property (the columns it adds, with dtypes) and a `transform(df)`
> method that fills those columns. `pipeline.py` chains the enabled ones. Shared math
> helpers live in [`../../common/helpers.py`](../../common/helpers.py).

| File | Adds features about |
|------|---------------------|
| `dns.py` | `DNSTransformation` — record presence/counts, TTLs, SOA, DNSSEC, SPF/DKIM/DMARC flags. |
| `ip.py` | `IPTransformation` — per-domain IP counts, IPv4 ratio, address/ASN entropy. |
| `geo.py` | `GeoTransformation` — geographic spread of the resolved IPs (country/lat/long stats). |
| `lexical.py` | `LexicalTransformation` — domain-name lexical features incl. n-gram likelihoods (uses `../data/ngram_freq*.json`). |
| `rdap_dn.py` | `RDAPDomainTransformation` — domain registration age/dates, registrar/entity features. |
| `rdap_ip.py` | `RDAPAddressTransformation` — IP-block RDAP features (prefix, entropy, ...). |
| `drop_columns.py` | `DropColumnsTransformation` — removes temporary/intermediate columns at the end. |

> HTML/TLS transformations belong to the content stage and live in
> [`../../content/transformations/`](../../content/transformations/).
