# `collectors/` — data collection

Everything that talks to the outside world to gather data. Two roles:

1. **Cron-driven collection** (via [`../cli/`](../cli/README.md) → `MongoStore`): pull URL
   lists and collect raw domain records / page content for stored URLs. These paths are
   the *only* writers to MongoDB.
2. **In-memory collection for prediction**: the same collector functions are called by the
   `domain`/`content` stages at predict time and the result is used directly, never stored.

| File / dir | Purpose |
|------------|---------|
| [`sources/`](sources/README.md) | URL-list sources: PhishTank (phish), Tranco + search (benign). |
| `dns.py` | Async DNS resolution: `find_zone_info`, `collect_dns` (A/AAAA/CNAME/MX/NS/TXT, SOA, DNSSEC, mail-auth flags). *Vendored.* |
| `ip.py` | Per-IP enrichment: `collect_ip_entries` (RDAP, ASN, GeoIP). *Vendored.* |
| `rdap.py` | Domain RDAP/WHOIS lookup: `fetch_domain_rdap` (registration dates, entities, DNSSEC). *Vendored.* |
| `domain_record.py` | `collect_domain_record` (async) / `collect_domain_record_sync` — assemble DNS + IP + RDAP into the one canonical raw domain-record dict that both the domain stage and the collect CLI use. |
| `web_fetch.py` | `fetch_website(url)` — fetch a page's HTML over HTTP. **HTML only — never fetches/executes JS.** |
| `tls.py` | `fetch_tls_data(url)` — lightweight TLS handshake → serializable summary (protocol, cipher, cert DER bytes). |
| `content.py` | `collect_content(url)` — combine `web_fetch` + `tls` into one serializable content dict (html + tls). |

The raw domain-record / content shapes here are exactly what `storage/mongo.py` persists,
so training and prediction see identical inputs.
