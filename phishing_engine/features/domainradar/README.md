# `features/domainradar/` — vendored DomainRadar feature extractor

> **Vendored code** (DomainRadar feature extractor, authored by Ondřej Ondryáš et al.),
> copied in and adjusted only for import-cleanliness (relative imports within the
> package). Entry points used by the engine: `extractor.init_transformations(config)` and
> `extractor.extract_features([record])`, called via [`../domain.py`](../domain.py) and
> [`../content.py`](../content.py).

| File / dir | What it does |
|------------|--------------|
| `extractor.py` | Orchestrator. `init_transformations(config)` builds the enabled transformation list (default: `dns`, `ip`, `geo`, `lexical`, `rdap_dn`, `rdap_ip`, `drop`); `extract_features(raw_data)` runs them over raw records and returns a feature `DataFrame` plus an errors dict. |
| `compat.py` | `CompatibilityTransformation` — reshapes a raw domain record (the shape produced by `collectors/domain_record.py` and stored in Mongo) into the flat column layout the transformations expect. |
| `util.py` | `get_safe(dict, "a.b.c")` — safe nested lookup (the only helper `compat` needs; the rest of the original util module was dropped). |
| [`transformations/`](transformations/README.md) | The individual feature transformations (DNS, IP, Geo, lexical, RDAP, HTML, TLS, column-drop). |
| `data/` | n-gram frequency tables (`ngram_freq*.json`) used by the lexical transformation. |

### Two consumers, two transformation sets
- The **domain stage** calls `init_transformations` with the default set (no HTML/TLS) and
  `extract_features` over a full domain record.
- The **content stage** uses only the `HTMLTransformation` and `TLSTransformation`
  classes directly (see `transformations/html.py` and `transformations/tls.py`), not the
  orchestrator.
