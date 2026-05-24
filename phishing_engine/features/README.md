# `features/` — feature extraction

Turns collected/raw data into the flat feature mappings the models consume. The top-level
modules are thin **adapters** the stages call; the heavy lifting lives in two vendored
sub-packages.

| File / dir | Purpose |
|------------|---------|
| `url.py` | `UrlLexicalFeatureExtractor` + `URL_LEXICAL_FEATURE_COLUMNS`. Parses a URL and computes lexical features via the `lexical/` library. No network. |
| `domain.py` | `DomainFeatureExtractor` — runs the `domainradar/` transformation pipeline over a raw domain record, returning a one-row feature DataFrame. |
| `content.py` | `ContentFeatureExtractor` — HTML + TLS features via the `domainradar/` HTML/TLS transformations. Reconstructs stored cert DER bytes into x509 objects (`_load_tls_certs`). |
| [`lexical/`](lexical/README.md) | **Vendored** URL lexical analyzer (domain parser, rule engine, NLP word splitter, gibberish model). |
| [`domainradar/`](domainradar/README.md) | **Vendored** DomainRadar feature extractor and its transformations. |

### Why adapters?
The same extractors run in two places — the prediction stages (on freshly collected data)
and the training pipeline (on data read back from Mongo) — so feature computation is
identical in both paths. The adapters are the single seam between the engine and the
vendored libraries.
