# `features/` — feature extraction

Turns collected/raw data into the flat feature mappings the models consume. The code is
organized **by stage**: each of `url/`, `domain/`, `content/` is a self-contained package
whose `extractor.py` exposes the adapter class the matching stage imports. `common/` holds
the shared transformation infrastructure.

| Dir | Stage | Purpose |
|-----|-------|---------|
| [`url/`](url/README.md) | `url` | `UrlLexicalFeatureExtractor` + `URL_LEXICAL_FEATURE_COLUMNS`. URL-string lexical features via the bundled `lexical/` analyzer. No network. |
| [`domain/`](domain/README.md) | `domain` | `DomainFeatureExtractor` — flattens a raw domain record and runs the DNS/IP/RDAP/Geo/lexical transformation pipeline, returning a one-row feature DataFrame. |
| [`content/`](content/README.md) | `content` | `ContentFeatureExtractor` — HTML + TLS-certificate features. Reconstructs stored cert DER bytes into x509 objects (`_load_tls_certs`). |
| [`common/`](common/README.md) | — | Shared `Transformation` base + math helpers used by the domain and content transformations. |

### Why adapters?
The same extractors run in two places — the prediction stages (on freshly collected data)
and the training pipeline (on data read back from Mongo) — so feature computation is
identical in both paths. Each stage package's `extractor.py` is the single seam the stage
imports; the heavier transformation code sits behind it.
