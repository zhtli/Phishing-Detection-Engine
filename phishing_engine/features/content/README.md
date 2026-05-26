# `features/content/` — content stage features

Feature extraction for the **content stage**: HTML + TLS-certificate features for a fetched
page. Derived from the DomainRadar feature extractor and now maintained as part of this
project.

| File / dir | What it does |
|------------|--------------|
| `extractor.py` | `ContentFeatureExtractor` — the adapter the stage imports. Runs the HTML and TLS transformations over `{html, tls}` and returns a flat feature dict. Reconstructs stored cert DER bytes into x509 objects (`_load_tls_certs`). |
| `transformations/html.py` | `HTMLTransformation` — ~85 `html_*` features (tag/script/form/anchor counts, obfuscation-API regex hits, ...). |
| `transformations/tls.py` | `TLSTransformation` — `tls_*` certificate-chain features (validity, chain/extension/policy stats, SANs). |

The shared `Transformation` base and helpers live in [`../common/`](../common/).
