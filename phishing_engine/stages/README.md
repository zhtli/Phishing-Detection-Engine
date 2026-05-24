# `stages/` — detection stages

The three ordered stages of the prediction pipeline. Each subclasses `BaseStage`
(in [`../core/pipeline.py`](../core/README.md)) and implements `collect` → `extract_features`
→ `predict`, plus `build_train_artifacts` (which rebuilds the same inputs from a stored
document so training reuses the exact prediction-time feature extractor).

Importing this package registers all three stages with the registry.

| File | Stage | Input | Fetches? | `requires_raw` |
|------|-------|-------|----------|----------------|
| `url.py` | `UrlStage` | URL string — lexical features | **No** | `None` |
| `domain.py` | `DomainStage` | DNS / IP / RDAP / WHOIS record | Yes (DNS/RDAP) | `"domain_record"` |
| `content.py` | `ContentStage` | HTML + TLS certificate | Yes (HTML + TLS, no JS) | `"content"` |

`requires_raw` tells the training pipeline which `raw.*` sub-document a stage needs; the
`url` stage needs none because it works from the URL string alone.

Each stage delegates the actual feature work to an adapter in
[`../features/`](../features/README.md) and (for the network stages) a collector function
in [`../collectors/`](../collectors/README.md).
