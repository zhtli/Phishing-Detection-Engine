# `phishing_engine/` — package overview

Self-contained phishing detection engine. Three things live here: a **prediction
pipeline**, a **training pipeline**, and a set of **collectors**. The repository root
`README.md` has the end-to-end story; this file is a map of the package directories.

| Directory | What it holds |
|-----------|---------------|
| [`core/`](core/README.md) | Framework plumbing: config, the prediction pipeline + gating, the model runner, training, the stage registry, URL/serialization helpers. |
| [`stages/`](stages/README.md) | The three concrete detection stages: `url`, `domain`, `content`. |
| [`features/`](features/README.md) | Feature extractors, organized by stage: [`url/`](features/url/README.md), [`domain/`](features/domain/README.md), [`content/`](features/content/README.md), plus shared [`common/`](features/common/README.md). |
| [`collectors/`](collectors/README.md) | Data collection. [`sources/`](collectors/sources/README.md) pull URL lists; `dns/ip/rdap/domain_record` build raw domain records; `web_fetch/tls/content` fetch page content. |
| [`storage/`](storage/README.md) | `MongoStore` — the **only** component that writes to MongoDB. |
| [`cli/`](cli/README.md) | The three command-line tools: `predict`, `train`, `collect`. |
| [`models/`](models/README.md) | Trained model artifacts (`*.joblib` / `*.pkl`). |
| [`data/`](data/README.md) | Static data assets (GeoLite2 databases). |
| `api.py` | FastAPI service exposing `/predict` and `/health`. |

### Data flow in one line
Collectors write raw data to Mongo → the training pipeline reads it and writes models to
disk → the prediction pipeline loads those models and scores URLs live (no Mongo writes).
