# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A modular, multi-stage phishing detection engine. All logic lives in the self-contained
`phishing_engine/` package. There are **three subsystems** with strict separation of
responsibilities:

- **Collectors** — extract data from sources and are the **only** component that writes to
  MongoDB (raw URL+label, raw domain records, raw page content).
- **Training pipeline** — reads labeled raw documents from MongoDB, extracts features, fits
  a classifier per stage, writes the model to disk. Never writes to MongoDB.
- **Prediction pipeline** — scores a single URL through ordered, gated stages. Collects
  what each stage needs in-memory. Never writes to MongoDB.

## Commands

All entrypoints are run as modules and default to `config/pipeline.json`.

```bash
# Predict (prints JSON, no Mongo writes)
python -m phishing_engine.cli.predict --url "http://example.com" --config config/pipeline.json

# Serve the same pipeline over HTTP (config path from $PHISHING_ENGINE_CONFIG)
uvicorn phishing_engine.api:app --host 0.0.0.0 --port 8000 --workers 1
#   GET /health   POST /predict  body: {"url": "https://..."}

# Collect (the ONLY Mongo writers; each also collects raw domain record + content inline)
python -m phishing_engine.cli.collect phishtank --limit 2000
python -m phishing_engine.cli.collect tranco --list-path tranco.csv --sample-size 500
python -m phishing_engine.cli.collect search --terms-file terms.txt --max-results 10

# Train one stage (or 'all') from labeled Mongo data; writes model to disk
python -m phishing_engine.cli.train --stage url       # -> models/url_model.pkl
python -m phishing_engine.cli.train --stage domain
python -m phishing_engine.cli.train --stage content
python -m phishing_engine.cli.train --stage all --model-type gradient_boosting
```

There is **no automated test suite, linter, or build config** (no pytest/pyproject/Makefile).
Verify changes by running the predict CLI, or with `python -m py_compile` for syntax checks.

## Environment

A `.venv/` exists and the Python environment is managed by the user. Do **not** run
`pip install` (or otherwise mutate the environment) without explicit approval; prefer
non-executing checks (`py_compile`, grep) for verification. The `url` stage's word splitter
needs the system `libenchant-2-2` library (`pyenchant`). GeoLite2 City/ASN DBs live under
`phishing_engine/data/GeoLite2-DB/`. MongoDB must be running for collect/train.

## Architecture

### The stage contract (the central abstraction)

`BaseStage` (in `core/pipeline.py`) defines `collect → extract_features → predict`. The
**same `extract_features` runs in both pipelines**, which is what guarantees train/predict
feature parity:

- At **prediction** time, `collect()` gathers raw data live (in-memory).
- At **training** time, `build_train_artifacts(document)` rebuilds the same artifacts dict
  from the `raw.*` sub-documents the collectors stored in Mongo, then the identical
  `extract_features` runs on them.

The adapters in `features/{url,domain,content}.py` are the single seam between the engine
and two **vendored** libraries: `features/lexical/` (URL lexical analysis) and
`features/domainradar/` (DNS/IP/RDAP/TLS/HTML transformations). Touch the adapters, not the
vendored code, when wiring features.

### Stages and gating

Stages run in config order with **early-exit gating** (`gate_decision` in `core/pipeline.py`):
the first stage whose probability crosses `phish_threshold` / `benign_threshold`
short-circuits and returns its decision; if none do, the result is `"unknown"`.

| Stage | `requires_raw` (training) | Fetches at predict time | Model input path |
|-------|---------------------------|-------------------------|------------------|
| `url`     | `None` (URL string only) | No (never fetches page) | `predict_from_dict` (flat dict) |
| `domain`  | `domain_record`          | DNS/IP/RDAP/WHOIS       | `predict_from_dataframe` (extractor yields a DataFrame) |
| `content` | `content`                | HTML + TLS cert (no JS) | `predict_from_dict` (flat dict) |

Stages register themselves by id when `phishing_engine.stages` is imported — every
entrypoint does `import phishing_engine.stages  # noqa` for this side effect. `build_stages`
(in `core/registry.py`) instantiates them from config.

### Feature-only degradation (key invariant)

A stage whose `model_path` does **not** exist on disk is built **without** a `ModelRunner`
(a warning is printed to stderr). It still extracts features but produces no probabilities,
so `gate_decision` returns `"continue"` and the URL flows to the next stage. This is
deliberate: the engine is usable before every model is trained. The shipped
`domain_model.joblib` works out of the box; `url` and `content` models must be trained
locally first.

### Label handling

Models trained via `cli.train` use **string labels** (`"phish"`/`"benign"`), so `classes_`
maps directly onto gate labels with no `label_map`. The shipped `domain_model.joblib` is a
legacy XGBoost model trained on `0`/`1`, so its stage config carries
`label_map: {"1": "phish", "0": "benign"}`. `ModelRunner._normalize_*` applies this map to
both predictions and probabilities.

### Feature alignment

`ModelRunner` aligns the engine's feature mapping to the model's expected columns
(`feature_columns` in config, or inferred from `feature_names_in_`). Missing columns are
filled with `0.0` and reported as `missing_features`; unknown columns are reported as
`extra_features`. This makes feature-set drift visible in the output rather than crashing.

### Configuration

`config/pipeline.json` drives everything (schema/validation in `core/config.py`, root key
`pipeline`). Each stage entry has `id`, `enabled`, `model_path`, optional `feature_columns`,
`label_map`, a `gate` block, and stage-specific `options` (timeouts, GeoIP DB paths, data
dirs). `mongo` holds the connection (uri/database/collection).

### Storage schema

`storage/mongo.py` (`MongoStore`) is the sole writer. One document per normalized URL,
keyed by `_id`:

```js
{ _id: <normalized_url>, url, normalized_url, domain,
  label: "phish"|"benign", source,
  created_at, updated_at,
  raw: { domain_record: {...}, content: { html, tls: {...} } },
  raw_collected: { domain_record_at, content_at } }
```

TLS certificates are stored as DER bytes under `raw.content.tls`; the content feature
extractor reconstructs x509 objects at feature time.

### Collection timing

The collect CLI stores each URL and **immediately** collects its raw domain record + page
content inline (see `_collect_for_url` in `cli/collect.py`) rather than deferring — phishing
URLs are short-lived, so a later pass would often find them dead. The two fetches are
independent; a failure on one is logged and skipped.

## Package map

```
phishing_engine/
  api.py                FastAPI /predict + /health (lazy-built, reused pipeline)
  cli/                  predict.py, train.py, collect.py
  core/                 config, pipeline+gating, model_runner, training, registry, urls, serialization
  stages/               url / domain / content (BaseStage lives in core/pipeline.py)
  features/             url.py domain.py content.py adapters; vendored lexical/ and domainradar/
  collectors/           sources/ (phishtank, tranco, search); dns/ip/rdap/domain_record; web_fetch/tls/content
  storage/mongo.py      MongoStore — the ONLY Mongo writer
  models/               domain_model.joblib (shipped); url/content trained locally
  data/GeoLite2-DB/     GeoLite2 City/ASN databases
```

Most directories have their own `README.md`; the root `README.md` has the end-to-end story.
The legacy `url_analyzer/` and `domain_analyzer/` directories are historical reference only
and are **not** imported.
