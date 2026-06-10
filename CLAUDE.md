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
- **Prediction pipeline** — scores a single URL through every stage, fusing their
  probabilities into one thresholded verdict. Collects what each stage needs in-memory.
  Never writes to MongoDB.

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
#   --model-type (default random_forest) mirrors model_evaluation.ipynb: logistic_regression,
#   decision_tree, random_forest, extra_trees, gradient_boosting, knn, xgboost, lightgbm, svm
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

Feature code is organized **by stage** under `features/`: `url/`, `domain/`, `content/` are
self-contained packages whose `extractor.py` exposes the adapter class the matching stage
imports (`features.{url,domain,content}` re-export it). `features/common/` holds the shared
`Transformation` base + math helpers used by the domain and content transformations; the
URL lexical analyzer is bundled at `features/url/lexical/`. Everything here is project-owned
and may be edited directly; the `domain/` transformations were derived from DomainRadar and
`url/lexical/` is third-party in origin, so preserve the feature math (it's what the trained
models expect) unless you intend to retrain.

### Stages and the decision cascade

The stages form a **per-stage-threshold cascade** (in `Pipeline.run`, `core/pipeline.py`).
They run in config order; each yields a phishing probability. A stage whose probability is
`>= its threshold` (the stage's own `threshold`, or the pipeline-wide `decision.threshold`
default when the stage doesn't set one — so each transition can demand its own confidence,
e.g. `0.9` for `url`, `0.8` for `content`) is trusted to decide on its own — the run ends
with that stage's own model verdict (`phish` if its probability is `>= 0.5` else `benign`)
and the remaining stages are **never run** (so their live collection is skipped) — while a
probability below the stage's threshold **escalates** the URL to the next stage for further
examination. If no stage exits early,
the verdict comes from **aggregating every stage's probability**: `decision.fallback_aggregation`
(`"mean"` (the default), `"max"`, or `"median"`) combines them into one score that is
`phish` if `>= 0.5` (a fixed boundary, `FALLBACK_DECISION_BOUNDARY`) else `benign`; the
reported `stage_id` is the stage that score came from (the argmax stage for `max`, the
stage nearest the value for `mean`/`median`). If no stage produced a probability (e.g. all models
untrained), the result is `"unknown"`. The threshold and aggregation policy live in the
top-level `pipeline.decision` block of the config. **Note:** the fallback only produces a
`phish` when `threshold > 0.5` — otherwise any stage reaching the 0.5 boundary would have
already early-exited, so the aggregate of the remaining sub-threshold probabilities is
always below 0.5. (This cascade no longer
mirrors the single-threshold *fused* sweep in `model_evaluation.ipynb`, which remains an
offline-evaluation artifact only.)

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
(a warning is logged). It still extracts features but produces no probabilities, so the
cascade simply escalates past it to the next stage and the engine still yields a verdict.
This is deliberate: the engine is usable before every model is trained. The shipped
`domain_model.joblib` works out of the box; `url` and `content` models must be trained
locally first.

### Label handling

Most models trained via `cli.train` fit on **string labels** (`"phish"`/`"benign"`), so
`classes_` maps directly onto the engine labels with no `label_map`. The one exception is
`--model-type xgboost`: XGBoost's sklearn API only accepts integer targets, so `train_stage`
encodes `benign=0`/`phish=1` and the model's `classes_` come out as `0`/`1` — that stage's
config must then carry `label_map: {"1": "phish", "0": "benign"}` (the encoded `train_stage`
summary reports the exact map, and a warning is logged). The shipped `domain_model.joblib`
is a legacy XGBoost model trained the same way, so its stage config carries that same
`label_map`. `ModelRunner._normalize_*` applies the map to both predictions and probabilities.

### Feature alignment

`ModelRunner` aligns the engine's feature mapping to the model's expected columns
(`feature_columns` in config, or inferred from `feature_names_in_`). Missing columns are
filled with `0.0` and reported as `missing_features`; unknown columns are reported as
`extra_features`. This makes feature-set drift visible in the output rather than crashing.

### Logging and error handling

Logging uses the stdlib `logging` module. Library modules log via
`logging.getLogger(__name__)` (the package root carries a `NullHandler`); the entry points
(the three CLIs and the API) call `core/logging_setup.configure_logging()` once, which
attaches a single stderr handler to the `phishing_engine` logger. Level defaults to `INFO`
and is overridable with `PHISHING_ENGINE_LOG_LEVEL` (e.g. `DEBUG` to see the per-lookup
network failures the collectors swallow). `BaseStage.run` guards `collect → extract →
predict`: a raising stage is logged with a full traceback and its message is recorded on
`StageResult.error`, so one stage's failure just makes the cascade escalate past it instead
of crashing the whole prediction.

### Configuration

`config/pipeline.json` drives everything (schema/validation in `core/config.py`, root key
`pipeline`). Each stage entry has `id`, `enabled`, `model_path`, optional `feature_columns`,
`label_map`, an optional per-stage `threshold` (overrides `decision.threshold` for that
stage's early-exit), and stage-specific `options` (timeouts, GeoIP DB paths, data dirs). The
top-level `decision` block holds the pipeline-wide policy (`threshold` default,
`positive_label`, `negative_label`, `fallback_aggregation`); `mongo` holds the connection
(uri/database/collection/domain_collection).

### Storage schema

`storage/mongo.py` (`MongoStore`) is the sole writer, across **two collections**. The
domain record is not embedded per URL (a domain is shared by many URLs); it is stored once
per `(domain, collection date)` in a separate domains collection and referenced by id.
Keying by date keeps point-in-time snapshots — a domain re-collected on a later day gets a
new version, so a URL's training example pairs with the domain state seen when that URL was
collected.

URL collection (one document per normalized URL, keyed by `_id`):

```js
{ _id: <normalized_url>, url, normalized_url, domain,
  label: "phish"|"benign", source,
  created_at, updated_at,
  raw: { domain_record_ref: "<domain>|<YYYY-MM-DD>", content: { html, tls: {...} } },
  raw_collected: { domain_record_at, content_at } }
```

Domains collection (one per `(domain, date)`, keyed by `_id` = `"<domain>|<YYYY-MM-DD>"`):

```js
{ _id: "<domain>|<YYYY-MM-DD>", domain, collected_date, collected_at, record: {...} }
```

On read, `iter_labeled(require="domain_record")` `$lookup`-joins the referenced domain doc
and re-exposes its `record` under `raw.domain_record`, so `build_train_artifacts` (and the
stage contract) is unchanged by the normalization.

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
  core/                 config, pipeline+decision cascade, model_runner, training, registry, urls, serialization
  stages/               url / domain / content (BaseStage lives in core/pipeline.py)
  features/             by-stage packages: url/ domain/ content/ (each w/ extractor.py adapter) + common/
  collectors/           sources/ (phishtank, tranco, search); dns/ip/rdap/domain_record; web_fetch/tls/content
  storage/mongo.py      MongoStore — the ONLY Mongo writer
  models/               domain_model.joblib (shipped); url/content trained locally
  data/GeoLite2-DB/     GeoLite2 City/ASN databases
```

Most directories have their own `README.md`; the root `README.md` has the end-to-end story.
The legacy `url_analyzer/` and `domain_analyzer/` directories are historical reference only
and are **not** imported.
