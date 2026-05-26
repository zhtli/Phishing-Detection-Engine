# Phishing Detection Engine

A modular, multi-stage phishing detection engine. All code and logic lives in the
self-contained `phishing_engine/` package — it has **no dependency on the legacy
`url_analyzer/` and `domain_analyzer/` directories** (those are kept only as historical
reference and are no longer imported).

## Architecture

There are **two pipelines** plus a set of **collectors**, with a clean separation of
responsibilities:

```
            sources                         MongoDB (raw data)              models on disk
  ┌──────────────────────────┐        ┌──────────────────────────┐
  │ PhishTank / Tranco /     │  write │ url_documents:           │  read   ┌──────────────┐
  │ search  (URL + label)    │ ─────> │  url, label, source,     │ ──────> │  TRAINING    │ ──▶ *.joblib / *.pkl
  │ domain record (DNS/IP/   │        │  raw.domain_record,      │         │  pipeline    │
  │ RDAP), page content      │        │  raw.content (html/tls)  │         └──────────────┘
  └──────────────────────────┘        └──────────────────────────┘
        COLLECTORS (cron)                   (collectors are the ONLY writers)

  realtime URL ─▶ PREDICTION pipeline ─▶ decision   (collects in-memory, never writes Mongo)
```

- **Collectors** extract data from sources and are the *only* component that writes to
  MongoDB. They store the raw data (URL+label, raw domain records, raw page content).
- The **training pipeline** reads labeled raw documents from MongoDB, extracts features
  with the same extractors used at prediction time, trains a classifier per stage, and
  writes the model to disk. It does not write to MongoDB.
- The **prediction pipeline** scores a single URL through ordered, gated stages. Each
  stage collects whatever it needs in-memory; the pipeline never writes to MongoDB.

### Stages (prediction)

Stages run in order with early-exit gating: a stage short-circuits the pipeline when its
score crosses the configured `phish_threshold` / `benign_threshold`.

| Stage | Input | Fetches network? |
|-------|-------|------------------|
| `url`     | URL string only — lexical features | **No** (never fetches the page) |
| `domain`  | DNS / IP / RDAP / WHOIS record | Yes (DNS/RDAP) |
| `content` | HTML + TLS certificate features | Yes (HTML + TLS, no JS) |

## Package layout

```
phishing_engine/
  api.py                  # FastAPI /predict + /health
  cli/
    predict.py            # prediction CLI
    train.py              # training CLI
    collect.py            # collectors CLI (cron-friendly subcommands)
  core/                   # framework plumbing
    config.py             # config models + loader
    pipeline.py           # prediction pipeline + gating (no Mongo writes)
    training.py           # training pipeline
    model_runner.py       # ModelRunner (load model, align features, predict)
    registry.py           # stage registry + build_stages
    urls.py               # URL normalization
    serialization.py      # result -> JSON-safe dict
  stages/                 # url / domain / content stages (BaseStage lives in core.pipeline)
  features/               # feature extraction, organized by stage
    url/                  # url stage: extractor.py + lexical/ analyzer (+ input data + gib model)
    domain/               # domain stage: extractor.py + pipeline + flatten + transformations/ + ngram data/
    content/              # content stage: extractor.py + transformations/{html,tls}
    common/               # shared Transformation base + math helpers
  collectors/
    sources/              # URL-list sources: phishtank.py tranco.py search.py
    dns.py ip.py rdap.py domain_record.py      # raw domain record collection
    web_fetch.py tls.py content.py             # raw page content (HTML + TLS)
  storage/mongo.py        # the ONLY Mongo writer + read helpers for training
  models/                 # domain_model.joblib (shipped); url/content models trained locally
  data/GeoLite2-DB/       # GeoLite2 City/ASN databases
```

## Configuration

Driven by `config/pipeline.json` (schema in `phishing_engine/core/config.py`):

- `mongo`: `uri`, `database`, `collection`.
- `stages`: ordered list. Each has `id`, `enabled`, `model_path`, optional
  `feature_columns`, `label_map`, `gate` (`phish_threshold`, `benign_threshold`,
  `positive_label`, `negative_label`), and stage-specific `options`.

A stage whose `model_path` does not exist yet runs **feature-only** (no prediction, the
gate passes the URL to the next stage), so the engine is usable before every model is
trained.

## Install

```bash
pip install -r requirements.txt
# the url stage's word splitter needs the system enchant library, e.g.:
#   sudo apt-get install libenchant-2-2
```

## Collectors (run by cron — the only Mongo writers)

```bash
# URL-list sources. Each command collects URLs AND fills in their raw
# data (raw.domain_record / raw.content) in the same run, processing every
# stored URL still missing that data.
python -m phishing_engine.cli.collect phishtank --limit 2000
python -m phishing_engine.cli.collect tranco --list-path top-1m.csv --sample-size 2000
python -m phishing_engine.cli.collect search --terms-file g-trends.csv --max-results 10
```

### Incremental PhishTank collection

The `phishtank` collector runs **incrementally by default**. After each successful run it
saves the run's start time as a watermark in Mongo (`collector_state` collection, keyed by
`phishtank`). The next run with no explicit time filter only ingests entries verified
since that watermark, so repeated cron runs pick up just the new feed updates instead of
re-pulling the whole feed.

```bash
# First run — no watermark yet, so this seeds it. Pull a backfill window, e.g. last 7 days:
python -m phishing_engine.cli.collect phishtank --days 7 --limit 2000

# Subsequent runs — no time flags needed. Pulls only entries verified since the last run:
python -m phishing_engine.cli.collect phishtank --limit 2000

# Override the watermark for one run (these win over the saved watermark):
python -m phishing_engine.cli.collect phishtank --since 2026-05-20T00:00:00Z
python -m phishing_engine.cli.collect phishtank --days 3

# Ignore the watermark and pull the entire current feed (e.g. a one-off full backfill):
python -m phishing_engine.cli.collect phishtank --full --limit 5000
```

Notes:
- The watermark is advanced only after a run succeeds, so a failed fetch/ingest leaves it
  untouched and the next run retries the same window.
- It is anchored to the run's **start** time (not end), so there's no gap at the boundary;
  any URLs re-seen are deduped by the upsert on the URL `_id`.
- Explicit `--since`/`--days` still advance the watermark afterward — only `--full` skips
  reading it.

### Resumable search collection

The `search` collector is **resumable per term**. It searches one term, ingests that
term's URLs (with their domain record + content), then records the term as done in Mongo
(`collector_state` collection, `_id: "search:done_terms"`). A re-run skips terms already
done, so a crash or a DuckDuckGo rate-limit block costs no progress — DuckDuckGo throttles
scraped traffic aggressively, so long runs commonly get blocked partway through.

```bash
# First run — searches every term, recording each as done as it completes:
python -m phishing_engine.cli.collect search --terms-file g-trends.csv --max-results 10

# Re-run after a crash/rate-limit block — resumes, skipping terms already done:
python -m phishing_engine.cli.collect search --terms-file g-trends.csv --max-results 10

# Re-search all terms, ignoring the saved done-terms set (e.g. to refresh results):
python -m phishing_engine.cli.collect search --terms-file g-trends.csv --full
```

Notes:
- A term is recorded as done only after its URLs are ingested, so an interrupted term is
  retried on the next run (re-ingested URLs are deduped by the upsert on the URL `_id`).
- A single term's search failure (`DDGSException`) is logged and skipped, not fatal. After
  **5 consecutive** failures the run stops early — that streak is the rate-limit signature,
  and the remaining terms resume on a later run once the block clears.
- `--full` bypasses the done-terms set for that run but does **not** clear it; new terms
  added to the file are still picked up by a normal (non-`--full`) run.
- The done-terms set is global per `source="search"`, shared across different terms files.

Example crontab:

```cron
# Incremental: each run pulls only feeds verified since the previous run.
*/30 * * * * cd /srv/engine && python -m phishing_engine.cli.collect phishtank --limit 2000
0    3 * * * cd /srv/engine && python -m phishing_engine.cli.collect tranco --list-path /srv/engine/tranco.csv --sample-size 2000
```

## Training

```bash
python -m phishing_engine.cli.train --stage url      # trains phishing_engine/models/url_model.pkl
python -m phishing_engine.cli.train --stage domain   # trains domain model
python -m phishing_engine.cli.train --stage content  # trains content model
python -m phishing_engine.cli.train --stage all --model-type gradient_boosting
```

Models are trained with string labels (`phish`/`benign`) so no `label_map` is needed at
prediction time. The shipped `domain_model.joblib` is the pre-existing XGBoost model
(uses `label_map {"1":"phish","0":"benign"}`). The `url` and `content` models must be
trained locally before those stages will predict.

> Note: the `url` stage is lexical-only by design, so the legacy `url_analyzer` model
> (which relied on fetched cert/redirect features) is not reused — retrain it with
> `cli.train`.

## Prediction

```bash
# CLI (prints JSON, no Mongo writes)
python -m phishing_engine.cli.predict --url "http://example.com" --config config/pipeline.json

# Service
uvicorn phishing_engine.api:app --host 0.0.0.0 --port 8000 --workers 1
#   GET  /health
#   POST /predict   body: {"url": "https://..."}
```

## MongoDB

```bash
sudo systemctl enable --now mongod
```

Documents (one per normalized URL, written only by collectors):

```js
{
  _id: "<normalized_url>", url, normalized_url, domain,
  label: "phish" | "benign",
  source: "phishtank" | "tranco" | "search",
  created_at, updated_at,
  raw: { domain_record: {...}, content: { html, tls: {...} } },
  raw_collected: { domain_record_at, content_at }
}
```

Certificates are stored as DER bytes under `raw.content.tls.certificates_der`; the content
feature extractor reconstructs them at feature time.
