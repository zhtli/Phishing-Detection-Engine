# Phishing Detection Engine

This repository implements a modular, multi-stage phishing detection engine. It is designed to be configurable, extensible, and suitable for both batch training/collection workflows and a realtime prediction service.

**Contents**
- **System overview** — architecture, dataflow, and design goals.
- **Components** — description of packages and modules.
- **Configuration** — how to edit and use the pipeline configuration.
- **Deployment & run** — commands to run locally and as a service.
- **Training & model updates** — how to train and deploy new models.
- **Operational notes** — MongoDB setup, thresholds, and validation checklist.

**System Overview**

The engine is organized as a staged pipeline of detectors. Each stage takes a `URL` as input, optionally collects extra data, computes features, runs one or more models/rules, and returns a confidence score. Stages are ordered and configurable: a stage can short-circuit the pipeline if its confidence crosses configured `phish`/`benign` thresholds. Typical default stages:

- `URL` stage — lexical and heuristic rules operating only on the URL string and lightweight metadata (redirects, certificate summary).
- `Domain` stage — DNS, IP, RDAP, WHOIS and other domain-level features.
- `Content` stage — HTML-only content features and TLS/certificate-derived features (explicitly avoids fetching and executing third-party JS).

Design goals:
- Modularity: stages implement a common `BaseStage` interface and are configurable in order and parameters.
- Efficiency: early-exit gating reduces expensive fetches and model runs.
- Reuse: adapters are provided to re-use existing `url_analyzer` and `domain_analyzer` code.
- Traceability: pipeline writes a unified per-URL document to MongoDB with per-stage results embedded and also writes label-specific records into separate benign/phish collections.

**Components**

- **phishing_engine/** — new package containing the pipeline implementation, stages, feature adaptors, collectors, CLI and API scaffolding.
	- `pipeline.py` — core `Pipeline` and `BaseStage` classes with gating logic.
	- `stages/` — implementations: `url_stage.py`, `domain_stage.py`, `content_stage.py`.
	- `features/` — adapters: `url_features.py`, `domain_features.py`, `content_features.py`, `tls_collector.py`.
	- `storage/mongo.py` — `MongoStore` for unified document upserts and per-stage result writes; supports separate benign and phish collections.
	- `collectors/` — data collectors (PhishTank, Tranco, search-term connectors).
	- `cli.py` — command-line entrypoint for collection, prediction, and (placeholder) training orchestration.
	- `api.py` — FastAPI app exposing `/predict` and `/health` endpoints for runtime predictions.

- **url_analyzer/** and **domain_analyzer/** — existing code reused by adapters for feature extraction and collectors (DNS, RDAP, lexical rules, cert parsing).

**Configuration**

The pipeline is driven by a JSON configuration file. Default path used by CLI/API: `config/pipeline.json` (adjust as needed). Important configuration sections:

- `mongo`:
	- `uri`, `database` — Mongo connection.
	- `collection` — default unified documents collection.
	- `benign_collection`, `phish_collection` — optional label-specific collection names where a labeled copy can be written.
- `stages` — ordered list of stage definitions. Each stage entry contains: `id`, `type` (url|domain|content), `model_path` (optional), and `options` specific to the stage.
- `gates` / `thresholds` — per-stage `phish_threshold` and `benign_threshold` values in [0,1]. When a stage returns a score >= `phish_threshold` the pipeline exits with `phish`. If score <= `benign_threshold` it exits with `benign`. Otherwise the pipeline continues.

Example (high level):

```json
{
	"mongo": { "uri": "mongodb://localhost:27017", "database": "phishing_engine", "collection": "urls", "benign_collection": "benign", "phish_collection": "phish" },
	"stages": [
		{ "id": "url", "type": "url", "options": { "include_fetch_features": true }, "gates": { "phish_threshold": 0.9, "benign_threshold": 0.05 } },
		{ "id": "domain", "type": "domain", "options": {}, "gates": { "phish_threshold": 0.8, "benign_threshold": 0.1 } },
		{ "id": "content", "type": "content", "options": { "store_raw_html": false }, "gates": { "phish_threshold": 0.7, "benign_threshold": 0.2 } }
	]
}
```

Note: exact config schema and keys are exposed in `phishing_engine/config.py`.

**Running locally (CLI)**

Short examples using the CLI. From the repository root:

```bash
# Run a single prediction against the CLI (returns JSON to stdout)
python -m phishing_engine.cli predict --url "http://example.com" --config config/pipeline.json

# Collect PhishTank feed into Mongo (labelled as phishing)
python -m phishing_engine.cli collect_phishtank --config config/pipeline.json --limit 1000

# Collect Tranco sample (benign dataset)
python -m phishing_engine.cli collect_tranco --config config/pipeline.json --sample-size 500
```

The CLI offers `predict`, `collect_*` commands and a `train` placeholder (see training section).

**Running as a service (FastAPI)**

To start the prediction API (production use should use a process manager):

```bash
# install dependencies
pip install -r requirements.txt

# start the service
uvicorn phishing_engine.api:app --host 0.0.0.0 --port 8000 --workers 1
```

Endpoints:
- `GET /health` — simple liveness.
- `POST /predict` — JSON body {"url": "https://..."} returns staged results and final decision.

**MongoDB setup**

1. Install and run MongoDB (example for Ubuntu):

```bash
sudo apt update
sudo apt install -y mongodb
sudo systemctl enable --now mongodb
```

2. Create database and indexes (optional):

```js
use phishing_engine
db.urls.createIndex({ normalized_url: 1 }, { unique: true })
db.urls.createIndex({ last_decision: 1 })
```

The pipeline's `MongoStore` will upsert a unified document keyed by `normalized_url` and write per-stage results under `stages.<stage_id>`. If a label is present in the context, a copy is optionally written into the configured `benign_collection` or `phish_collection`.

**Training & Model Updates**

Training is intentionally separated from runtime prediction. The current repo provides the scaffolding and a `train` CLI placeholder. Recommended workflow for training a stage model:

1. Collect labeled data into Mongo using the `collect_*` commands (PhishTank for phishing, Tranco/search for benign).
2. Export labeled samples and run feature extraction using the same feature adaptors used in the pipeline to ensure feature parity.
3. Train multiple candidate models (e.g., XGBoost, LightGBM, logistic regression), evaluate with cross validation, choose the best model by precision/recall and desired operating point.
4. Persist the chosen model with `joblib.dump()` and place the file in a models directory. Update `config/pipeline.json` for that stage's `model_path` and adjust `gates` thresholds.

Example training snippet (Python):

```python
from joblib import dump
# X_train, y_train = ... # produced by the repo's feature extractors
# model = MyTrainer().fit(X_train, y_train)
dump(model, "models/content_model.joblib")
```

After publishing the model, update the stage entry in the config with `"model_path": "models/content_model.joblib"` and reload the service.

**Threshold tuning and gating**

Set `phish_threshold` and `benign_threshold` per stage based on validation ROC/PR curves and desired operational tradeoffs. Typical pattern:

- Conservative early thresholds in `URL` stage to only short-circuit very clear cases (e.g., `phish_threshold` high like 0.9).
- Looser thresholds in final `Content` stage where features are richer.

**Operational checklist & validation**

- Verify Mongo connectivity and named collections in your `config/pipeline.json`.
- Test the CLI `predict` against known benign and phishing examples to verify expected decisions.
- Run a small batch collection and ensure documents appear under `urls` and in the label-specific collections when appropriate.
- Monitor latency of the `content` stage and tune `store_raw_html` / `max_html_bytes` options to keep storage bounded.

**Security & privacy notes**

- The pipeline avoids fetching third-party JS during normal predictions (content stage fetch is HTML-only) to limit privacy risks and network usage.
- Stored HTML and certificates may include sensitive data; manage access and retention policies accordingly.

**Next steps & TODOs**

- Implement the `train` orchestration to produce repeatable, versioned models.
- Add unit and integration tests for end-to-end collection → extraction → predict flows.
- Implement rate-limiting and polite crawling (respect robots.txt, add delays and user-agent rotation) in collectors.
- Add CI to validate import surface and linting.

If you'd like, I can add a runnable `examples/` folder with a small dataset and a ready-to-run training notebook, or implement the `train` command to fully automate model training and threshold selection.

--
Generated on: 2026-05-23

