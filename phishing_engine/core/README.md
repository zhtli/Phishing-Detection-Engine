# `core/` — framework plumbing

Shared, domain-agnostic machinery that the stages, collectors and CLIs build on. Nothing
here knows about a *specific* stage; concrete stages live in [`../stages/`](../stages/README.md).

| File | Purpose |
|------|---------|
| `config.py` | Pydantic models for `config/pipeline.json` (`AppConfig` → `PipelineConfig` → `StageConfig` + `DecisionConfig` + `MongoConfig`) and `load_config()`. |
| `pipeline.py` | The prediction engine: `BaseStage` (the collect→extract→predict contract), `Pipeline.run()` (runs the enabled stages as a single-threshold cascade, stopping at the first confident phish via `Pipeline._build_result`), and the `StageResult` / `PipelineContext` / `PipelineResult` dataclasses. **Never writes to Mongo.** |
| `model_runner.py` | `ModelRunner` — loads a model (`.joblib`/`.pkl`), aligns a feature dict/DataFrame to the model's columns, runs predict/predict_proba, and maps raw class labels to engine labels (`phish`/`benign`). `PredictionOutput` holds the result. |
| `training.py` | The training pipeline: reads labeled docs from Mongo, runs a stage's feature extractor over each, fits a classifier (`random_forest` / `gradient_boosting`), and dumps it to disk. `train_stage()` is the entry point. |
| `registry.py` | Stage registry. Stages register themselves on import; `build_stages()` instantiates them and attaches a `ModelRunner` when the model file exists (missing model ⇒ feature-only). |
| `urls.py` | `normalize_url()` / `extract_domain()` — canonical URL form used as the Mongo `_id`. |
| `serialization.py` | `result_to_dict()` — turn pipeline results into JSON-safe dicts for the CLI/API. |

### How a prediction flows
`Pipeline.run(url)` runs the enabled stages in order as a single-threshold cascade. For
each stage: `collect` → `extract_features` → `predict`. A stage whose phishing probability
is `>= decision.threshold` ends the run with that stage's own model verdict (`phish` if
its probability is `>= 0.5` else `benign`) and the remaining stages are skipped; a
probability below the threshold escalates the URL to the next stage. If no stage exits
early, every stage's probability is aggregated — `mean` (default), `max`, or `median` per
`decision.fallback_aggregation` — and the verdict is `phish` if that aggregate is `>= 0.5`
else `benign` (this fallback only fires `phish` when `threshold > 0.5`). If no stage
produced a probability (e.g. all models untrained) the result is `"unknown"`.
