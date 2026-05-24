# `models/` — trained model artifacts

Holds the per-stage classifier files referenced by `model_path` in
`config/pipeline.json`. `ModelRunner` loads them with `joblib` (works for both `.joblib`
and `.pkl`).

| File | Stage | Origin |
|------|-------|--------|
| `domain_model.joblib` | `domain` | **Shipped.** Pre-existing XGBoost pipeline; uses `label_map {"1":"phish","0":"benign"}`. |
| `url_model.pkl` | `url` | **Trained locally** via `python -m phishing_engine.cli.train --stage url`. Not shipped. |
| `content_model.joblib` | `content` | **Trained locally** via `--stage content`. Not shipped. |

Models trained by the engine use string class labels (`phish`/`benign`), so no
`label_map` is needed for them. A stage whose model file is absent runs feature-only until
it is trained (the pipeline still works, gating just passes that stage through).
