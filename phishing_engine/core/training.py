"""Training pipeline.

Reads labeled raw documents from MongoDB (collected by the collectors), extracts
per-stage features using the *same* extractors the prediction pipeline uses, trains a
classifier, and persists it to disk. It never writes to MongoDB.

Models are trained with string class labels ("phish"/"benign") so the resulting
``classes_`` map directly onto the gate labels — no ``label_map`` needed at predict time.
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Tuple

import joblib
import pandas as pd

from phishing_engine.core.pipeline import BaseStage, PipelineContext


def _make_context(document: dict) -> PipelineContext:
    """Build a minimal ``PipelineContext`` from a stored document (for feature extraction)."""
    return PipelineContext(
        url=document.get("url", ""),
        normalized_url=document.get("_id") or document.get("normalized_url", ""),
        domain=document.get("domain", ""),
        label=document.get("label"),
    )


def _make_model(model_type: str):
    """Construct an untrained classifier (``random_forest`` default, or ``gradient_boosting``)."""
    if model_type == "gradient_boosting":
        from sklearn.ensemble import GradientBoostingClassifier

        return GradientBoostingClassifier(random_state=42)
    from sklearn.ensemble import RandomForestClassifier

    return RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)


def collect_training_data(stage: BaseStage, store, limit: int = 0) -> Tuple[List[dict], List[str]]:
    """Extract a feature row + label for every labeled document the stage can use.

    Iterates labeled documents that have the raw data the stage requires, runs the
    stage's feature extractor on each, and returns parallel ``(rows, labels)`` lists.
    Documents that error or yield no features are skipped.
    """
    rows: List[dict] = []
    labels: List[str] = []
    for document in store.iter_labeled(require=stage.requires_raw, limit=limit):
        label = document.get("label")
        if label not in ("phish", "benign"):
            continue
        context = _make_context(document)
        artifacts = stage.build_train_artifacts(document)
        try:
            features = stage.extract_features(context, artifacts)
        except Exception:
            continue
        if not features:
            continue
        rows.append(features)
        labels.append(label)
    return rows, labels


def train_stage(
    stage: BaseStage,
    store,
    output_path: str,
    model_type: str = "random_forest",
    feature_columns: Optional[List[str]] = None,
    limit: int = 0,
) -> dict:
    """Train one stage's model from stored labeled data and persist it to ``output_path``.

    Gathers features via ``collect_training_data``, aligns them to ``feature_columns``
    (if given), fits the chosen classifier, dumps it with joblib, and returns a summary
    (sample counts, feature count, classes, output path). Requires both classes present.
    """
    rows, labels = collect_training_data(stage, store, limit=limit)
    if not rows:
        raise ValueError(f"No training samples found for stage '{stage.stage_id}'")
    if len(set(labels)) < 2:
        raise ValueError(
            f"Stage '{stage.stage_id}' needs both phish and benign samples; got only {set(labels)}"
        )

    df = pd.DataFrame(rows)
    if feature_columns:
        for column in feature_columns:
            if column not in df.columns:
                df[column] = 0
        df = df[feature_columns]

    df = df.replace({True: 1, False: 0})
    df = df.apply(pd.to_numeric, errors="coerce").fillna(0.0)

    model = _make_model(model_type)
    model.fit(df, labels)

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output)

    return {
        "stage": stage.stage_id,
        "samples": len(labels),
        "phish": labels.count("phish"),
        "benign": labels.count("benign"),
        "feature_count": df.shape[1],
        "model_path": str(output),
        "classes": list(getattr(model, "classes_", [])),
    }
