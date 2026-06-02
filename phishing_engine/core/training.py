"""Training pipeline.

Reads labeled raw documents from MongoDB (collected by the collectors), extracts
per-stage features using the *same* extractors the prediction pipeline uses, trains a
classifier, and persists it to disk. It never writes to MongoDB.

Models are trained with string class labels ("phish"/"benign") so the resulting
``classes_`` map directly onto the gate labels — no ``label_map`` needed at predict time.
"""
from __future__ import annotations

import contextlib
import logging
import sys
from pathlib import Path
from typing import List, Optional, Tuple

import joblib
import pandas as pd
from tqdm import tqdm

from phishing_engine.core.pipeline import BaseStage, PipelineContext

logger = logging.getLogger(__name__)


def _make_context(document: dict) -> PipelineContext:
    """Build a minimal ``PipelineContext`` from a stored document (for feature extraction)."""
    return PipelineContext(
        url=document.get("url", ""),
        normalized_url=document.get("_id") or document.get("normalized_url", ""),
        domain=document.get("domain", ""),
        label=document.get("label"),
    )


# XGBoost's sklearn API only accepts integer-encoded targets (0..n_classes-1); the other
# classifiers fit on the "phish"/"benign" strings directly. ``train_stage`` encodes labels
# for these and records the matching ``label_map`` (see the shipped legacy domain model).
_NUMERIC_LABEL_MODELS = frozenset({"xgboost"})

# The ``--model-type`` choices the CLI exposes (mirrors model_evaluation.ipynb's make_models).
MODEL_TYPES = (
    "logistic_regression", "decision_tree", "random_forest", "extra_trees",
    "gradient_boosting", "knn", "xgboost", "lightgbm", "svm",
)


def _make_model(model_type: str, verbose: int = 0):
    """Construct an untrained classifier matching ``model_evaluation.ipynb``'s ``make_models()``.

    Tree/boosting models are returned bare; the scale-sensitive estimators (logistic
    regression, KNN, SVM) are wrapped in a ``StandardScaler`` pipeline, mirroring the
    notebook so a CLI-trained model reproduces the one that was evaluated there. Imports are
    lazy so a missing optional dependency (xgboost/lightgbm) only fails its own branch.
    Unknown values fall back to ``random_forest``.
    """
    rs = 42
    if model_type == "logistic_regression":
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler

        return Pipeline([("scaler", StandardScaler()),
                         ("clf", LogisticRegression(max_iter=1000, random_state=rs))])
    if model_type == "decision_tree":
        from sklearn.tree import DecisionTreeClassifier

        return DecisionTreeClassifier(random_state=rs)
    if model_type == "extra_trees":
        from sklearn.ensemble import ExtraTreesClassifier

        return ExtraTreesClassifier(n_estimators=300, n_jobs=-1, random_state=rs, verbose=verbose)
    if model_type == "gradient_boosting":
        from sklearn.ensemble import GradientBoostingClassifier

        return GradientBoostingClassifier(random_state=rs, verbose=verbose)
    if model_type == "knn":
        from sklearn.neighbors import KNeighborsClassifier
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler

        return Pipeline([("scaler", StandardScaler()), ("clf", KNeighborsClassifier())])
    if model_type == "xgboost":
        from xgboost import XGBClassifier

        return XGBClassifier(n_estimators=400, max_depth=6, learning_rate=0.1,
                             subsample=0.9, colsample_bytree=0.9, eval_metric="logloss",
                             tree_method="hist", n_jobs=-1, random_state=rs)
    if model_type == "lightgbm":
        from lightgbm import LGBMClassifier

        return LGBMClassifier(n_estimators=400, learning_rate=0.05, n_jobs=-1,
                              random_state=rs, verbose=-1)
    if model_type == "svm":
        from sklearn.svm import SVC
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler

        return Pipeline([("scaler", StandardScaler()),
                         ("clf", SVC(kernel="rbf", probability=True, random_state=rs))])
    from sklearn.ensemble import RandomForestClassifier

    return RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=rs, verbose=verbose)


def collect_training_data(stage: BaseStage, store, limit: int = 0) -> Tuple[List[dict], List[str]]:
    """Extract a feature row + label for every labeled document the stage can use.

    Iterates labeled documents that have the raw data the stage requires, runs the
    stage's feature extractor on each, and returns parallel ``(rows, labels)`` lists.
    Documents that error or yield no features are skipped.

    The ``domain`` stage features depend only on the shared domain record, so many URLs
    map to identical rows. Those are deduplicated to one row per ``domain_record_ref``;
    a domain is labeled ``phish`` if *any* of its URLs is phish (else ``benign``).
    """
    rows: List[dict] = []
    labels: List[str] = []
    failed = 0
    empty = 0
    duplicate = 0
    # The domain record is shared across a host's URLs, so collapse to one row per snapshot.
    dedup = stage.requires_raw == "domain_record"
    seen: dict = {}  # domain_record_ref -> index into rows/labels
    total = store.count_labeled(require=stage.requires_raw, limit=limit)
    documents = tqdm(
        store.iter_labeled(require=stage.requires_raw, limit=limit),
        total=total,
        desc=f"{stage.stage_id}: extracting features",
        unit="doc",
    )
    for document in documents:
        label = document.get("label")
        if label not in ("phish", "benign"):
            continue

        key = (document.get("raw") or {}).get("domain_record_ref") if dedup else None
        if key is not None and key in seen:
            # Same domain snapshot already has a row; upgrade its label to phish if needed.
            if label == "phish":
                labels[seen[key]] = "phish"
            duplicate += 1
            continue

        context = _make_context(document)
        artifacts = stage.build_train_artifacts(document)
        try:
            features = stage.extract_features(context, artifacts)
        except Exception:
            failed += 1
            logger.warning(
                "stage %r: feature extraction failed for document %r; skipping",
                stage.stage_id,
                document.get("_id"),
                exc_info=True,
            )
            continue
        if not features:
            empty += 1
            logger.debug(
                "stage %r: document %r produced no features; skipping",
                stage.stage_id,
                document.get("_id"),
            )
            continue
        rows.append(features)
        labels.append(label)
        if key is not None:
            seen[key] = len(rows) - 1
    if failed or empty or duplicate:
        logger.info(
            "stage %r: collected %d training rows (%d failed, %d empty, %d duplicate-domain skipped)",
            stage.stage_id,
            len(rows),
            failed,
            empty,
            duplicate,
        )
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

    # Most classifiers fit on the string labels so their ``classes_`` map straight onto the
    # engine labels. XGBoost needs integer targets, so encode benign=0/phish=1 (the
    # convention model_evaluation.ipynb and the shipped domain model use) and surface the
    # ``label_map`` the stage config must then carry for predictions to map back correctly.
    fit_labels: list = labels
    label_map: Optional[dict] = None
    if model_type in _NUMERIC_LABEL_MODELS:
        fit_labels = [1 if lab == "phish" else 0 for lab in labels]
        label_map = {"1": "phish", "0": "benign"}
        logger.warning(
            "stage %r: %s trains on integer labels; set this stage's config label_map to %s",
            stage.stage_id, model_type, label_map,
        )

    print(
        f"[{stage.stage_id}] fitting {model_type} on {df.shape[0]} samples x {df.shape[1]} features...",
        file=sys.stderr,
        flush=True,
    )
    model = _make_model(model_type, verbose=1)
    # sklearn's verbose output goes to stdout; redirect it to stderr so the JSON summary
    # printed by the CLI stays the only thing on stdout.
    with contextlib.redirect_stdout(sys.stderr):
        model.fit(df, fit_labels)
    print(f"[{stage.stage_id}] training complete.", file=sys.stderr, flush=True)

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output)

    summary = {
        "stage": stage.stage_id,
        "model_type": model_type,
        "samples": len(labels),
        "phish": labels.count("phish"),
        "benign": labels.count("benign"),
        "feature_count": df.shape[1],
        "model_path": str(output),
        "classes": list(getattr(model, "classes_", [])),
    }
    if label_map:
        summary["label_map"] = label_map
    return summary
