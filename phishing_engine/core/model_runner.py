"""Model loading and inference.

``ModelRunner`` wraps a persisted scikit-learn/XGBoost estimator and adapts the engine's
feature mappings to whatever the model expects: it aligns columns by name, fills gaps,
runs ``predict``/``predict_proba``, and maps raw class labels onto the engine's
``phish``/``benign`` vocabulary via an optional ``label_map``.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import joblib
import pandas as pd


@dataclass
class PredictionOutput:
    """A single prediction: the resolved label, per-label probabilities, the confidence
    (probability of the chosen label), and which configured features were missing/extra
    relative to the input."""

    label: Optional[str]
    probabilities: Dict[str, float]
    confidence: Optional[float]
    missing_features: List[str]
    extra_features: List[str]
    raw_label: Optional[str] = None


class ModelRunner:
    """Loads a model from disk and runs predictions with feature/label alignment."""

    def __init__(
        self,
        model_path: str | Path,
        feature_columns: Optional[List[str]] = None,
        label_map: Optional[Dict[str, str]] = None,
    ):
        """Load the model and decide the expected feature ordering.

        ``feature_columns`` pins the input ordering; if omitted it is inferred from the
        model's ``feature_names_in_``. ``label_map`` translates the model's raw class
        labels (e.g. ``"0"``/``"1"``) to engine labels (``"benign"``/``"phish"``).
        """
        self.model_path = Path(model_path)
        self.model = self._load_model(self.model_path)
        self.feature_columns = feature_columns or self._infer_feature_columns()
        self.label_map = label_map or {}

    def _load_model(self, path: Path):
        """Load the estimator from disk.

        ``joblib.load`` reads both joblib-dumped models and plain pickle files, so it
        works for ``.joblib`` and ``.pkl`` models alike.
        """
        if not path.exists():
            raise FileNotFoundError(f"Model not found: {path}")
        return joblib.load(path)

    def _infer_feature_columns(self) -> Optional[List[str]]:
        """Recover the training-time feature ordering from the model (or a pipeline step)."""
        if hasattr(self.model, "feature_names_in_"):
            return list(self.model.feature_names_in_)
        if hasattr(self.model, "named_steps"):
            for step in self.model.named_steps.values():
                if hasattr(step, "feature_names_in_"):
                    return list(step.feature_names_in_)
        return None

    def _normalize_label(self, label: str) -> str:
        """Map a raw class label to the engine label via ``label_map`` (identity if absent)."""
        return self.label_map.get(str(label), str(label))

    def _normalize_probabilities(self, classes, proba: np.ndarray) -> Dict[str, float]:
        """Build a ``{engine_label: probability}`` dict, summing classes that map together."""
        probabilities: Dict[str, float] = {}
        for raw_label, value in zip(classes, proba):
            normalized = self._normalize_label(raw_label)
            probabilities[normalized] = probabilities.get(normalized, 0.0) + float(value)
        return probabilities

    def _predict(self, vector: np.ndarray) -> PredictionOutput:
        """Run predict/predict_proba on an already-aligned feature matrix (one row)."""
        raw_pred = self.model.predict(vector)[0]
        raw_label = str(raw_pred)
        normalized_label = self._normalize_label(raw_label)

        probabilities: Dict[str, float] = {}
        confidence = None
        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(vector)[0]
            probabilities = self._normalize_probabilities(self.model.classes_, proba)
            confidence = probabilities.get(normalized_label)

        return PredictionOutput(
            label=normalized_label,
            probabilities=probabilities,
            confidence=confidence,
            missing_features=[],
            extra_features=[],
            raw_label=raw_label,
        )

    def _vector_from_dict(self, features: Dict[str, object]) -> Tuple[np.ndarray, List[str], List[str]]:
        """Project a feature dict onto ``feature_columns`` as a numeric row vector.

        Missing columns are filled with 0.0 (and reported); columns not in the model's
        schema are reported as extras. Returns ``(vector, missing, extra)``.
        """
        if not self.feature_columns:
            raise ValueError("Feature columns are required for dict-based prediction.")

        missing: List[str] = []
        extra: List[str] = []
        vector: List[float] = []

        for name in self.feature_columns:
            if name in features:
                value = features.get(name)
                try:
                    vector.append(float(value))
                except (TypeError, ValueError):
                    vector.append(0.0)
            else:
                vector.append(0.0)
                missing.append(name)

        for name in features.keys():
            if name not in self.feature_columns:
                extra.append(name)

        return np.asarray(vector, dtype=np.float32).reshape(1, -1), missing, extra

    def predict_from_dict(self, features: Dict[str, object]) -> PredictionOutput:
        """Predict from a flat ``{feature_name: value}`` mapping (used by url/content stages)."""
        vector, missing, extra = self._vector_from_dict(features)
        output = self._predict(vector)
        output.missing_features = missing
        output.extra_features = extra
        return output

    def predict_from_dataframe(self, df: pd.DataFrame) -> PredictionOutput:
        """Predict from a one-row DataFrame, reindexing to the model's columns first.

        Used by the domain stage, whose extractor already yields a DataFrame. Columns
        are coerced to numeric; booleans become 0/1.
        """
        missing: List[str] = []
        extra: List[str] = []

        if self.feature_columns:
            for name in self.feature_columns:
                if name not in df.columns:
                    df[name] = pd.NA
                    missing.append(name)
            for name in df.columns:
                if name not in self.feature_columns:
                    extra.append(name)
            df = df[self.feature_columns]

        df = df.replace({True: 1, False: 0})
        df = df.apply(pd.to_numeric, errors="coerce")
        vector = df.to_numpy(dtype=np.float32, copy=False)

        output = self._predict(vector)
        output.missing_features = missing
        output.extra_features = extra
        return output
