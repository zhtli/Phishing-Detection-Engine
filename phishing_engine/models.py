from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import joblib
import pickle
import pandas as pd


@dataclass
class PredictionOutput:
    label: Optional[str]
    probabilities: Dict[str, float]
    confidence: Optional[float]
    missing_features: List[str]
    extra_features: List[str]
    raw_label: Optional[str] = None


class ModelRunner:
    def __init__(
        self,
        model_path: str | Path,
        feature_columns: Optional[List[str]] = None,
        label_map: Optional[Dict[str, str]] = None,
    ):
        self.model_path = Path(model_path)
        self.model = self._load_model(self.model_path)
        self.feature_columns = feature_columns or self._infer_feature_columns()
        self.label_map = label_map or {}

    def _load_model(self, path: Path):
        if not path.exists():
            raise FileNotFoundError(f"Model not found: {path}")
        if path.suffix.lower() == ".joblib":
            return joblib.load(path)
        with path.open("rb") as handle:
            return pickle.load(handle)

    def _infer_feature_columns(self) -> Optional[List[str]]:
        if hasattr(self.model, "feature_names_in_"):
            return list(self.model.feature_names_in_)
        if hasattr(self.model, "named_steps"):
            for step in self.model.named_steps.values():
                if hasattr(step, "feature_names_in_"):
                    return list(step.feature_names_in_)
        return None

    def _normalize_label(self, label: str) -> str:
        return self.label_map.get(str(label), str(label))

    def _normalize_probabilities(self, classes, proba: np.ndarray) -> Dict[str, float]:
        probabilities: Dict[str, float] = {}
        for raw_label, value in zip(classes, proba):
            normalized = self._normalize_label(raw_label)
            probabilities[normalized] = probabilities.get(normalized, 0.0) + float(value)
        return probabilities

    def _predict(self, vector: np.ndarray) -> PredictionOutput:
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
        vector, missing, extra = self._vector_from_dict(features)
        output = self._predict(vector)
        output.missing_features = missing
        output.extra_features = extra
        return output

    def predict_from_dataframe(self, df: pd.DataFrame) -> PredictionOutput:
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
