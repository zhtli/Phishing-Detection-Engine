"""Pydantic models and loader for ``config/pipeline.json``.

The config drives the whole engine: the ordered stage list, each stage's model path,
feature columns and label remapping, the pipeline-wide decision policy, plus the
MongoDB connection.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class DecisionConfig(BaseModel):
    """Pipeline-wide single-threshold decision policy.

    Every enabled stage is run and its phishing probability collected. Those per-stage
    probabilities are fused into one score (``max`` by default, or ``mean``); a URL is
    labeled ``positive_label`` when the fused score is ``>= threshold`` and
    ``negative_label`` otherwise. If no stage produced a probability (e.g. all models are
    untrained), the verdict is ``"unknown"``.
    """

    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    fusion: Literal["max", "mean"] = "max"
    positive_label: str = "phish"
    negative_label: str = "benign"


class StageConfig(BaseModel):
    """Configuration for one pipeline stage.

    ``model_path`` may point at a not-yet-trained model (the stage then runs
    feature-only). ``feature_columns`` pins the model's input ordering, ``label_map``
    remaps raw model classes to engine labels, and ``options`` holds stage-specific
    settings (timeouts, GeoIP paths, data dirs, ...).
    """

    id: str
    enabled: bool = True
    model_path: Optional[str] = None
    feature_columns: Optional[List[str]] = None
    label_map: Dict[str, str] = Field(default_factory=dict)
    options: Dict[str, Any] = Field(default_factory=dict)


class MongoConfig(BaseModel):
    """MongoDB connection settings for the collectors and the training reader."""

    uri: str = "mongodb://localhost:27017"
    database: str = "phishing_engine"
    collection: str = "url_documents"
    domain_collection: str = "domain_records"


class PipelineConfig(BaseModel):
    """The ordered stages, the decision policy, and the Mongo connection."""

    stages: List[StageConfig]
    decision: DecisionConfig = Field(default_factory=DecisionConfig)
    mongo: MongoConfig = Field(default_factory=MongoConfig)


class AppConfig(BaseModel):
    """Top-level config object (root key ``pipeline`` in the JSON file)."""

    pipeline: PipelineConfig


def load_config(path: str | Path) -> AppConfig:
    """Read and validate the JSON config file at ``path`` into an ``AppConfig``."""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")

    data = json.loads(config_path.read_text(encoding="utf-8"))
    return AppConfig.model_validate(data)
