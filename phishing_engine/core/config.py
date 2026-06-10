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
    """Pipeline-wide per-stage-threshold cascade policy.

    Enabled stages run in order. A stage whose phishing probability is ``>= threshold`` is
    trusted to decide on its own: the cascade ends with that stage's model verdict
    (``positive_label`` if its probability is ``>= 0.5`` else ``negative_label``), the
    remaining stages skipped; a probability below ``threshold`` escalates to the next.
    ``threshold`` is the pipeline-wide default; a stage may set its own ``threshold`` to
    demand a different confidence for its transition. If no
    stage exits early, the verdict comes from aggregating *every* stage's probability:
    ``fallback_aggregation`` (``"mean"`` (default), ``"max"``, or ``"median"``) combines them into one score,
    which is ``positive_label`` if ``>= 0.5`` else ``negative_label``. If no stage produced
    a probability (e.g. all models are untrained), the verdict is ``"unknown"``.

    Note: the fallback only matters when ``threshold > 0.5`` — otherwise any stage at or
    above the 0.5 boundary would already have early-exited as ``positive_label``, so the
    aggregate of the remaining (sub-threshold) probabilities is always below 0.5.
    """

    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    positive_label: str = "phish"
    negative_label: str = "benign"
    # How to combine all stages' probabilities when the cascade ends with no early exit.
    fallback_aggregation: Literal["max", "mean", "median"] = "mean"


class StageConfig(BaseModel):
    """Configuration for one pipeline stage.

    ``model_path`` may point at a not-yet-trained model (the stage then runs
    feature-only). ``feature_columns`` pins the model's input ordering, ``label_map``
    remaps raw model classes to engine labels, and ``options`` holds stage-specific
    settings (timeouts, GeoIP paths, data dirs, ...).

    ``threshold`` overrides the pipeline-wide ``decision.threshold`` for *this* stage's
    early-exit decision, so each transition can demand its own confidence (e.g. ``0.9``
    for the cheap ``url`` stage, ``0.8`` for ``content``). ``None`` (the default) falls
    back to ``decision.threshold``.
    """

    id: str
    enabled: bool = True
    model_path: Optional[str] = None
    feature_columns: Optional[List[str]] = None
    label_map: Dict[str, str] = Field(default_factory=dict)
    options: Dict[str, Any] = Field(default_factory=dict)
    threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)


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
