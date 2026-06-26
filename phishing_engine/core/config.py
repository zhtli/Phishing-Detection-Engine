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
    """Pipeline-wide two-sided deferral-band cascade policy.

    Enabled stages run in order. Each stage carries a symmetric **margin** ``δ`` defining a
    deferral band ``[0.5 - δ, 0.5 + δ]`` around the 0.5 boundary. A stage whose phishing
    probability ``p`` lands **outside** its band is confident enough to decide on its own and
    the cascade ends here with that stage's model verdict (``positive_label`` if
    ``p >= 0.5 + δ`` else ``negative_label``), the remaining stages skipped; a ``p`` **inside**
    the band is uncertain and escalates to the next stage. ``margin`` is the pipeline-wide
    default; a stage may set its own ``margin`` to demand a different confidence for its
    transition (a smaller δ exits more readily). If no stage exits early, the verdict comes
    from aggregating *every* stage's probability: ``fallback_aggregation`` (``"mean"``
    (default), ``"max"``, or ``"median"``) combines them into one score, which is
    ``positive_label`` if ``>= 0.5`` else ``negative_label``. If no stage produced a
    probability (e.g. all models are untrained), the verdict is ``"unknown"``.

    ``δ = 0.5`` makes the band ``[0, 1]`` so every stage escalates and the verdict always comes
    from the aggregate; ``δ = 0`` makes the first stage decide every URL.
    """

    margin: float = Field(default=0.5, ge=0.0, le=0.5)
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

    ``margin`` overrides the pipeline-wide ``decision.margin`` for *this* stage's deferral
    band, so each transition can demand its own confidence (e.g. a tight ``0.3`` for the cheap
    ``url`` stage, a wider ``0.45`` for ``content``). ``None`` (the default) falls back to
    ``decision.margin``.
    """

    id: str
    enabled: bool = True
    model_path: Optional[str] = None
    feature_columns: Optional[List[str]] = None
    label_map: Dict[str, str] = Field(default_factory=dict)
    options: Dict[str, Any] = Field(default_factory=dict)
    margin: Optional[float] = Field(default=None, ge=0.0, le=0.5)


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
