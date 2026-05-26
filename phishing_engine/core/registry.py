"""Stage registry and builder.

Stage classes register themselves by id when ``phishing_engine.stages`` is imported.
``build_stages`` turns a list of ``StageConfig`` into ready-to-run stage instances,
attaching a loaded ``ModelRunner`` when the configured model file exists.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Type

from phishing_engine.core.config import StageConfig
from phishing_engine.core.model_runner import ModelRunner

logger = logging.getLogger(__name__)

_STAGE_REGISTRY: Dict[str, Type] = {}


def register_stage(stage_id: str, stage_cls: Type) -> None:
    """Register ``stage_cls`` under ``stage_id`` so the config can reference it."""
    _STAGE_REGISTRY[stage_id] = stage_cls


def get_stage(stage_id: str) -> Type:
    """Return the stage class registered for ``stage_id`` (raises ``KeyError`` if unknown)."""
    if stage_id not in _STAGE_REGISTRY:
        raise KeyError(f"Stage not registered: {stage_id}")
    return _STAGE_REGISTRY[stage_id]


def build_stages(configs: List[StageConfig]):
    """Instantiate stages from config, loading each stage's model if its file exists.

    A configured-but-missing model is not an error: the stage is built without a runner
    and runs feature-only (a warning is logged).
    """
    stages = []
    for config in configs:
        stage_cls = get_stage(config.id)
        runner = None
        if config.model_path:
            if Path(config.model_path).exists():
                runner = ModelRunner(
                    model_path=config.model_path,
                    feature_columns=config.feature_columns,
                    label_map=config.label_map,
                )
            else:
                # Model not trained yet: the stage still extracts features but produces
                # no prediction, so the gate passes the URL on to the next stage.
                logger.warning(
                    "stage '%s': model not found at %s; running feature-only "
                    "(train it with train_cli).",
                    config.id,
                    config.model_path,
                )
        stages.append(stage_cls(config, runner))
    return stages
