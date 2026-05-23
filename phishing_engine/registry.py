from __future__ import annotations

from typing import Dict, List, Type

from phishing_engine.config import StageConfig
from phishing_engine.models import ModelRunner


_STAGE_REGISTRY: Dict[str, Type] = {}


def register_stage(stage_id: str, stage_cls: Type) -> None:
    _STAGE_REGISTRY[stage_id] = stage_cls


def get_stage(stage_id: str) -> Type:
    if stage_id not in _STAGE_REGISTRY:
        raise KeyError(f"Stage not registered: {stage_id}")
    return _STAGE_REGISTRY[stage_id]


def build_stages(configs: List[StageConfig]):
    stages = []
    for config in configs:
        stage_cls = get_stage(config.id)
        runner = None
        if config.model_path:
            runner = ModelRunner(
                model_path=config.model_path,
                feature_columns=config.feature_columns,
                label_map=config.label_map,
            )
        stages.append(stage_cls(config, runner))
    return stages
