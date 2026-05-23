from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class GateConfig(BaseModel):
    phish_threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    benign_threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    positive_label: str = "phish"
    negative_label: str = "benign"


class StageConfig(BaseModel):
    id: str
    enabled: bool = True
    model_path: Optional[str] = None
    feature_columns: Optional[List[str]] = None
    label_map: Dict[str, str] = Field(default_factory=dict)
    gate: GateConfig = Field(default_factory=GateConfig)
    options: Dict[str, Any] = Field(default_factory=dict)


class MongoConfig(BaseModel):
    uri: str = "mongodb://localhost:27017"
    database: str = "phishing_engine"
    collection: str = "url_documents"
    benign_collection: Optional[str] = "benign_documents"
    phish_collection: Optional[str] = "phish_documents"


class PipelineConfig(BaseModel):
    stages: List[StageConfig]
    mongo: MongoConfig = Field(default_factory=MongoConfig)


class AppConfig(BaseModel):
    pipeline: PipelineConfig


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")

    data = json.loads(config_path.read_text(encoding="utf-8"))
    return AppConfig.model_validate(data)
