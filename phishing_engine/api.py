"""FastAPI service exposing the prediction pipeline over HTTP.

A single ``Pipeline`` is built lazily on first request and reused. Like the CLI, the
service never writes to MongoDB. Config path comes from ``PHISHING_ENGINE_CONFIG``.
"""
from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from phishing_engine.core.config import load_config
from phishing_engine.core.pipeline import Pipeline
from phishing_engine.core.registry import build_stages
from phishing_engine.core.serialization import result_to_dict

import phishing_engine.stages  # noqa: F401  (registers stages)

CONFIG_PATH = os.getenv("PHISHING_ENGINE_CONFIG", "config/pipeline.json")

app = FastAPI(title="Phishing Detection Engine")
_pipeline: Optional[Pipeline] = None


class PredictRequest(BaseModel):
    url: str


def get_pipeline() -> Pipeline:
    """Return the process-wide pipeline, building it from config on first call."""
    global _pipeline
    if _pipeline is None:
        config = load_config(CONFIG_PATH)
        _pipeline = Pipeline(build_stages(config.pipeline.stages))
    return _pipeline


@app.get("/health")
def health():
    """Liveness probe."""
    return {"status": "ok"}


@app.post("/predict")
def predict(request: PredictRequest):
    """Score a URL and return the full pipeline result; 500 on any failure."""
    try:
        return result_to_dict(get_pipeline().run(request.url))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
