from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from phishing_engine.config import load_config
from phishing_engine.pipeline import Pipeline
from phishing_engine.registry import build_stages
from phishing_engine.storage.mongo import MongoStore
from phishing_engine.utils import result_to_dict

import phishing_engine.stages  # noqa: F401

CONFIG_PATH = os.getenv("PHISHING_ENGINE_CONFIG", "config/pipeline.json")

app = FastAPI(title="Phishing Detection Engine")
_pipeline: Optional[Pipeline] = None


class PredictRequest(BaseModel):
    url: str
    mode: str = "predict"
    label: Optional[str] = None
    source: Optional[str] = None


def get_pipeline() -> Pipeline:
    global _pipeline
    if _pipeline is not None:
        return _pipeline

    config = load_config(CONFIG_PATH)
    stages = build_stages(config.pipeline.stages)
    mongo = config.pipeline.mongo
    store = MongoStore(
        mongo.uri,
        mongo.database,
        mongo.collection,
        benign_collection=mongo.benign_collection,
        phish_collection=mongo.phish_collection,
    )
    _pipeline = Pipeline(stages, store=store)
    return _pipeline


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/predict")
def predict(request: PredictRequest):
    try:
        pipeline = get_pipeline()
        result = pipeline.run(
            request.url,
            mode=request.mode,
            label=request.label,
            source=request.source,
        )
        return result_to_dict(result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
