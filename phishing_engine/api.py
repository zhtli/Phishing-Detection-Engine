"""FastAPI service exposing the prediction pipeline over HTTP.

A single ``Pipeline`` is built lazily on first request and reused. Like the CLI, the
service never writes to MongoDB. Config path comes from ``PHISHING_ENGINE_CONFIG``.

It also serves the bundled web UI (``phishing_engine/webui``) from the same origin so the
whole thing runs from one ``uvicorn`` process with no CORS friction: ``GET /`` returns the
UI, ``POST /predict`` is what its ``engine.js`` calls. Override the UI location with
``PHISHING_ENGINE_WEBUI_DIR``.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from phishing_engine.core.config import load_config
from phishing_engine.core.logging_setup import configure_logging
from phishing_engine.core.pipeline import Pipeline
from phishing_engine.core.registry import build_stages
from phishing_engine.core.serialization import result_to_api_dict

import phishing_engine.stages  # noqa: F401  (registers stages)

configure_logging()
logger = logging.getLogger(__name__)

CONFIG_PATH = os.getenv("PHISHING_ENGINE_CONFIG", "config/pipeline.json")

# The bundled web UI lives alongside this module at phishing_engine/webui/.
# Overridable for non-standard layouts.
_DEFAULT_WEBUI_DIR = Path(__file__).resolve().parent / "webui"
WEBUI_DIR = Path(os.getenv("PHISHING_ENGINE_WEBUI_DIR", str(_DEFAULT_WEBUI_DIR)))
WEBUI_INDEX = WEBUI_DIR / "index.html"

app = FastAPI(title="Phishing Detection Engine")

# Permissive CORS so the UI works even when served from a different origin during dev.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_pipeline: Optional[Pipeline] = None


class PredictRequest(BaseModel):
    url: str


def get_pipeline() -> Pipeline:
    """Return the process-wide pipeline, building it from config on first call."""
    global _pipeline
    if _pipeline is None:
        config = load_config(CONFIG_PATH)
        _pipeline = Pipeline(build_stages(config.pipeline.stages), config.pipeline.decision)
    return _pipeline


@app.get("/health")
def health():
    """Liveness probe (the demo's 'engine online' indicator polls this)."""
    return {"status": "ok"}


@app.post("/predict")
def predict(request: PredictRequest):
    """Score a URL and return the full UI-shaped cascade result; 500 on any failure."""
    try:
        pipeline = get_pipeline()
        result = pipeline.run(request.url)
        return result_to_api_dict(pipeline, result, request.url)
    except Exception as exc:
        logger.exception("prediction failed for url %r", request.url)
        raise HTTPException(status_code=500, detail=str(exc))


# --- web UI (mounted after the API routes so /health and /predict take precedence) ---
# StaticFiles(html=True) auto-serves index.html at "/" and the JS/CSS/JSX assets elsewhere.
if WEBUI_INDEX.exists():
    app.mount("/", StaticFiles(directory=str(WEBUI_DIR), html=True), name="webui")
else:
    logger.warning(
        "web UI not found at %s; only the JSON API is served "
        "(set PHISHING_ENGINE_WEBUI_DIR to override)",
        WEBUI_INDEX,
    )
