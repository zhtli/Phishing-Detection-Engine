"""Convert pipeline result objects into JSON-safe dicts for the CLI and API."""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict

from phishing_engine.core.pipeline import PipelineResult, StageResult

logger = logging.getLogger(__name__)


def sanitize_value(value: Any):
    """Recursively coerce a value into something ``json.dumps`` can handle.

    Passes primitives through, ISO-formats datetimes, unwraps numpy scalars via
    ``.item()``, recurses into dicts/lists, and falls back to ``str()`` for anything else.
    """
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): sanitize_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize_value(v) for v in value]
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception as exc:
            logger.debug("falling back to str() for value of type %s: %s", type(value).__name__, exc)
    return str(value)


def stage_result_to_dict(result: StageResult) -> Dict[str, Any]:
    """Serialize one ``StageResult`` (features/artifacts included) to a JSON-safe dict."""
    return {
        "stage_id": result.stage_id,
        "label": result.label,
        "probabilities": sanitize_value(result.probabilities),
        "confidence": sanitize_value(result.confidence),
        "decision": result.decision,
        "features": sanitize_value(result.features),
        "artifacts": sanitize_value(result.artifacts),
        "missing_features": result.missing_features,
        "extra_features": result.extra_features,
        "error": result.error,
    }


def result_to_dict(result: PipelineResult) -> Dict[str, Any]:
    """Serialize a full ``PipelineResult`` (final decision + every stage) to a JSON-safe dict."""
    return {
        "decision": result.decision,
        "stage_id": result.stage_id,
        "label": result.label,
        "confidence": sanitize_value(result.confidence),
        "probabilities": sanitize_value(result.probabilities),
        #"stages": {key: stage_result_to_dict(value) for key, value in result.stages.items()},
    }
