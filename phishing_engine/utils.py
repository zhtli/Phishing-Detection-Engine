from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

from phishing_engine.pipeline import PipelineResult, StageResult


def sanitize_value(value: Any):
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
        except Exception:
            pass
    return str(value)


def stage_result_to_dict(result: StageResult) -> Dict[str, Any]:
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
    return {
        "decision": result.decision,
        "stage_id": result.stage_id,
        "label": result.label,
        "confidence": sanitize_value(result.confidence),
        "probabilities": sanitize_value(result.probabilities),
        "stages": {key: stage_result_to_dict(value) for key, value in result.stages.items()},
    }
