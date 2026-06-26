"""Convert pipeline result objects into JSON-safe dicts for the CLI and API.

``result_to_dict`` is the minimal verdict used by the predict CLI. ``result_to_api_dict``
is the richer, UI-shaped payload the HTTP API serves: it walks the cascade and, per stage,
reports the real probability, deferral band, latency, run/decision flags, human-readable
signals and the live-collected evidence (WHOIS / DNS / page facts) — everything the demo UI
renders.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from phishing_engine.core import explain
from phishing_engine.core.pipeline import (
    FALLBACK_DECISION_BOUNDARY,
    Pipeline,
    PipelineResult,
    StageResult,
)
from phishing_engine.core.urls import extract_domain, normalize_url

logger = logging.getLogger(__name__)

# Static, factual display metadata per stage (name/info/model/network) mirrored by the
# UI's idle screen and analyzing-state shells. Not derivable from the model itself.
STAGE_META: Dict[str, Dict[str, Any]] = {
    "url": {
        "key": "url", "name": "URL Lexical Classifier", "short": "URL",
        "info": "URL string & lexical tokens only", "network": False,
    },
    "content": {
        "key": "content", "name": "Page Content Classifier", "short": "Content",
        "info": "Static HTML + TLS certificate features", "network": True,
    },
    "domain": {
        "key": "domain", "name": "Domain Classifier", "short": "Domain",
        "info": "DNS / IP / RDAP / WHOIS record", "network": True,
    },
}


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


_VERDICT_MAP = {"phish": "phishing", "benign": "legitimate"}


def _stage_margin(stage, decision) -> float:
    """The stage's own deferral margin δ, or the pipeline-wide default."""
    return stage.config.margin if stage.config.margin is not None else decision.margin


def result_to_api_dict(pipeline: Pipeline, result: PipelineResult, url: str) -> Dict[str, Any]:
    """Assemble the rich, UI-shaped payload from a finished cascade run.

    Needs the ``pipeline`` (for per-stage deferral bands, cascade order and which stages have a
    loaded model) alongside the ``result`` (``result.stages`` holds only the stages that ran).
    Produces the cascade-level verdict/decision metadata, a per-stage card list (probability,
    band, latency, run/decision flags, signals) and the merged ``extracted`` evidence.
    """
    decision = pipeline.decision
    positive, negative = decision.positive_label, decision.negative_label

    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    host = parsed.hostname or ""
    protocol = parsed.scheme or "http"
    domain = extract_domain(normalized)

    ordered = [s for s in pipeline.stages if s.config.enabled]

    verdict = _VERDICT_MAP.get(result.decision, "unknown")

    # Locate the deciding stage (1-based) and classify the decision mode: a stage whose own
    # probability landed outside its deferral band is an early-exit; otherwise the verdict came
    # from the aggregated fallback (or there was no probability at all → "unknown").
    deciding_idx: Optional[int] = None
    if result.stage_id is not None:
        for i, stage in enumerate(ordered):
            if stage.stage_id == result.stage_id:
                deciding_idx = i + 1
                break

    decision_mode = "unknown"
    if verdict != "unknown" and deciding_idx is not None:
        deciding_stage = ordered[deciding_idx - 1]
        deciding_sr = result.stages.get(result.stage_id)
        p = deciding_sr.probabilities.get(positive) if deciding_sr and deciding_sr.probabilities else None
        margin = _stage_margin(deciding_stage, decision)
        low, high = FALLBACK_DECISION_BOUNDARY - margin, FALLBACK_DECISION_BOUNDARY + margin
        decision_mode = "early-exit" if (p is not None and (p <= low or p >= high)) else "aggregation"

    aggregate_score = None
    if decision_mode == "aggregation" and result.probabilities:
        aggregate_score = result.probabilities.get(positive)

    stages = []
    total_latency = 0.0
    extracted: Dict[str, Any] = {}
    for i, stage in enumerate(ordered):
        idx = i + 1
        meta = STAGE_META.get(stage.stage_id, {
            "key": stage.stage_id, "name": stage.stage_id, "short": stage.stage_id,
            "info": "", "network": True,
        })
        sr = result.stages.get(stage.stage_id)
        ran = sr is not None
        margin = _stage_margin(stage, decision)
        low = FALLBACK_DECISION_BOUNDARY - margin
        high = FALLBACK_DECISION_BOUNDARY + margin

        score = None
        latency_ms = None
        error = None
        signals: list = []
        if ran:
            score = sr.probabilities.get(positive) if sr.probabilities else None
            error = sr.error
            if sr.elapsed_ms is not None:
                latency_ms = round(sr.elapsed_ms)
                total_latency += latency_ms
            signals = explain.stage_signals(stage.stage_id, sr.features, sr.artifacts)
            if stage.stage_id == "content":
                extracted.update(explain.content_evidence(sr.artifacts, sr.features))
            elif stage.stage_id == "domain":
                extracted.update(explain.domain_evidence((sr.artifacts or {}).get("record")))

        # A score outside the band [low, high] is "confident" — below low clears legitimate,
        # at/above high flags phishing; in between the stage escalates.
        exited = score is not None and (score <= low or score >= high)
        exit_side = None
        if exited:
            exit_side = positive if score >= FALLBACK_DECISION_BOUNDARY else negative
        stage_verdict = "phishing" if (score is not None and score >= FALLBACK_DECISION_BOUNDARY) else "legitimate"
        decided = decision_mode == "early-exit" and idx == deciding_idx

        stages.append({
            "id": idx,
            "key": meta["key"],
            "name": meta["name"],
            "short": meta["short"],
            "info": meta["info"],
            "network": meta["network"],
            "margin": margin,
            "bandLow": low,
            "bandHigh": high,
            "score": sanitize_value(score),
            "latencyMs": latency_ms,
            "ran": ran,
            "skipped": not ran,
            "decided": decided,
            "escalated": ran and not decided,
            "exited": exited,
            "exitSide": exit_side,
            "verdict": stage_verdict,
            "noModel": stage.model_runner is None,
            "error": error,
            "signals": signals,
        })

    # The URL bar / page-status header are always shown; keep sane defaults when the
    # content stage didn't run (or fetch failed).
    extracted.setdefault("finalUrl", normalized)
    extracted.setdefault("statusCode", "—")

    # The raw data each stage actually collected, for the "raw data" view: the URL parse,
    # the verbatim HTML/DOM (already byte-capped by the content stage), and the full domain
    # record (DNS / RDAP / WHOIS / hosting IPs). The numeric feature vectors are intentionally
    # omitted — they're model inputs, not "raw" collected data.
    raw: Dict[str, Any] = {}
    for stage in ordered:
        sr = result.stages.get(stage.stage_id)
        if sr is None:
            continue
        artifacts = sr.artifacts or {}
        if stage.stage_id == "url":
            raw["url"] = {"parsed": sanitize_value(artifacts.get("parsed"))}
        elif stage.stage_id == "content":
            html = artifacts.get("html") or ""
            raw["content"] = {
                "htmlBytes": len(html.encode("utf-8", errors="ignore")) if html else 0,
                "html": html,
            }
        elif stage.stage_id == "domain":
            raw["domain"] = sanitize_value(artifacts.get("record"))

    return {
        "url": normalized,
        "host": host,
        "domain": domain,
        "protocol": protocol,
        "verdict": verdict,
        "decision": result.decision,
        "decisionMode": decision_mode,
        "decidingStage": deciding_idx,
        "aggregation": decision.fallback_aggregation,
        "aggregateScore": sanitize_value(aggregate_score),
        "overallConfidence": sanitize_value(result.confidence),
        "margin": decision.margin,
        "positiveLabel": positive,
        "negativeLabel": negative,
        "totalLatencyMs": round(total_latency),
        "stages": stages,
        "extracted": extracted,
        "raw": raw,
    }
