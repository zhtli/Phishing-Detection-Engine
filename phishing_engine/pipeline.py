from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

from phishing_engine.config import GateConfig
from phishing_engine.models import PredictionOutput


@dataclass
class StageResult:
    stage_id: str
    label: Optional[str]
    probabilities: Dict[str, float]
    confidence: Optional[float]
    decision: Optional[str]
    features: Optional[Dict[str, object]]
    artifacts: Optional[Dict[str, object]]
    missing_features: List[str]
    extra_features: List[str]
    error: Optional[str] = None


@dataclass
class PipelineContext:
    url: str
    normalized_url: str
    domain: str
    label: Optional[str] = None
    source: Optional[str] = None
    stage_results: Dict[str, StageResult] = field(default_factory=dict)


@dataclass
class PipelineResult:
    decision: str
    stage_id: Optional[str]
    label: Optional[str]
    confidence: Optional[float]
    probabilities: Dict[str, float]
    stages: Dict[str, StageResult]


class BaseStage:
    stage_id = "base"

    def __init__(self, config, model_runner=None):
        self.config = config
        self.model_runner = model_runner

    def collect(self, context: PipelineContext) -> Dict[str, object]:
        raise NotImplementedError

    def extract_features(
        self, context: PipelineContext, artifacts: Dict[str, object]
    ) -> Dict[str, object]:
        raise NotImplementedError

    def predict(
        self, features: Dict[str, object], artifacts: Dict[str, object]
    ) -> PredictionOutput:
        raise NotImplementedError

    def run(self, context: PipelineContext, mode: str = "predict") -> StageResult:
        artifacts = self.collect(context)
        features = self.extract_features(context, artifacts)

        prediction = None
        if mode == "predict" and self.model_runner is not None:
            prediction = self.predict(features, artifacts)

        label = prediction.label if prediction else None
        probabilities = prediction.probabilities if prediction else {}
        confidence = prediction.confidence if prediction else None
        missing = prediction.missing_features if prediction else []
        extra = prediction.extra_features if prediction else []

        return StageResult(
            stage_id=self.stage_id,
            label=label,
            probabilities=probabilities,
            confidence=confidence,
            decision=None,
            features=features,
            artifacts=artifacts,
            missing_features=missing,
            extra_features=extra,
        )


class Pipeline:
    def __init__(self, stages, store=None):
        self.stages = stages
        self.store = store

    def run(
        self,
        url: str,
        mode: str = "predict",
        label: Optional[str] = None,
        source: Optional[str] = None,
    ) -> PipelineResult:
        normalized = normalize_url(url)
        domain = extract_domain(normalized)
        context = PipelineContext(
            url=url,
            normalized_url=normalized,
            domain=domain,
            label=label,
            source=source,
        )

        if self.store:
            self.store.upsert_base(url, normalized, domain, label=label, source=source)

        for stage in self.stages:
            if not stage.config.enabled:
                continue

            result = stage.run(context, mode=mode)
            context.stage_results[stage.stage_id] = result

            if mode == "predict":
                decision = gate_decision(result, stage.config.gate)
                if decision != "continue":
                    result.decision = decision

            if self.store:
                self.store.update_stage_result(normalized, stage.stage_id, result, label=context.label)

            if mode == "predict" and result.decision:
                if self.store:
                    self.store.update_decision(
                        normalized,
                        result.decision,
                        stage.stage_id,
                        result,
                        label=context.label,
                    )
                return PipelineResult(
                    decision=result.decision,
                    stage_id=stage.stage_id,
                    label=result.label,
                    confidence=result.confidence,
                    probabilities=result.probabilities,
                    stages=context.stage_results,
                )

        final_decision = "collected" if mode == "collect" else "unknown"
        return PipelineResult(
            decision=final_decision,
            stage_id=None,
            label=None,
            confidence=None,
            probabilities={},
            stages=context.stage_results,
        )


def gate_decision(result: StageResult, gate: GateConfig) -> str:
    if not result.probabilities:
        return "continue"

    positive = gate.positive_label
    negative = gate.negative_label
    positive_prob = result.probabilities.get(positive)
    negative_prob = result.probabilities.get(negative)

    if gate.phish_threshold is not None and positive_prob is not None:
        if positive_prob >= gate.phish_threshold:
            return positive

    if gate.benign_threshold is not None and negative_prob is not None:
        if negative_prob >= gate.benign_threshold:
            return negative

    return "continue"


def normalize_url(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    host = parsed.hostname or ""
    try:
        host = host.encode("idna").decode("ascii")
    except Exception:
        pass
    normalized = parsed._replace(netloc=host).geturl()
    return normalized


def extract_domain(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or parsed.path
    return host.strip().strip(".")
