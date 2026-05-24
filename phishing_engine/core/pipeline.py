"""Prediction pipeline core: the gated multi-stage orchestration and its data types.

This module defines the framework pieces shared by every stage:
  * ``BaseStage`` — the collect → extract → predict contract each stage implements.
  * ``Pipeline`` — runs the ordered stages with early-exit gating.
  * the result/context dataclasses passed between them.

Concrete stages live in ``phishing_engine.stages`` and import ``BaseStage`` from here.
The pipeline never writes to MongoDB; persisting raw data is the collectors' job.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from phishing_engine.core.config import GateConfig
from phishing_engine.core.model_runner import PredictionOutput
from phishing_engine.core.urls import extract_domain, normalize_url


@dataclass
class StageResult:
    """The outcome of running a single stage.

    Captures the model output (label/probabilities/confidence), the computed
    ``features`` and intermediate ``artifacts``, any feature-alignment gaps
    (``missing_features``/``extra_features``), and the gate ``decision`` (set by the
    pipeline once thresholds are applied).
    """

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
    """Per-URL state threaded through the stages of one prediction run."""

    url: str
    normalized_url: str
    domain: str
    label: Optional[str] = None
    source: Optional[str] = None
    stage_results: Dict[str, StageResult] = field(default_factory=dict)


@dataclass
class PipelineResult:
    """The final verdict for a URL plus every stage's intermediate result.

    ``decision`` is the gate label that short-circuited the pipeline (``"phish"`` /
    ``"benign"``) or ``"unknown"`` if no stage crossed a threshold.
    """

    decision: str
    stage_id: Optional[str]
    label: Optional[str]
    confidence: Optional[float]
    probabilities: Dict[str, float]
    stages: Dict[str, StageResult]


class BaseStage:
    """Common contract for a detection stage: collect → extract_features → predict.

    Subclasses set ``stage_id`` and ``requires_raw`` and implement the three steps.
    The same ``extract_features`` is used both at prediction time (on freshly collected
    artifacts) and at training time (on artifacts rebuilt from a stored document).
    """

    stage_id = "base"
    # Which raw-data key a stage needs from a stored document for training
    # (None means it works from the URL string alone).
    requires_raw: Optional[str] = None

    def __init__(self, config, model_runner=None):
        """Bind the stage's config and (optionally) a loaded ``ModelRunner``.

        ``model_runner`` is ``None`` when the stage's model has not been trained yet;
        in that case the stage produces features but no prediction.
        """
        self.config = config
        self.model_runner = model_runner

    def collect(self, context: PipelineContext) -> Dict[str, object]:
        """Collect raw data in-memory for prediction. Never writes to storage."""
        raise NotImplementedError

    def extract_features(
        self, context: PipelineContext, artifacts: Dict[str, object]
    ) -> Dict[str, object]:
        """Turn collected artifacts (and/or the URL) into a flat feature mapping."""
        raise NotImplementedError

    def predict(
        self, features: Dict[str, object], artifacts: Dict[str, object]
    ) -> PredictionOutput:
        """Run the stage's model over the features and return a ``PredictionOutput``."""
        raise NotImplementedError

    @staticmethod
    def build_train_artifacts(document: Dict[str, object]) -> Dict[str, object]:
        """Build the artifacts dict from a stored raw document, for training.

        Mirrors what ``collect`` would return at prediction time, but sourced from the
        ``raw.*`` sub-documents the collectors persisted in MongoDB.
        """
        return {}

    def run(self, context: PipelineContext) -> StageResult:
        """Execute the full collect → extract → (optional) predict flow for one URL."""
        artifacts = self.collect(context)
        features = self.extract_features(context, artifacts)

        prediction = None
        if self.model_runner is not None:
            prediction = self.predict(features, artifacts)

        return StageResult(
            stage_id=self.stage_id,
            label=prediction.label if prediction else None,
            probabilities=prediction.probabilities if prediction else {},
            confidence=prediction.confidence if prediction else None,
            decision=None,
            features=features,
            artifacts=artifacts,
            missing_features=prediction.missing_features if prediction else [],
            extra_features=prediction.extra_features if prediction else [],
        )


class Pipeline:
    """Prediction pipeline. Runs ordered stages with early-exit gating.

    The pipeline never writes to MongoDB — collection of raw data for storage is the
    collectors' job. Each stage collects whatever it needs in-memory.
    """

    def __init__(self, stages):
        """Store the ordered list of (already built) stages to run."""
        self.stages = stages

    def run(self, url: str) -> PipelineResult:
        """Score ``url`` through the stages, returning as soon as a gate decides.

        Disabled stages are skipped. The first stage whose score crosses its
        ``phish``/``benign`` threshold short-circuits and its decision is returned;
        if none do, the result is ``"unknown"``.
        """
        normalized = normalize_url(url)
        domain = extract_domain(normalized)
        context = PipelineContext(url=url, normalized_url=normalized, domain=domain)

        for stage in self.stages:
            if not stage.config.enabled:
                continue

            result = stage.run(context)
            context.stage_results[stage.stage_id] = result

            decision = gate_decision(result, stage.config.gate)
            if decision != "continue":
                result.decision = decision
                return PipelineResult(
                    decision=decision,
                    stage_id=stage.stage_id,
                    label=result.label,
                    confidence=result.confidence,
                    probabilities=result.probabilities,
                    stages=context.stage_results,
                )

        return PipelineResult(
            decision="unknown",
            stage_id=None,
            label=None,
            confidence=None,
            probabilities={},
            stages=context.stage_results,
        )


def gate_decision(result: StageResult, gate: GateConfig) -> str:
    """Apply a stage's thresholds to its probabilities.

    Returns the positive label when ``P(positive) >= phish_threshold``, the negative
    label when ``P(negative) >= benign_threshold``, otherwise ``"continue"`` (meaning
    the pipeline should move on to the next stage). A stage with no probabilities
    (e.g. an untrained model) always yields ``"continue"``.
    """
    if not result.probabilities:
        return "continue"

    positive_prob = result.probabilities.get(gate.positive_label)
    negative_prob = result.probabilities.get(gate.negative_label)

    if gate.phish_threshold is not None and positive_prob is not None:
        if positive_prob >= gate.phish_threshold:
            return gate.positive_label

    if gate.benign_threshold is not None and negative_prob is not None:
        if negative_prob >= gate.benign_threshold:
            return gate.negative_label

    return "continue"
