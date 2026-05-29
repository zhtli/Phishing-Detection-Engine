"""Prediction pipeline core: the multi-stage orchestration and its data types.

This module defines the framework pieces shared by every stage:
  * ``BaseStage`` — the collect → extract → predict contract each stage implements.
  * ``Pipeline`` — runs every enabled stage and fuses their scores into one verdict.
  * the result/context dataclasses passed between them.

The pipeline uses a single-threshold decision: each stage yields a phishing
probability, those are fused (``max`` by default) into one score, and the URL is
flagged ``phish`` when that score crosses the configured ``threshold``. This matches
the offline evaluation in ``model_evaluation.ipynb``.

Concrete stages live in ``phishing_engine.stages`` and import ``BaseStage`` from here.
The pipeline never writes to MongoDB; persisting raw data is the collectors' job.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from phishing_engine.core.config import DecisionConfig
from phishing_engine.core.model_runner import PredictionOutput
from phishing_engine.core.urls import extract_domain, normalize_url

logger = logging.getLogger(__name__)


@dataclass
class StageResult:
    """The outcome of running a single stage.

    Captures the model output (label/probabilities/confidence), the computed
    ``features`` and intermediate ``artifacts``, any feature-alignment gaps
    (``missing_features``/``extra_features``), and the per-stage ``decision`` (set by
    the pipeline: this stage's own phishing probability compared to the threshold).
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

    ``decision`` is ``"phish"`` / ``"benign"`` from comparing the fused score to the
    threshold, or ``"unknown"`` if no stage produced a probability. ``stage_id`` names
    the most suspicious stage (the one contributing the highest phishing probability),
    and ``probabilities`` holds the fused distribution ``{positive: score, negative:
    1 - score}``.
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
        """Execute the full collect → extract → (optional) predict flow for one URL.

        Each phase is guarded: if one raises, the traceback is logged and a short error
        message is recorded on the ``StageResult``. The stage then produces no
        probabilities, so it simply drops out of the fused score and the pipeline still
        returns a verdict rather than crashing on a single stage's failure.
        """
        artifacts: Dict[str, object] = {}
        features: Optional[Dict[str, object]] = None
        prediction: Optional[PredictionOutput] = None
        error: Optional[str] = None

        try:
            artifacts = self.collect(context)
            features = self.extract_features(context, artifacts)
            if self.model_runner is not None:
                prediction = self.predict(features, artifacts)
        except Exception as exc:
            logger.exception(
                "stage %r failed for url %r", self.stage_id, context.url
            )
            error = f"{type(exc).__name__}: {exc}"

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
            error=error,
        )


class Pipeline:
    """Prediction pipeline. Runs every enabled stage and fuses their scores.

    Unlike an early-exit gate, this runs all enabled stages, collects each one's
    phishing probability, fuses them into a single score (``max`` by default), and flags
    the URL ``phish`` when that score crosses the configured threshold. The pipeline
    never writes to MongoDB — collecting raw data for storage is the collectors' job;
    each stage collects whatever it needs in-memory.
    """

    def __init__(self, stages, decision: Optional[DecisionConfig] = None):
        """Store the ordered stages and the (single-threshold) decision policy."""
        self.stages = stages
        self.decision = decision or DecisionConfig()

    def run(self, url: str) -> PipelineResult:
        """Run every enabled stage, fuse their phishing probabilities, and decide.

        Disabled stages are skipped. Each remaining stage contributes its
        ``P(positive)`` (stages with no model / no probability are simply omitted). The
        contributions are fused per ``decision.fusion`` and compared to
        ``decision.threshold``; the verdict is ``positive`` / ``negative`` accordingly,
        or ``"unknown"`` if no stage produced a probability.
        """
        normalized = normalize_url(url)
        domain = extract_domain(normalized)
        context = PipelineContext(url=url, normalized_url=normalized, domain=domain)

        for stage in self.stages:
            if not stage.config.enabled:
                continue
            result = stage.run(context)
            context.stage_results[stage.stage_id] = result

        return self._decide(context)

    def _decide(self, context: PipelineContext) -> PipelineResult:
        """Fuse the stages' phishing probabilities into the final ``PipelineResult``."""
        decision = self.decision
        positive, negative = decision.positive_label, decision.negative_label
        threshold = decision.threshold

        # Gather each stage's positive-class probability (skip stages without one), and
        # tag each contributing stage with its own threshold decision for diagnostics.
        scored: List[tuple] = []  # (stage_id, p_positive)
        for stage_id, result in context.stage_results.items():
            if not result.probabilities:
                continue
            p = result.probabilities.get(positive)
            if p is None:
                continue
            scored.append((stage_id, p))
            result.decision = positive if p >= threshold else negative

        if not scored:
            return PipelineResult(
                decision="unknown",
                stage_id=None,
                label=None,
                confidence=None,
                probabilities={},
                stages=context.stage_results,
            )

        score = self._fuse([p for _, p in scored], decision.fusion)
        verdict = positive if score >= threshold else negative
        # Attribute the verdict to the most suspicious stage (highest phishing prob).
        top_stage_id = max(scored, key=lambda item: item[1])[0]

        return PipelineResult(
            decision=verdict,
            stage_id=top_stage_id,
            label=verdict,
            confidence=score if verdict == positive else 1.0 - score,
            probabilities={positive: score, negative: 1.0 - score},
            stages=context.stage_results,
        )

    @staticmethod
    def _fuse(probabilities: List[float], how: str) -> float:
        """Combine per-stage phishing probabilities into one score (``max`` or ``mean``)."""
        if not probabilities:
            return 0.0
        if how == "mean":
            return sum(probabilities) / len(probabilities)
        return max(probabilities)
