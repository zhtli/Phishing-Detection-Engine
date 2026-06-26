"""Prediction pipeline core: the multi-stage orchestration and its data types.

This module defines the framework pieces shared by every stage:
  * ``BaseStage`` — the collect → extract → predict contract each stage implements.
  * ``Pipeline`` — runs the stages as a cascade, stopping at the first confident stage.
  * the result/context dataclasses passed between them.

The pipeline is a two-sided per-stage deferral-band cascade: stages run in config order and
each yields a phishing probability ``p``. Each stage has a symmetric margin ``δ`` (its own
``margin``, or the pipeline-wide ``decision.margin`` default) defining a band
``[0.5 - δ, 0.5 + δ]``. A stage whose ``p`` lands **outside** its band is confident enough to
decide on its own — the run ends with that stage's model verdict (``phish`` if
``p >= 0.5 + δ`` else ``benign``) and the remaining stages (and their live collection) are
skipped; a ``p`` **inside** the band is uncertain and escalates the URL to the next stage for
further examination.
If the cascade reaches the last stage without an early exit, the verdict comes from
aggregating *every* stage's probability — the ``max``, ``mean``, or ``median`` of them, per
``decision.fallback_aggregation`` — and is ``phish`` if that aggregate is ``>= 0.5``
(see ``FALLBACK_DECISION_BOUNDARY``) else ``benign``.

Concrete stages live in ``phishing_engine.stages`` and import ``BaseStage`` from here.
The pipeline never writes to MongoDB; persisting raw data is the collectors' job.
"""
from __future__ import annotations

import logging
import statistics
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from phishing_engine.core.config import DecisionConfig
from phishing_engine.core.model_runner import PredictionOutput
from phishing_engine.core.urls import extract_domain, normalize_url

logger = logging.getLogger(__name__)

# The fixed 0.5 boundary the aggregated fallback score is compared against. It also serves as
# the centre of every stage's deferral band ([0.5 - margin, 0.5 + margin]).
FALLBACK_DECISION_BOUNDARY = 0.5


@dataclass
class StageResult:
    """The outcome of running a single stage.

    Captures the model output (label/probabilities/confidence), the computed
    ``features`` and intermediate ``artifacts``, any feature-alignment gaps
    (``missing_features``/``extra_features``), and the per-stage ``decision`` (set by
    the pipeline from this stage's phishing probability vs. its deferral band: a probability
    outside the band ends the cascade here with this stage's own model verdict, one inside
    the band escalates to the next stage with ``decision`` left ``None``).
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
    # Wall-clock time for this stage's collect → extract → predict, in milliseconds.
    elapsed_ms: Optional[float] = None


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
    """The final verdict for a URL plus the intermediate result of every stage that ran.

    ``decision`` is ``"phish"`` / ``"benign"``, or ``"unknown"`` if no stage produced a
    probability. ``stage_id`` names the deciding stage — the one that exited the cascade
    with a phish, or (in the aggregated fallback) the stage whose probability the
    aggregate came from — and ``probabilities`` holds the deciding distribution
    ``{positive: p, negative: 1 - p}`` (``p`` is the aggregate in the fallback case).
    ``stages`` contains only the stages that actually ran — an early phish exit omits the
    later, never-run stages.
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
        probabilities, so the cascade simply escalates past it to the next stage rather
        than crashing the whole prediction on a single stage's failure.
        """
        artifacts: Dict[str, object] = {}
        features: Optional[Dict[str, object]] = None
        prediction: Optional[PredictionOutput] = None
        error: Optional[str] = None

        started = time.perf_counter()
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
        elapsed_ms = (time.perf_counter() - started) * 1000.0

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
            elapsed_ms=elapsed_ms,
        )


class Pipeline:
    """Prediction pipeline. Runs the enabled stages as a two-sided deferral-band cascade.

    Stages run in config order. Each yields a phishing probability ``p`` and has a margin
    ``δ`` (its own ``margin`` override, else the pipeline-wide ``decision.margin``) defining a
    band ``[0.5 - δ, 0.5 + δ]``. A stage whose ``p`` is **outside** its band is trusted to
    decide on its own (the run ends with that stage's model verdict, ``phish`` if
    ``p >= 0.5 + δ`` else ``benign``) and the remaining stages are never run (so their live
    collection is skipped), while a ``p`` **inside** the band escalates the URL to the next
    stage. If no stage exits early, the verdict comes from aggregating every stage's
    probability (``max``, ``mean``, or ``median`` per ``decision.fallback_aggregation``) and
    comparing it to the fixed ``FALLBACK_DECISION_BOUNDARY`` of 0.5. The pipeline never writes
    to MongoDB — collecting raw data for storage is the collectors' job; each stage collects
    whatever it needs in-memory.
    """

    def __init__(self, stages, decision: Optional[DecisionConfig] = None):
        """Store the ordered stages and the (deferral-band) decision policy."""
        self.stages = stages
        self.decision = decision or DecisionConfig()

    def run(self, url: str) -> PipelineResult:
        """Run the enabled stages as a cascade and return the verdict.

        Disabled stages are skipped. Each remaining stage produces ``P(positive)`` (a
        stage with no model / no probability — or one that errored — cannot decide, so the
        cascade escalates past it). The first stage whose ``P(positive)`` falls outside its
        deferral band ``[0.5 - δ, 0.5 + δ]`` (``δ`` = the stage's own ``margin`` override,
        else ``decision.margin``) is trusted to decide on its own: the run ends with that
        stage's model verdict (``positive`` if ``P(positive) >= 0.5`` else ``negative``) and
        the later stages are never run; a probability inside the band escalates. If no stage
        exits early, the verdict comes from aggregating every stage's probability (``max``,
        ``mean``, or ``median``) against ``FALLBACK_DECISION_BOUNDARY``, or is ``"unknown"``
        if no stage produced a probability.
        """
        normalized = normalize_url(url)
        domain = extract_domain(normalized)
        context = PipelineContext(url=url, normalized_url=normalized, domain=domain)

        decision = self.decision
        positive, negative = decision.positive_label, decision.negative_label

        # Every (stage_id, P(positive)) the cascade saw, in run order.
        collected: List[Tuple[str, float]] = []
        early_exit: Optional[Tuple[str, float]] = None

        for stage in self.stages:
            if not stage.config.enabled:
                continue
            result = stage.run(context)
            context.stage_results[stage.stage_id] = result

            p = result.probabilities.get(positive) if result.probabilities else None
            if p is None:
                # No usable probability (untrained model, error, ...) — escalate.
                continue
            collected.append((stage.stage_id, p))
            # Each transition can demand its own confidence; fall back to the pipeline-wide
            # default when a stage doesn't set its own margin. The deferral band is
            # [0.5 - margin, 0.5 + margin] around the FALLBACK_DECISION_BOUNDARY.
            margin = (
                stage.config.margin
                if stage.config.margin is not None
                else decision.margin
            )
            low = FALLBACK_DECISION_BOUNDARY - margin
            high = FALLBACK_DECISION_BOUNDARY + margin
            if p <= low or p >= high:
                # Outside the band: confident either way, so this stage decides on its own —
                # adopt its model verdict (``positive`` if P(positive) >= 0.5 else
                # ``negative``) and skip the remaining stages.
                result.decision = positive if p >= FALLBACK_DECISION_BOUNDARY else negative
                early_exit = (stage.stage_id, p)
                break
            # Inside the band: uncertain — escalate to the next stage (no per-stage verdict).
            result.decision = None

        return self._build_result(context, collected, early_exit)

    def _aggregate(self, collected: List[Tuple[str, float]]) -> Tuple[str, float]:
        """Combine all stages' probabilities into one fallback score and the stage it came from.

        ``max`` lets the single most suspicious stage drive the verdict; ``mean`` (the
        default) and ``median`` require broader agreement across stages. For ``mean`` and
        ``median`` the aggregate may fall between two stages, so the reported stage is the
        one whose probability is nearest it.
        """
        mode = self.decision.fallback_aggregation
        if mode == "max":
            return max(collected, key=lambda sp: sp[1])
        if mode == "mean":
            agg = statistics.fmean(p for _, p in collected)
        else:  # "median"
            agg = statistics.median(p for _, p in collected)
        stage_id = min(collected, key=lambda sp: abs(sp[1] - agg))[0]
        return stage_id, agg

    def _build_result(
        self,
        context: PipelineContext,
        collected: List[Tuple[str, float]],
        early_exit: Optional[Tuple[str, float]],
    ) -> PipelineResult:
        """Turn the cascade outcome into the final ``PipelineResult``.

        An ``early_exit`` (a stage whose probability fell outside its deferral band) adopts
        that stage's own model verdict — ``positive`` if its
        ``P(positive) >= FALLBACK_DECISION_BOUNDARY`` else ``negative`` (so a below-band
        probability becomes a ``negative`` exit). Otherwise the collected probabilities are
        aggregated and compared to the fixed ``FALLBACK_DECISION_BOUNDARY``. With nothing
        collected the verdict is ``"unknown"``.
        """
        positive, negative = self.decision.positive_label, self.decision.negative_label

        if early_exit is not None:
            # The triggering stage decides with its own model verdict, not a forced phish.
            stage_id, p = early_exit
            verdict = positive if p >= FALLBACK_DECISION_BOUNDARY else negative
        elif collected:
            stage_id, p = self._aggregate(collected)
            verdict = positive if p >= FALLBACK_DECISION_BOUNDARY else negative
        else:
            return PipelineResult(
                decision="unknown",
                stage_id=None,
                label=None,
                confidence=None,
                probabilities={},
                stages=context.stage_results,
            )

        return PipelineResult(
            decision=verdict,
            stage_id=stage_id,
            label=verdict,
            confidence=p if verdict == positive else 1.0 - p,
            probabilities={positive: p, negative: 1.0 - p},
            stages=context.stage_results,
        )
