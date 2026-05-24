from __future__ import annotations

from phishing_engine.features.url import UrlLexicalFeatureExtractor
from phishing_engine.core.pipeline import BaseStage, PipelineContext


class UrlStage(BaseStage):
    """First stage: lexical analysis of the URL string only — never fetches the page.

    Needs no raw data for training (``requires_raw = None``); the URL alone is enough.
    """

    stage_id = "url"
    requires_raw = None

    def __init__(self, config, model_runner=None):
        super().__init__(config, model_runner)
        self.extractor = UrlLexicalFeatureExtractor()

    def collect(self, context: PipelineContext) -> dict:
        """No collection: this stage works purely from the URL string."""
        return {}

    def extract_features(self, context: PipelineContext, artifacts: dict) -> dict:
        """Compute lexical features from the normalized URL."""
        features, extra_artifacts = self.extractor.extract(context.normalized_url)
        artifacts.update(extra_artifacts)
        return features

    def predict(self, features: dict, artifacts: dict):
        """Score the lexical features with the URL model."""
        return self.model_runner.predict_from_dict(features)
