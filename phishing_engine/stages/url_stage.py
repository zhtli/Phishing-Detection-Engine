from __future__ import annotations

from phishing_engine.pipeline import BaseStage, PipelineContext
from phishing_engine.features.url_features import UrlLexicalFeatureExtractor


class UrlStage(BaseStage):
    stage_id = "url"

    def __init__(self, config, model_runner=None):
        super().__init__(config, model_runner)
        self.extractor = UrlLexicalFeatureExtractor()
        self.include_fetch = bool(config.options.get("include_fetch_features", False))

    def collect(self, context: PipelineContext) -> dict:
        return {}

    def extract_features(self, context: PipelineContext, artifacts: dict) -> dict:
        features, extra_artifacts = self.extractor.extract(
            context.normalized_url,
            include_fetch_features=self.include_fetch,
        )
        artifacts.update(extra_artifacts)
        return features

    def predict(self, features: dict, artifacts: dict):
        return self.model_runner.predict_from_dict(features)
