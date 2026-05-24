from __future__ import annotations

from phishing_engine.collectors.content import collect_content
from phishing_engine.features.content import ContentFeatureExtractor
from phishing_engine.core.pipeline import BaseStage, PipelineContext


class ContentStage(BaseStage):
    """Final stage: HTML + TLS-certificate features over the fetched page.

    Fetches HTML only (never JS). At prediction time it collects the page live; for
    training it reads what the content collector stored under ``raw.content``.
    """

    stage_id = "content"
    requires_raw = "content"

    def __init__(self, config, model_runner=None):
        super().__init__(config, model_runner)
        options = config.options
        self.max_html_bytes = int(options.get("max_html_bytes", 500000))
        self.tls_timeout = float(options.get("tls_timeout", 10.0))
        self.feature_extractor = ContentFeatureExtractor()

    def collect(self, context: PipelineContext) -> dict:
        """Fetch the page HTML and a TLS handshake summary (in-memory, not stored)."""
        return collect_content(
            context.normalized_url,
            tls_timeout=self.tls_timeout,
            max_html_bytes=self.max_html_bytes,
        )

    def extract_features(self, context: PipelineContext, artifacts: dict) -> dict:
        """Compute HTML + TLS features from the collected/stored content."""
        html = artifacts.get("html", "")
        tls_data = artifacts.get("tls")
        features, extra_artifacts = self.feature_extractor.extract(html, tls_data)
        artifacts.update(extra_artifacts)
        return features

    def predict(self, features: dict, artifacts: dict):
        """Score the HTML/TLS features with the content model."""
        return self.model_runner.predict_from_dict(features)

    @staticmethod
    def build_train_artifacts(document: dict) -> dict:
        """Rebuild the collect() artifacts from a stored doc's ``raw.content``."""
        content = (document.get("raw") or {}).get("content") or {}
        return {"html": content.get("html", ""), "tls": content.get("tls")}
