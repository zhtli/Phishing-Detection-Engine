from __future__ import annotations

from phishing_engine.features.content_features import ContentFeatureExtractor
from phishing_engine.features.tls_collector import fetch_tls_data
from phishing_engine.pipeline import BaseStage, PipelineContext

from url_analyzer.collectors.web_fetch import fetch_website


class ContentStage(BaseStage):
    stage_id = "content"

    def __init__(self, config, model_runner=None):
        super().__init__(config, model_runner)
        options = config.options
        self.store_raw_html = bool(options.get("store_raw_html", False))
        self.max_html_bytes = int(options.get("max_html_bytes", 500000))
        self.tls_timeout = float(options.get("tls_timeout", 10.0))
        self.feature_extractor = ContentFeatureExtractor()

    def collect(self, context: PipelineContext) -> dict:
        html, _, status_code, redirect_count, final_url, reason = fetch_website(
            context.normalized_url,
            fetch_scripts=False,
        )
        target_url = final_url or context.normalized_url
        tls_data = fetch_tls_data(target_url, timeout=self.tls_timeout)

        return {
            "html": html,
            "status_code": status_code,
            "redirect_count": redirect_count,
            "final_url": final_url,
            "reason": reason,
            "tls_data": tls_data,
            "tls_summary": {
                "protocol": tls_data.get("protocol") if tls_data else None,
                "cipher": tls_data.get("cipher") if tls_data else None,
            },
        }

    def extract_features(self, context: PipelineContext, artifacts: dict) -> dict:
        html = artifacts.get("html", "")
        tls_data = artifacts.get("tls_data")

        features, extra_artifacts = self.feature_extractor.extract(
            html,
            tls_data,
        )

        artifacts["tls_data"] = None

        if self.store_raw_html:
            encoded = (html or "").encode("utf-8")
            artifacts["html"] = encoded[: self.max_html_bytes].decode("utf-8", errors="ignore")
        else:
            artifacts["html"] = None

        artifacts.update(extra_artifacts)
        return features

    def predict(self, features: dict, artifacts: dict):
        return self.model_runner.predict_from_dict(features)
