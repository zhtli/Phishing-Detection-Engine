from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from geoip2.database import Reader as GeoIPReader

from phishing_engine.features.domain_features import DomainFeatureExtractor
from phishing_engine.pipeline import BaseStage, PipelineContext

ROOT_DIR = Path(__file__).resolve().parents[2]
DOMAIN_ANALYZER_DIR = ROOT_DIR / "domain_analyzer"

if str(DOMAIN_ANALYZER_DIR) not in sys.path:
    sys.path.insert(0, str(DOMAIN_ANALYZER_DIR))

from domain_analyzer.predict_domain import collect_domain_record


class DomainStage(BaseStage):
    stage_id = "domain"

    def __init__(self, config, model_runner=None):
        super().__init__(config, model_runner)
        options = config.options
        self.timeout = float(options.get("timeout", 5.0))
        self.rtt_enabled = bool(options.get("rtt_enabled", True))
        self.rtt_privileged = bool(options.get("rtt_privileged", False))
        self.rtt_count = int(options.get("rtt_count", 3))
        self.rtt_timeout = float(options.get("rtt_timeout", 1.0))
        self.rtt_interval = float(options.get("rtt_interval", 0.2))
        self.geoip_city_db = options.get("geoip_city_db")
        self.geoip_asn_db = options.get("geoip_asn_db")
        self.feature_extractor = DomainFeatureExtractor(
            data_dir=options.get("data_dir"),
            enabled_transformations=options.get("enabled_transformations"),
        )

    def collect(self, context: PipelineContext) -> dict:
        geo_reader = None
        asn_reader = None
        if self.geoip_city_db:
            geo_reader = GeoIPReader(self.geoip_city_db)
        if self.geoip_asn_db:
            asn_reader = GeoIPReader(self.geoip_asn_db)

        try:
            record = asyncio.run(
                collect_domain_record(
                    context.normalized_url,
                    timeout=self.timeout,
                    geo_reader=geo_reader,
                    asn_reader=asn_reader,
                    rtt_enabled=self.rtt_enabled,
                    rtt_privileged=self.rtt_privileged,
                    rtt_count=self.rtt_count,
                    rtt_timeout=self.rtt_timeout,
                    rtt_interval=self.rtt_interval,
                )
            )
        finally:
            if geo_reader:
                geo_reader.close()
            if asn_reader:
                asn_reader.close()

        return {"record": record}

    def extract_features(self, context: PipelineContext, artifacts: dict) -> dict:
        record = artifacts.get("record")
        if not record:
            return {}

        features_df, errors = self.feature_extractor.extract(record)
        if features_df is None:
            artifacts["feature_errors"] = {k: str(v) for k, v in errors.items()}
            return {}

        if "class" in features_df.columns:
            features_df = features_df.drop(columns=["class"])
        if "domain_name" in features_df.columns:
            features_df = features_df.drop(columns=["domain_name"])

        artifacts["feature_errors"] = {k: str(v) for k, v in errors.items()}
        artifacts["features_df"] = features_df
        return features_df.iloc[0].to_dict()

    def predict(self, features: dict, artifacts: dict):
        features_df = artifacts.get("features_df")
        if features_df is None:
            raise ValueError("Domain features unavailable for prediction")
        return self.model_runner.predict_from_dataframe(features_df)
