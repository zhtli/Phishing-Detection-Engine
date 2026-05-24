from __future__ import annotations

from phishing_engine.collectors.domain_record import collect_domain_record_sync
from phishing_engine.features.domain import DomainFeatureExtractor
from phishing_engine.core.pipeline import BaseStage, PipelineContext


class DomainStage(BaseStage):
    """Second stage: DNS/IP/RDAP/WHOIS features over a raw domain record.

    At prediction time it collects the record live; for training it reads the record the
    enrichment collector stored under ``raw.domain_record``.
    """

    stage_id = "domain"
    requires_raw = "domain_record"

    def __init__(self, config, model_runner=None):
        super().__init__(config, model_runner)
        options = config.options
        self.timeout = float(options.get("timeout", 5.0))
        self.rtt_enabled = bool(options.get("rtt_enabled", False))
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
        """Collect a live DNS/IP/RDAP record for the domain (in-memory, not stored)."""
        record = collect_domain_record_sync(
            context.normalized_url,
            timeout=self.timeout,
            geoip_city_db=self.geoip_city_db,
            geoip_asn_db=self.geoip_asn_db,
            rtt_enabled=self.rtt_enabled,
            rtt_privileged=self.rtt_privileged,
            rtt_count=self.rtt_count,
            rtt_timeout=self.rtt_timeout,
            rtt_interval=self.rtt_interval,
        )
        return {"record": record}

    def extract_features(self, context: PipelineContext, artifacts: dict) -> dict:
        """Run the DomainRadar transformations over the record into a feature row.

        Stores the resulting one-row DataFrame in ``artifacts['features_df']`` so
        ``predict`` can feed it to the model with correct column alignment.
        """
        record = artifacts.get("record")
        if not record:
            return {}

        features_df, errors = self.feature_extractor.extract(record)
        artifacts["feature_errors"] = {k: str(v) for k, v in errors.items()}
        if features_df is None:
            return {}

        for column in ("class", "domain_name"):
            if column in features_df.columns:
                features_df = features_df.drop(columns=[column])

        artifacts["features_df"] = features_df
        return features_df.iloc[0].to_dict()

    def predict(self, features: dict, artifacts: dict):
        """Score the domain feature DataFrame with the domain model."""
        features_df = artifacts.get("features_df")
        if features_df is None:
            raise ValueError("Domain features unavailable for prediction")
        return self.model_runner.predict_from_dataframe(features_df)

    @staticmethod
    def build_train_artifacts(document: dict) -> dict:
        """Rebuild the collect() artifacts from a stored doc's ``raw.domain_record``."""
        return {"record": (document.get("raw") or {}).get("domain_record")}
