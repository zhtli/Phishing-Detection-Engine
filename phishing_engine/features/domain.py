from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional

from phishing_engine.features.domainradar import extractor as domain_extractor

DEFAULT_DATA_DIR = Path(__file__).resolve().parent / "domainradar" / "data"


class DomainFeatureExtractor:
    """Runs the DomainRadar transformation pipeline over a raw domain record."""

    def __init__(
        self,
        data_dir: Optional[str] = None,
        enabled_transformations: Optional[Iterable[str]] = None,
    ):
        data_path = Path(data_dir) if data_dir else DEFAULT_DATA_DIR
        config = {"data_dir": str(data_path)}
        if enabled_transformations is not None:
            config["enabled_transformations"] = list(enabled_transformations)
        domain_extractor.init_transformations(config)

    def extract(self, record: dict):
        """Run the configured transformations over one raw record.

        Returns ``(DataFrame | None, errors)`` as produced by the vendored extractor:
        a one-row feature DataFrame, or ``None`` with an ``errors`` mapping on failure.
        """
        return domain_extractor.extract_features([record])
