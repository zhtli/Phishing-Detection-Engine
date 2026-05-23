from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parents[2]
DOMAIN_ANALYZER_DIR = ROOT_DIR / "domain_analyzer"
EXTRACTOR_DIR = DOMAIN_ANALYZER_DIR / "extractor"

if str(EXTRACTOR_DIR) not in sys.path:
    sys.path.insert(0, str(EXTRACTOR_DIR))

import extractor as domain_extractor


class DomainFeatureExtractor:
    def __init__(
        self,
        data_dir: Optional[str] = None,
        enabled_transformations: Optional[Iterable[str]] = None,
    ):
        data_path = Path(data_dir) if data_dir else EXTRACTOR_DIR / "data"
        config = {"data_dir": str(data_path)}
        if enabled_transformations is not None:
            config["enabled_transformations"] = list(enabled_transformations)
        domain_extractor.init_transformations(config)

    def extract(self, record: dict):
        return domain_extractor.extract_features([record])
