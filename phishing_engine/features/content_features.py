from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, Tuple

import pandas as pd

ROOT_DIR = Path(__file__).resolve().parents[2]
DOMAIN_ANALYZER_DIR = ROOT_DIR / "domain_analyzer"

if str(DOMAIN_ANALYZER_DIR) not in sys.path:
    sys.path.insert(0, str(DOMAIN_ANALYZER_DIR))

from extractor.html import HTMLTransformation
from extractor.tls import TLSTransformation


class ContentFeatureExtractor:
    def __init__(self):
        self.html_transform = HTMLTransformation(None)
        self.tls_transform = TLSTransformation()

    def extract(
        self,
        html: str,
        tls_data: dict | None,
    ) -> Tuple[Dict[str, object], Dict[str, object]]:
        df = pd.DataFrame([
            {
                "html": html,
                "tls": tls_data,
            }
        ])

        df = self.html_transform.transform(df)
        df = self.tls_transform.transform(df)

        df = df.drop(columns=["html", "tls"], errors="ignore")
        features = df.iloc[0].to_dict()

        return features, {}
