"""Prediction CLI: score a single URL through the staged prediction pipeline.

Never writes to MongoDB. Each stage collects whatever it needs in-memory.

    python -m phishing_engine.cli.predict --url "http://example.com" --config config/pipeline.json
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from phishing_engine.core.config import load_config
from phishing_engine.core.pipeline import Pipeline
from phishing_engine.core.registry import build_stages
from phishing_engine.core.serialization import result_to_dict

import phishing_engine.stages  # noqa: F401  (registers stages)


def build_pipeline(config_path: str) -> Pipeline:
    """Load the config and build a prediction ``Pipeline`` (no Mongo store attached)."""
    config = load_config(config_path)
    stages = build_stages(config.pipeline.stages)
    return Pipeline(stages)


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint: score the ``--url`` and print the result as JSON to stdout."""
    parser = argparse.ArgumentParser(description="Phishing detection — predict a single URL")
    parser.add_argument("--url", required=True, help="URL to score")
    parser.add_argument("--config", default="config/pipeline.json", help="Path to pipeline config JSON")
    args = parser.parse_args(argv)

    pipeline = build_pipeline(args.config)
    result = pipeline.run(args.url)
    print(json.dumps(result_to_dict(result), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
