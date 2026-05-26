"""Training CLI: train/retrain a stage model from labeled raw data in MongoDB.

Reads from MongoDB (collected by the collectors), trains, and writes the model to disk.
Does not write to MongoDB.

    python -m phishing_engine.cli.train --stage url --config config/pipeline.json
    python -m phishing_engine.cli.train --stage all --model-type gradient_boosting
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from phishing_engine.core.config import load_config
from phishing_engine.core.logging_setup import configure_logging
from phishing_engine.core.registry import get_stage
from phishing_engine.storage.mongo import MongoStore
from phishing_engine.core.training import train_stage

import phishing_engine.stages  # noqa: F401  (registers stages)


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint: train one stage (or ``all``) from labeled Mongo data; print summaries."""
    parser = argparse.ArgumentParser(description="Phishing detection — train stage models")
    parser.add_argument("--stage", required=True, help="Stage id to train (url|domain|content) or 'all'")
    parser.add_argument("--config", default="config/pipeline.json", help="Path to pipeline config JSON")
    parser.add_argument("--model-type", default="random_forest",
                        choices=["random_forest", "gradient_boosting"], help="Classifier to train")
    parser.add_argument("--limit", type=int, default=0, help="Max labeled documents to use (0 = all)")
    parser.add_argument("--output", default=None, help="Override output model path (single stage only)")
    args = parser.parse_args(argv)

    configure_logging()
    config = load_config(args.config)
    mongo = config.pipeline.mongo
    store = MongoStore(mongo.uri, mongo.database, mongo.collection, mongo.domain_collection)

    stage_configs = config.pipeline.stages
    if args.stage != "all":
        stage_configs = [s for s in stage_configs if s.id == args.stage]
        if not stage_configs:
            parser.error(f"No stage with id '{args.stage}' in config")

    try:
        for stage_config in stage_configs:
            output_path = args.output or stage_config.model_path
            if not output_path:
                print(json.dumps({"stage": stage_config.id, "skipped": "no model_path configured"}))
                continue
            # Build the stage without a model runner (the model may not exist yet).
            stage = get_stage(stage_config.id)(stage_config, None)
            summary = train_stage(
                stage,
                store,
                output_path=output_path,
                model_type=args.model_type,
                feature_columns=stage_config.feature_columns,
                limit=args.limit,
            )
            print(json.dumps(summary, indent=2, default=str))
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
