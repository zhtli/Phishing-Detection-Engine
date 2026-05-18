"""__main__.py: The main module for the feature extractor component. Provides a command-line interface for running
the processor. MongoDB extraction is available via CLI options."""
__author__ = "Ondřej Ondryáš <xondry02@vut.cz>"

import argparse
import os
import sys

import pandas as pd
from pandas import DataFrame

import extractor


DEFAULT_OUTPUT_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), ".", "output")
)

def extract_from_mongo(
    mongo_uri: str,
    db_name: str,
    collection_name: str,
    output_dir: str,
    batch_size: int,
    limit: int,
    label_class: str | None,
):
    try:
        from pymongo import MongoClient
    except ImportError as exc:
        raise SystemExit("pymongo is required for MongoDB extraction. Install it first.") from exc

    os.makedirs(output_dir, exist_ok=True)
    extractor.init_transformations({})

    client = MongoClient(mongo_uri)
    db = client[db_name]

    try:
            collection = db[collection_name]
            print(f"Reading collection: {collection_name}")
            total_docs = collection.count_documents({})
            if limit > 0:
                total_docs = min(total_docs, limit)
            print(f"Total documents to process: {total_docs}")

            batches: list[DataFrame] = []
            all_errors: dict[str, Exception] = {}

            cursor = collection.find({}, no_cursor_timeout=True).batch_size(batch_size)
            processed = 0
            batch: list[dict] = []

            try:
                for doc in cursor:
                    batch.append(doc)
                    processed += 1

                    limit_reached = limit > 0 and processed >= limit
                    if len(batch) >= batch_size or limit_reached:
                        df, errors = extractor.extract_features(batch)
                        if df is not None:
                            if label_class is not None:
                                df["class"] = label_class
                            batches.append(df)
                        all_errors.update(errors)
                        batch = []
                        progress_msg = (
                            f"Processed {processed}/{total_docs} documents from {collection_name}..."
                        )
                        print(f"\r{progress_msg}".ljust(80), end="", flush=True)

                    if limit_reached:
                        break
            finally:
                cursor.close()

            if batch:
                df, errors = extractor.extract_features(batch)
                if df is not None:
                    if label_class is not None:
                        df["class"] = label_class
                    batches.append(df)
                all_errors.update(errors)
                progress_msg = (
                    f"Processed {processed}/{total_docs} documents from {collection_name}..."
                )
                print(f"\r{progress_msg}".ljust(80), end="", flush=True)

            if processed:
                print()

            if all_errors:
                print(f"Errors in {collection_name}: {len(all_errors)}")

            if batches:
                result = pd.concat(batches, ignore_index=True)
                output_file = os.path.join(output_dir, f"{collection_name}_features.csv")
                result.to_csv(output_file, index=False)
                print(f"Saved {len(result)} feature vectors to: {output_file}")
            else:
                print(f"No feature vectors created for {collection_name}.")
    finally:
        client.close()


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Domain analysis feature extractor")
    parser.add_argument("--mongo", action="store_true", help="Extract features from MongoDB")
    parser.add_argument("--mongo-uri", default="mongodb://localhost:27017", help="MongoDB connection URI")
    parser.add_argument("--db", default="mydatabase", help="MongoDB database name")
    parser.add_argument(
        "--collection",
        help="Name of the collection to extract features from",
    )
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Output directory for feature files")
    parser.add_argument("--batch-size", type=int, default=1000, help="Number of documents per batch")
    parser.add_argument("--limit", type=int, default=0, help="Optional limit per collection (0 = no limit)")
    parser.add_argument(
        "--label-class",
        help="Label class to store for all rows (e.g., benign or phish)",
    )
    return parser


if __name__ == '__main__':
    parser = _build_arg_parser()
    args = parser.parse_args()

    if args.mongo:
        extract_from_mongo(
            mongo_uri=args.mongo_uri,
            db_name=args.db,
            collection_name=args.collection,
            output_dir=args.output_dir,
            batch_size=args.batch_size,
            limit=args.limit,
            label_class=args.label_class,
        )
        sys.exit(0)

    parser.print_help()
