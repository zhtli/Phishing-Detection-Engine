import argparse
import csv
import os
import pickle
import sys
from io import StringIO
from pathlib import Path

import numpy as np
import lime
import lime.lime_tabular
import urllib3

urllib3.disable_warnings()

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from url_analyzer.predictors.domain_parser import domain_parser
from url_analyzer.predictors.json2csv import json2csv
from url_analyzer.predictors.rule_extraction import rule_extraction
from url_analyzer.predictors.cert_features import cert_features
from url_analyzer.collectors.web_fetch import fetch_certificate_for_url, fetch_website


FEATURE_COLS = [
    "domain_digit_count",
    "subdomain_digit_count",
    "path_digit_count",
    "domain_length",
    "subdomain_length",
    "path_length",
    "isKnownTld",
    # "www",
    # "com",
    "punnyCode",
    "random_domain",
    "subDomainCount",
    "char_repeat",
    "popularity1m_tld",
    "popularity1m",
    "-",
    ".",
    "/",
    "@",
    "?",
    "&",
    "=",
    "_",
    "domain_in_brand_list",
    "domain_in_FWB_list",
    "raw_word_count",
    "splitted_word_count",
    "average_word_length",
    "longest_word_length",
    "shortest_word_length",
    "std_word_length",
    "compound_word_count",
    "keyword_count",
    "brand_name_count",
    "negligible_word_count",
    "target_brand_count",
    "target_keyword_count",
    "similar_keyword_count",
    "similar_brand_count",
    "average_compound_words",
    "random_words",
    "redirect_count",
    "cert_valid",
    "cert_validity_days",
    "cert_san_total",
    "cert_san_dns",
    "cert_validation_type",
]

LIME_FEATURES = 10
LIME_BACKGROUND_ROWS = 200


def _extract_feature_row(url):
    parser = domain_parser()
    extractor = rule_extraction()
    converter = json2csv()

    parsed = parser.parse_nonlabeled_samples([url])
    features = extractor.extraction(parsed)
    csv_str = converter.convert_for_test(features, "")

    reader = csv.DictReader(StringIO(csv_str))
    return next(reader, None)


def _collect_dataset_features(url):
    redirect_count = -1
    cert_valid_value = -1

    try:
        _, _, _, redirect_count, final_url, _ = fetch_website(url)
    except Exception as exc:
        print(f"Warning: fetch failed for {url}: {exc}")
        final_url = url

    cert_pem, _, cert_valid, cert_error = fetch_certificate_for_url(final_url or url)

    if cert_valid is True:
        cert_valid_value = 1
    elif cert_valid is False:
        cert_valid_value = 0

    cert_helper = cert_features()
    cert_feature_values = cert_helper.feature_defaults()
    if cert_pem:
        cert_feature_values = cert_helper.from_pem_string(cert_pem)
    elif cert_error:
        print(f"Warning: certificate unavailable: {cert_error}")

    dataset_features = {
        "redirect_count": redirect_count,
        "cert_valid": cert_valid_value,
    }
    dataset_features.update(cert_feature_values)
    return dataset_features, final_url


def _apply_dataset_features(feature_row, dataset_features):
    if not feature_row:
        return feature_row

    for key, value in dataset_features.items():
        feature_row[key] = value

    return feature_row


def _vector_from_features(feature_row, feature_cols):
    if not feature_row:
        raise ValueError("No features extracted for the provided URL.")

    missing = []
    extra = []
    vector = []

    for name in feature_cols:
        if name in feature_row:
            try:
                vector.append(float(feature_row[name]))
            except (TypeError, ValueError):
                vector.append(0.0)
        else:
            vector.append(0.0)
            missing.append(name)

    for name in feature_row.keys():
        if name not in feature_cols:
            extra.append(name)

    return np.asarray(vector, dtype=np.float32).reshape(1, -1), missing, extra


def _load_lime_background(feature_cols, max_rows=LIME_BACKGROUND_ROWS):
    background_path = BASE_DIR / "output/csv/gsb.csv"
    if not background_path.exists():
        return None

    rows = []
    with open(background_path, "r", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            values = []
            for name in feature_cols:
                try:
                    values.append(float(row.get(name, 0.0)))
                except (TypeError, ValueError):
                    values.append(0.0)
            rows.append(values)
            if len(rows) >= max_rows:
                break

    if not rows:
        return None

    return np.asarray(rows, dtype=np.float32)


def _synthetic_background(test_vector, size=LIME_BACKGROUND_ROWS):
    base = test_vector[0]
    scale = np.maximum(np.abs(base) * 0.05, 1e-3)
    noise = np.random.normal(0.0, scale, size=(size, base.shape[0]))
    background = base + noise
    return np.clip(background, 0.0, None)


def main():
    
    parser = argparse.ArgumentParser(
        description="Predict phishing for a URL using a saved model.",
    )
    parser.add_argument("--url", required=True, help="URL to score")
    parser.add_argument(
        "--model-pkl",
        default=None,
        help="Path to saved model.pkl (default: ./model.pkl)",
    )
    args = parser.parse_args()

    os.chdir(BASE_DIR)

    if args.model_pkl:
        model_path = Path(args.model_pkl)
        if not model_path.is_absolute():
            model_path = BASE_DIR / model_path
    else:
        model_path = BASE_DIR / "model.pkl"
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")

    feature_cols = FEATURE_COLS

    with open(model_path, "rb") as model_file:
        model = pickle.load(model_file)

    
    dataset_features, final_url = _collect_dataset_features(args.url)
    feature_row = _extract_feature_row(final_url)
    feature_row = _apply_dataset_features(feature_row, dataset_features)
    test_vector, missing, extra = _vector_from_features(feature_row, feature_cols)
    
    pred = model.predict(test_vector)[0]
    proba = model.predict_proba(test_vector)[0]
    class_names = [str(label) for label in model.classes_]
    class_probs = {name: round(float(prob) * 100, 2) for name, prob in zip(class_names, proba)}

    print("URL:", args.url)
    print("Model file:", model_path)
    print("Final URL after redirects:", final_url)
    print("Extracted features:", feature_row)
    print("Prediction:", pred)
    print("Probabilities (%):", class_probs)

    if missing:
        print("Warning: missing features filled with 0:", missing)
    if extra:
        print("Warning: features ignored (not in training):", extra)

    if hasattr(model, "predict_proba"):
        background = _load_lime_background(feature_cols)
        if background is None or len(background) < 2:
            background = _synthetic_background(test_vector)

        explainer = lime.lime_tabular.LimeTabularExplainer(
            background,
            feature_names=feature_cols,
            class_names=class_names,
            discretize_continuous=True,
        )
        
        explanation = explainer.explain_instance(
            test_vector[0],
            model.predict_proba,
            num_features=min(LIME_FEATURES, len(feature_cols)),
        )

        print("\nExplanation (top features):")
        for feature, weight in explanation.as_list():
            print(f"{feature}: {weight:.4f}")
    else:
        print("\nExplanation skipped: model does not support predict_proba().")


if __name__ == "__main__":
    main()
