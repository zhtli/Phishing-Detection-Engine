from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Tuple

from url_analyzer.predictors.domain_parser import domain_parser
from url_analyzer.predictors.url_rules import url_rules
from url_analyzer.predictors.cert_features import cert_features
from url_analyzer.collectors.web_fetch import fetch_certificate_for_url, fetch_website

ROOT_DIR = Path(__file__).resolve().parents[2]
PREDICTORS_DIR = ROOT_DIR / "url_analyzer" / "predictors"


DEFAULT_FEATURE_COLUMNS = [
    "domain_digit_count",
    "subdomain_digit_count",
    "path_digit_count",
    "domain_length",
    "subdomain_length",
    "path_length",
    "isKnownTld",
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


class UrlLexicalFeatureExtractor:
    def __init__(self):
        self._parser = None
        self._rules = None

    def _ensure_rules(self):
        if self._parser and self._rules:
            return

        base_dir = str(PREDICTORS_DIR)
        cwd = os.getcwd()
        os.chdir(base_dir)
        try:
            self._parser = domain_parser()
            self._rules = url_rules()
        finally:
            os.chdir(cwd)

    def extract(
        self, url: str, include_fetch_features: bool = False
    ) -> Tuple[Dict[str, object], Dict[str, object]]:
        self._ensure_rules()

        parsed = self._parser.parse_nonlabeled_samples([url])
        if not parsed:
            return {}, {"error": "Unable to parse URL"}

        sample = parsed[0]
        nlp_info, features = self._rules.rules_main(
            sample["domain"],
            sample["tld"],
            sample["subdomain"],
            sample["path"],
            sample["words_raw"],
        )

        artifacts: Dict[str, object] = {
            "parsed": sample,
            "nlp_info": nlp_info,
        }

        if include_fetch_features:
            html, js_scripts, status_code, redirect_count, final_url, reason = fetch_website(
                url,
                fetch_scripts=False,
            )
            cert_pem, _, cert_valid, cert_error = fetch_certificate_for_url(final_url or url)

            features["redirect_count"] = redirect_count
            if cert_valid is True:
                features["cert_valid"] = 1
            elif cert_valid is False:
                features["cert_valid"] = 0
            else:
                features["cert_valid"] = -1

            cert_helper = cert_features()
            if cert_pem:
                features.update(cert_helper.from_pem_string(cert_pem))
            else:
                features.update(cert_helper.feature_defaults())

            artifacts.update(
                {
                    "final_url": final_url,
                    "status_code": status_code,
                    "reason": reason,
                    "redirect_count": redirect_count,
                    "js_script_count": len(js_scripts),
                    "cert_error": cert_error,
                }
            )
        else:
            features.setdefault("redirect_count", -1)
            features.setdefault("cert_valid", -1)
            cert_helper = cert_features()
            features.update(cert_helper.feature_defaults())

        return features, artifacts
