from __future__ import annotations

import logging
from typing import Dict, List, Tuple

from phishing_engine.features.lexical.domain_parser import domain_parser
from phishing_engine.features.lexical.url_rules import url_rules

logger = logging.getLogger(__name__)


# Lexical-only feature set produced from the URL string alone (no network fetch).
URL_LEXICAL_FEATURE_COLUMNS: List[str] = [
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
]


class UrlLexicalFeatureExtractor:
    """Extracts lexical features from a URL string. Never fetches the page."""

    def __init__(self):
        self._parser = None
        self._rules = None

    def _ensure_rules(self):
        """Lazily build the (expensive) parser and rule engine on first use.

        The vendored modules resolve their data files relative to the package, so no
        working-directory juggling is needed.
        """
        if self._parser is not None and self._rules is not None:
            return
        self._parser = domain_parser()
        self._rules = url_rules()

    def extract(self, url: str) -> Tuple[Dict[str, object], Dict[str, object]]:
        """Parse the URL and compute lexical features.

        Returns ``(features, artifacts)`` where ``features`` is the flat feature mapping
        and ``artifacts`` carries the parsed URL parts and NLP word analysis.
        """
        self._ensure_rules()

        parsed = self._parser.parse_nonlabeled_samples([url])
        if not parsed:
            logger.warning("unable to parse URL for lexical features: %r", url)
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
        return features, artifacts
