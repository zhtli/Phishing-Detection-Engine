# Portions of this file are derived from DomainRadar
# (https://github.com/nesfit/domainradar), Copyright (c) 2024 FIT BUT, FIT CTU,
# licensed under BSD-3-Clause. See THIRD_PARTY_NOTICES at the repository root.
"""lexical.py: Feature extraction transformations for lexical features."""
__authors__ = [
    "Radek Hranický <hranicky@fit.vut.cz>",
    "Ondřej Ondryáš <xondry02@vut.cz>",
    "Adam Horák <ihorak@fit.vut.cz>",
    "Petr Pouč <xpoucp01@vut.cz>"
]

import json
import os
import re

import tldextract
from pandas import DataFrame

from phishing_engine.features.common.base import Transformation
from phishing_engine.features.common.helpers import get_normalized_entropy, get_stddev, simhash

phishing_keywords = [
    "account", "action", "alert", "app", "auth", "bank", "billing", "center", "chat", "device", "fax", "event",
    "find", "free", "gift", "help", "info", "invoice", "live", "location", "login", "mail", "map", "message",
    "my", "new", "nitro", "now", "online", "pay", "promo", "real", "required", "safe", "secure", "security",
    "service", "signin", "support", "track", "update", "verification", "verify", "vm", "web"
]


def calculate_suffix_score(has_trusted_suffix, has_wellknown_suffix, has_cdn_suffix, has_vps_suffix, has_img_suffix):
    if has_trusted_suffix is None:
        has_trusted_suffix = 0
    if has_wellknown_suffix is None:
        has_wellknown_suffix = 0
    if has_cdn_suffix is None:
        has_cdn_suffix = 0
    if has_vps_suffix is None:
        has_vps_suffix = 0
    if has_img_suffix is None:
        has_img_suffix = 0

    TRUSTED_SUFFIX_SCORE = 10
    WELLKNOWN_SUFFIX_SCORE = 5
    CDN_SUFFIX_SCORE = 3
    VPS_SUFFIX_SCORE = 2
    IMG_SUFFIX_SCORE = 8  # Usually contains just images

    return has_trusted_suffix * TRUSTED_SUFFIX_SCORE + \
        has_wellknown_suffix * WELLKNOWN_SUFFIX_SCORE + \
        has_cdn_suffix * CDN_SUFFIX_SCORE + \
        has_vps_suffix * VPS_SUFFIX_SCORE + \
        has_img_suffix * IMG_SUFFIX_SCORE


_tld_abuse_scores = {  # Source: https://www.scoutdns.com/most-abused-top-level-domains-list-october-scoutdns/
    'com': 0.6554,
    'net': 0.1040,
    'eu': 0.0681,
    'name': 0.0651,
    'co': 0.0107,
    'life': 0.0087,
    'moe': 0.0081,
    'org': 0.0081,
    'xyz': 0.0072,
    'site': 0.0051,
    'ch': 0.0051,
    'it': 0.0048,
    'club': 0.0046,
    'info': 0.0043,
    'de': 0.0041,
    'racing': 0.0040,
    'live': 0.0035,
    'ru': 0.0034,
    'cc': 0.0034,
    'mobi': 0.0029,
    'me': 0.0023,
    'au': 0.0020,
    'cn': 0.0019,
    'pw': 0.0014,
    'in': 0.0011,
    'fr': 0.0010,
    'be': 0.0010,
    'pro': 0.0010,
    'top': 0.0009,
    'stream': 0.0007,
}


def get_tld_abuse_score(tld):
    # Dictionary containing the abuse scores for the provided TLDs

    # Remove the dot from the start of the TLD if it exists
    tld = tld.lstrip('.')

    # Return the abuse score if the TLD is in the dictionary, otherwise return 0
    return _tld_abuse_scores.get(tld, 0)


# Compile the regular expressions for both patterns
_ipv4_standard_format = re.compile(
    r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
_ipv4_dashed_format = re.compile(
    r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)-){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')


def contains_ipv4(s):
    # Use search method of compiled regex objects
    if _ipv4_standard_format.search(s) or _ipv4_dashed_format.search(s):
        return True
    return False


def longest_consonant_seq(domain: str) -> int:
    """Function returns longest consonant sequence

    Args:
        domain (str): domain name

    Returns:
        int: length of the longest consonant sequence
    """
    consonants = "bcdfghjklmnpqrstvwxyz"
    current_len = 0
    max_len = 0
    domain = domain.lower()
    for char in domain:
        if char in consonants:
            current_len += 1
        else:
            current_len = 0
        if current_len > max_len:
            max_len = current_len
    return max_len


def get_consonant_ratio(domain: str) -> float:
    """Function returns the consonant ratio
    which represents the total amount of consonants
    divided by the string length

    Args:
        domain (str): domain

    Returns:
        float: consonant ratio
    """
    domain = domain.lower()
    consonants = set("bcdfghjklmnpqrstvwxyz")
    consonant_count = sum(1 for char in domain if char in consonants)
    domain_len = len(domain)
    return consonant_count / domain_len if consonant_count > 0 else 0.0


def get_hex_ratio(domain: str) -> float:
    """Function computes hexadecimal ratio

    Args:
        domain (str): The length of the domain

    Returns:
        float: hexadecimal ratio
    """
    hex_chars = set('0123456789ABCDEFabcdef')
    hex_count = sum(char in hex_chars for char in domain)
    return hex_count / len(domain)


def contains_www(domain: str) -> int:
    """
    Function returns whether the domain contains
    the www subdomain. If the last subdomain is 'www'
    function returns 1, Otherwise function returns 0

    Args:
        domain (str): The whole domain name

    Returns:
        int: 1 if the domain name contains 'www'
             0 if the domain name does not contain 'www'
    """
    subdomains = domain.split(".")
    if subdomains[0] == "www":
        return 1
    return 0


def count_subdomains(domain: str) -> int:
    """
    Function returns the number of subdomains
    in the domain name

    Args:
        domain (str): The domain name

    Returns:
        int: Number of subdomains
    """
    ext = tldextract.extract(domain)
    if not ext.subdomain:
        return 0

    else:
        subdomains = ext.subdomain.split(".")
        subdomains_count = len(subdomains)
        if "www" in subdomains:
            subdomains_count -= 1
        return subdomains_count


def verify_tld(domain_suffix: str, known_tlds: set) -> int:
    """
    Function checks whether the domain tld is in
    the public suffix database

    Args:
        domain_suffix (str): Domain tld
        known_tlds (set): The set of the known tlds

    Returns:
        int: 1 if the tld is well-known
             0 if the tld is not well-known
    """
    if domain_suffix in known_tlds:
        return 1
    else:
        return 0


def remove_tld(domain: str) -> str:
    """Function removes tld from
    the domain name

    Args:
        domain (str): Domain name

    Returns:
        str: Domain without TLD
    """
    ext = tldextract.extract(domain)
    subdomain = ext.subdomain
    sld = ext.domain
    result = subdomain + "." + sld if subdomain else sld
    return result


def vowel_count(domain: str) -> int:
    """Function returns the number of vowels in
    the domain name
    Args:
        domain (str): The domain name
    Returns:
        int: Number of vowels
    """
    vowels = set("aeiouy")
    return sum(1 for char in domain.lower() if char in vowels)


def extract_subdomains(domain: str) -> list:
    """
    Function returns the list of the subdomains and
    sld from domain name

    Args:
        domain (str): The domain name

    Returns:
        list: Subdomains not including tld
    """
    ext = tldextract.extract(domain)
    subdomains = ext.subdomain.split('.') if ext.subdomain else []
    if 'www' in subdomains:
        subdomains.remove('www')
    sld = ext.domain
    domain_list = subdomains + [sld]
    return domain_list


def total_underscores_and_hyphens(domain: str) -> int:
    """Function returns the total number of underscores
    and hyphens in the domain name.

    Args:
        domain (str): The domain name

    Returns:
        int: Number of underscores and hyphens
    """
    return sum(domain.count(char) for char in ['_', '-'])


def consecutive_chars(domain: str) -> int:
    """Function returns the number of consecutive
    characters.

    Args:
        domain (str): The domain name

    Returns:
        int: Number of consecutive characters
    """
    if len(domain) == 0:
        return 0

    max_count = 1
    count = 1
    prev_char = domain[0]
    for char in domain[1:]:
        if char == prev_char:
            count += 1
            max_count = max(max_count, count)
        else:
            count = 1
        prev_char = char
    return max_count


# Calculate ngram matches, find if bigram or trigram of this domain name is present in the ngram list
def find_ngram_matches(text: str, ngrams: dict) -> int:
    """
    Find the number of ngram matches in the text.
    Input: text string, ngrams dictionary
    Output: number of matches
    """
    matches = 0
    for ngram in ngrams:
        if ngram in text:
            matches += 1
    return matches


# Returns an array od domain parts lengths
def get_lengths_of_parts(dn: str):
    # Split the domain string into parts divided by dots
    domain_parts = dn.split('.')

    # Get the length of each part and store in a list
    part_lens = [len(part) for part in domain_parts]
    return part_lens


class LexicalTransformation(Transformation):
    def __init__(self, config: dict):
        self._phishing_ngram_freq = dict()
        self._malware_ngram_freq = dict()
        self._dga_ngram_freq = dict()

        data_path = config.get("data_dir", "data")
        # N-grams
        with open(os.path.join(data_path, 'ngram_freq_phishing.json')) as f:
            self._phishing_ngram_freq = json.load(f)

        # N-grams
        with open(os.path.join(data_path, 'ngram_freq_malware.json')) as f:
            self._malware_ngram_freq = json.load(f)

        # N-grams
        with open(os.path.join(data_path, 'ngram_freq_dga.json')) as f:
            self._dga_ngram_freq = json.load(f)

    def transform(self, df: DataFrame) -> DataFrame:
        """
        Calculate domain lexical features.
        Input: DF with domain_name column
        Output: DF with lexical features derived from domain_name added
        """

        df['lex_name_len'] = df['domain_name'].apply(len)
        # NOTUSED # df['lex_dots_count'] = df['domain_name'].apply(lambda x: x.count('.'))   # (with www and TLD) :-> lex_sub_count used instead
        # NOTUSED # df['lex_subdomain_len'] = df['domain_name'].apply(lambda x: sum([len(y) for y in x.split('.')]))  # without dots
        # NOTUSED # df['lex_digit_count'] = df['domain_name'].apply(lambda x: sum([1 for y in x if y.isdigit()]))
        df['lex_has_digit'] = df['domain_name'].apply(lambda x: 1 if sum([1 for y in x if y.isdigit()]) > 0 else 0)
        df['lex_phishing_keyword_count'] = df['domain_name'].apply(
            lambda x: sum(1 for w in phishing_keywords if w in x))

        # NOTUSED # df['lex_vowel_count'] = df['domain_name'].apply(lambda x: vowel_count(x))
        # NOTUSED # df['lex_underscore_hyphen_count'] = df['domain_name'].apply(lambda x: total_underscores_and_hyphens(x))
        df['lex_consecutive_chars'] = df['domain_name'].apply(lambda x: consecutive_chars(x))
        # NOTUSED # df['lex_norm_entropy'] = df['domain_name'].apply(get_normalized_entropy)              # Normalized entropy od the domain name

        # Save temporary domain name parts for lex feature calculation
        df['tmp_tld'] = df['domain_name'].apply(lambda x: tldextract.extract(x).suffix)
        df['tmp_sld'] = df['domain_name'].apply(lambda x: tldextract.extract(x).domain)
        df['tmp_stld'] = df['tmp_sld'] + "." + df['tmp_tld']
        df['tmp_concat_subdomains'] = df['domain_name'].apply(lambda x: remove_tld(x).replace(".", ""))

        # TLD-based features
        df['lex_tld_len'] = df['tmp_tld'].apply(len)  # Length of TLD
        df['lex_tld_abuse_score'] = df['tmp_tld'].apply(get_tld_abuse_score)  # TLD abuse score
        df['lex_tld_hash'] = df['tmp_tld'].apply(simhash)  # TLD hash

        # SLD-based features
        df['lex_sld_len'] = df['tmp_sld'].apply(len)  # Length of SLD
        df['lex_sld_norm_entropy'] = df['tmp_sld'].apply(
            get_normalized_entropy)  # Normalized entropy of the SLD only
        df['lex_sld_digit_count'] = df['tmp_sld'].apply(
            lambda x: (sum([1 for y in x if y.isdigit()])) if len(x) > 0 else 0).astype("float")
        df['lex_sld_digit_ratio'] = df['tmp_sld'].apply(
            lambda x: (sum([1 for y in x if y.isdigit()]) / len(x)) if len(
                x) > 0 else 0)  # Digit ratio in subdomains
        df['lex_sld_phishing_keyword_count'] = df['tmp_sld'].apply(
            lambda x: sum(1 for w in phishing_keywords if w in x))
        df['lex_sld_vowel_count'] = df['tmp_sld'].apply(lambda x: vowel_count(x))
        df['lex_sld_vowel_ratio'] = df['tmp_sld'].apply(lambda x: (vowel_count(x) / len(x)) if len(x) > 0 else 0)
        df['lex_sld_consonant_count'] = df['tmp_sld'].apply(
            lambda x: (sum(1 for c in x if c in 'bcdfghjklmnpqrstvwxyz')) if len(x) > 0 else 0)
        df['lex_sld_consonant_ratio'] = df['tmp_sld'].apply(
            lambda x: (sum(1 for c in x if c in 'bcdfghjklmnpqrstvwxyz') / len(x)) if len(x) > 0 else 0)
        df['lex_sld_non_alphanum_count'] = df['tmp_sld'].apply(
            lambda x: (sum(1 for c in x if not c.isalnum())) if len(x) > 0 else 0)
        df['lex_sld_non_alphanum_ratio'] = df['tmp_sld'].apply(
            lambda x: (sum(1 for c in x if not c.isalnum()) / len(x)) if len(x) > 0 else 0)
        df['lex_sld_hex_count'] = df['tmp_sld'].apply(
            lambda x: (sum(1 for c in x if c in '0123456789ABCDEFabcdef')) if len(x) > 0 else 0)
        df['lex_sld_hex_ratio'] = df['tmp_sld'].apply(
            lambda x: (sum(1 for c in x if c in '0123456789ABCDEFabcdef') / len(x)) if len(x) > 0 else 0)
        # End of new SLD-based features

        df['lex_sub_count'] = df['domain_name'].apply(
            lambda x: count_subdomains(x))  # Number of subdomains (without www)
        df['lex_stld_unique_char_count'] = df['tmp_stld'].apply(
            lambda x: len(set(x.replace(".", ""))))  # Number of unique characters in TLD and SLD
        df['lex_begins_with_digit'] = df['domain_name'].apply(
            lambda x: 1 if x[0].isdigit() else 0)  # Is first character a digit
        df['lex_www_flag'] = df['domain_name'].apply(
            lambda x: 1 if (x.split("."))[0] == "www" else 0)  # Begins with www
        df['lex_sub_max_consonant_len'] = df['tmp_concat_subdomains'].apply(
            longest_consonant_seq)  # Max consonant sequence length
        df['lex_sub_norm_entropy'] = df['tmp_concat_subdomains'].apply(
            get_normalized_entropy)  # Normalized entropy od the domain name (without TLD)
        df['lex_sub_digit_count'] = df['tmp_concat_subdomains'].apply(
            lambda x: (sum([1 for y in x if y.isdigit()])) if len(x) > 0 else 0).astype("float")
        df['lex_sub_digit_ratio'] = df['tmp_concat_subdomains'].apply(
            lambda x: (sum([1 for y in x if y.isdigit()]) / len(x)) if len(
                x) > 0 else 0)  # Digit ratio in subdomains
        df['lex_sub_vowel_count'] = df['tmp_concat_subdomains'].apply(lambda x: vowel_count(x))
        df['lex_sub_vowel_ratio'] = df['tmp_concat_subdomains'].apply(
            lambda x: (vowel_count(x) / len(x)) if len(x) > 0 else 0)
        df['lex_sub_consonant_count'] = df['tmp_concat_subdomains'].apply(
            lambda x: (sum(1 for c in x if c in 'bcdfghjklmnpqrstvwxyz')) if len(x) > 0 else 0)
        df['lex_sub_consonant_ratio'] = df['tmp_concat_subdomains'].apply(
            lambda x: (sum(1 for c in x if c in 'bcdfghjklmnpqrstvwxyz') / len(x)) if len(x) > 0 else 0)
        df['lex_sub_non_alphanum_count'] = df['tmp_concat_subdomains'].apply(
            lambda x: (sum(1 for c in x if not c.isalnum())) if len(x) > 0 else 0)
        df['lex_sub_non_alphanum_ratio'] = df['tmp_concat_subdomains'].apply(
            lambda x: (sum(1 for c in x if not c.isalnum()) / len(x)) if len(x) > 0 else 0)
        df['lex_sub_hex_count'] = df['tmp_concat_subdomains'].apply(
            lambda x: (sum(1 for c in x if c in '0123456789ABCDEFabcdef')) if len(x) > 0 else 0)
        df['lex_sub_hex_ratio'] = df['tmp_concat_subdomains'].apply(
            lambda x: (sum(1 for c in x if c in '0123456789ABCDEFabcdef') / len(x)) if len(x) > 0 else 0)

        # N-Grams
        df["lex_phishing_bigram_matches"] = df["tmp_concat_subdomains"].apply(find_ngram_matches, args=(
            self._phishing_ngram_freq["bigram_freq"],))
        df["lex_phishing_trigram_matches"] = df["tmp_concat_subdomains"].apply(find_ngram_matches, args=(
            self._phishing_ngram_freq["trigram_freq"],))
        df["lex_phishing_tetragram_matches"] = df["tmp_concat_subdomains"].apply(find_ngram_matches, args=(
            self._phishing_ngram_freq["tetragram_freq"],))
        df["lex_phishing_pentagram_matches"] = df["tmp_concat_subdomains"].apply(find_ngram_matches, args=(
            self._phishing_ngram_freq["pentagram_freq"],))

        # Part lengths
        df["tmp_part_lengths"] = df["domain_name"].apply(lambda x: get_lengths_of_parts(x))
        df["lex_avg_part_len"] = df["tmp_part_lengths"].apply(lambda x: sum(x) / len(x) if len(x) > 0 else 0)
        df["lex_stdev_part_lens"] = df["tmp_part_lengths"].apply(lambda x: get_stddev(x) if len(x) > 0 else 0)
        df["lex_longest_part_len"] = df["tmp_part_lengths"].apply(lambda x: max(x) if len(x) > 0 else 0)

        # Length distribution
        df["lex_short_part_count"] = df["tmp_part_lengths"].apply(
            lambda x: len([pl for pl in x if pl <= 3]) if len(x) > 0 else 0)
        df["lex_medium_part_count"] = df["tmp_part_lengths"].apply(
            lambda x: len([pl for pl in x if 4 <= pl <= 10]) if len(x) > 0 else 0)
        df["lex_long_part_count"] = df["tmp_part_lengths"].apply(
            lambda x: len([pl for pl in x if 11 <= pl <= 30]) if len(x) > 0 else 0)
        df["lex_superlong_part_count"] = df["tmp_part_lengths"].apply(
            lambda x: len([pl for pl in x if pl >= 31]) if len(x) > 0 else 0)
        df["lex_shortest_sub_len"] = df["tmp_concat_subdomains"].apply(
            lambda x: min(get_lengths_of_parts(x)) if len(get_lengths_of_parts(x)) > 0 else 0)

        # Drop temporary columns
        df.drop(columns=['tmp_tld', 'tmp_sld', 'tmp_stld', 'tmp_concat_subdomains', 'tmp_part_lengths'], inplace=True)
        return df

    @property
    def features(self) -> dict[str, str]:
        return {
            "tmp_tld": "",
            "tmp_sld": "",
            "tmp_stld": "",
            "tmp_concat_subdomains": "",
            "tmp_part_lengths": "",
            "lex_name_len": "Int64",
            "lex_has_digit": "Int64",
            "lex_phishing_keyword_count": "Int64",
            "lex_consecutive_chars": "Int64",
            "lex_tld_len": "Int64",
            "lex_tld_abuse_score": "float64",
            "lex_tld_hash": "Int64",
            "lex_sld_len": "Int64",
            "lex_sld_norm_entropy": "float64",
            "lex_sld_digit_count": "Int64",
            "lex_sld_digit_ratio": "float64",
            "lex_sld_phishing_keyword_count": "Int64",
            "lex_sld_vowel_count": "Int64",
            "lex_sld_vowel_ratio": "float64",
            "lex_sld_consonant_count": "Int64",
            "lex_sld_consonant_ratio": "float64",
            "lex_sld_non_alphanum_count": "Int64",
            "lex_sld_non_alphanum_ratio": "float64",
            "lex_sld_hex_count": "Int64",
            "lex_sld_hex_ratio": "float64",
            "lex_sub_count": "Int64",
            "lex_stld_unique_char_count": "Int64",
            "lex_begins_with_digit": "Int64",
            "lex_www_flag": "Int64",
            "lex_sub_max_consonant_len": "Int64",
            "lex_sub_norm_entropy": "float64",
            "lex_sub_digit_count": "Int64",
            "lex_sub_digit_ratio": "float64",
            "lex_sub_vowel_count": "Int64",
            "lex_sub_vowel_ratio": "float64",
            "lex_sub_consonant_count": "Int64",
            "lex_sub_consonant_ratio": "float64",
            "lex_sub_non_alphanum_count": "Int64",
            "lex_sub_non_alphanum_ratio": "float64",
            "lex_sub_hex_count": "Int64",
            "lex_sub_hex_ratio": "float64",
            "lex_phishing_bigram_matches": "Int64",
            "lex_phishing_trigram_matches": "Int64",
            "lex_phishing_tetragram_matches": "Int64",
            "lex_phishing_pentagram_matches": "Int64",
            "lex_avg_part_len": "float64",
            "lex_stdev_part_lens": "float64",
            "lex_longest_part_len": "Int64",
            "lex_short_part_count": "Int64",
            "lex_medium_part_count": "Int64",
            "lex_long_part_count": "Int64",
            "lex_superlong_part_count": "Int64",
            "lex_shortest_sub_len": "Int64"
        }
