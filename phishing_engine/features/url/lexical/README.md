# `features/url/lexical/` — URL lexical analyzer (third-party origin)

> **Vendored code.** This is a third-party URL lexical-analysis library, copied into the
> engine and adjusted only so it is import-clean and resolves its data files relative to
> this package (no working-directory dependence). Internals are documented here rather
> than annotated function-by-function. Entry point used by the engine:
> `url_rules.rules_main(...)` via [`../url.py`](../url.py).

| File | What it does |
|------|--------------|
| `domain_parser.py` | `domain_parser.parse_nonlabeled_samples([url])` splits a URL into `domain`, `tld`, `subdomain`, `path`, and tokenized `words_raw` (uses `tldextract`). |
| `url_rules.py` | `url_rules.rules_main(domain, tld, subdomain, path, words_raw)` computes the lexical feature dict: digit/length/special-char counts, known-TLD and punycode flags, popularity (top-1M) lookups, brand/keyword list membership, and the NLP word features. The class loads its word lists in `__init__`. |
| `word_with_nlp.py` | `nlp_class` — groups URL words into keywords / brands / look-alikes / gibberish, computes the `*_word_*` features, and flags random/DGA-looking domains using the gibberish model. |
| `word_splitter_file.py` | `WordSplitterClass` — splits long concatenated tokens into real words using an Enchant dictionary plus a custom brand word list. **Requires the system `enchant` library.** |
| `gib_detect_train.py` | Character-bigram gibberish detector (`avg_transition_prob`) backed by `gib_model.pki`. |
| `ns_log.py` | `NsLog(name)` — minimal, quiet logger factory (NullHandler; the original wrote rotating log files, removed during vendoring). |
| `gib_model.pki` | Pickled bigram transition matrix + threshold for the gibberish detector. |
| `input/` | Word lists: `allbrands.txt`, `keywords.txt`, `FWB_domains.txt`, and the `top-1m.txt` popularity list. |

The feature names produced here are pinned in `URL_LEXICAL_FEATURE_COLUMNS`
(in [`../url.py`](../url.py)) and in the `url` stage's `feature_columns` in the config.
