# `features/url/` — URL stage features

Feature extraction for the **url stage**: lexical features computed from the URL string
alone (no network, never fetches the page).

| File / dir | What it does |
|------------|--------------|
| `extractor.py` | `UrlLexicalFeatureExtractor` + `URL_LEXICAL_FEATURE_COLUMNS`. Parses a URL and computes its lexical features via the `lexical/` library. |
| [`lexical/`](lexical/README.md) | URL lexical analyzer (domain parser, rule engine, NLP word splitter, gibberish model). Third-party in origin. |
