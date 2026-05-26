# `features/url/lexical/input/` — word lists for the URL analyzer

Static text data loaded by the vendored lexical analyzer (`../url_rules.py`,
`../word_with_nlp.py`, `../word_splitter_file.py`). Resolved relative to the package.

| File | Used for |
|------|----------|
| `allbrands.txt` | Known brand names — brand detection and the Enchant custom dictionary. |
| `keywords.txt` | Phishing-related keywords (login, verify, secure, ...). |
| `FWB_domains.txt` | "Free web-hosting / bulletproof" domains flagged by the FWB-list rule. |
| `top-1m.txt` | Top-1M popular hosts for the popularity features. |
