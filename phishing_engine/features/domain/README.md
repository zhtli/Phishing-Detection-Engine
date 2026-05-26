# `features/domain/` — domain stage features

Feature extraction for the **domain stage**: takes a raw domain record (DNS / IP / RDAP /
WHOIS, the shape produced by `collectors/domain_record.py`) and produces a one-row feature
DataFrame. Derived from the DomainRadar feature extractor (Ondřej Ondryáš et al.) and now
maintained as part of this project.

| File / dir | What it does |
|------------|--------------|
| `extractor.py` | `DomainFeatureExtractor` — the adapter the stage imports. Configures the pipeline (data dir, enabled transformations) and runs it over one record. |
| `pipeline.py` | Orchestrator. `init_transformations(config)` builds the enabled transformation list (default: `dns`, `ip`, `geo`, `lexical`, `rdap_dn`, `rdap_ip`, `drop`); `extract_features(raw_data)` flattens each raw record, runs the transformations over the resulting `DataFrame`, and returns it plus an errors dict. |
| `flatten.py` | `DomainRecordFlattener` — reshapes the nested raw record into the flat column layout the transformations expect. First step of the pipeline, run per record before the DataFrame is built. |
| `util.py` | `get_safe(dict, "a.b.c")` — safe nested lookup used by the flattener. |
| [`transformations/`](transformations/README.md) | The individual domain feature transformations (DNS, IP, Geo, lexical, RDAP, column-drop). |
| `data/` | n-gram frequency tables (`ngram_freq*.json`) used by the lexical transformation. Gitignored. |

The shared `Transformation` base and math helpers live in [`../common/`](../common/);
HTML/TLS transformations live with the [content stage](../content/).
