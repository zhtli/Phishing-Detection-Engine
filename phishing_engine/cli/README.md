# `cli/` — command-line tools

Three independent entry points, one per workflow. Each is runnable with `python -m`.

| File | Command | Does | Writes Mongo? |
|------|---------|------|---------------|
| `predict.py` | `python -m phishing_engine.cli.predict --url URL` | Score one URL through the pipeline; print the result as JSON. | No |
| `train.py` | `python -m phishing_engine.cli.train --stage url\|domain\|content\|all` | Train a stage's model from labeled Mongo data; write it to disk. | No (reads only) |
| `collect.py` | `python -m phishing_engine.cli.collect <subcommand>` | Run a collector and store raw data to Mongo. Subcommands: `phishtank`, `tranco`, `search`, `enrich-domain`, `enrich-content`. | **Yes — the only writer** |

All three accept `--config` (default `config/pipeline.json`). `collect.py` is designed to
be driven by cron — see the crontab example in the repository-root README.
