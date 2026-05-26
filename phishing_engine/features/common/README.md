# `features/common/` — shared transformation infrastructure

Shared by the [domain](../domain/) and [content](../content/) transformation sets.

| File | What it does |
|------|--------------|
| `base.py` | `Transformation` abstract base — the `features` (columns + dtypes) and `transform(df)` contract every transformation implements. |
| `helpers.py` | Math/util helpers: entropy, simhash, mean/stddev/min/max, md5 hashing, date helpers. |
