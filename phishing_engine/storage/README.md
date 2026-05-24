# `storage/` — MongoDB persistence

`mongo.py` holds `MongoStore`, the **only** component in the engine that writes to
MongoDB. Collectors use its write methods; the training pipeline uses its read helpers;
the prediction pipeline never touches it.

### Document schema (one per normalized URL, `_id` = normalized URL)
```js
{
  _id, url, normalized_url, domain,
  label: "phish" | "benign" | null,
  source: "phishtank" | "tranco" | "search",
  created_at, updated_at,
  raw: { domain_record: {...}, content: { html, tls: {...} } },
  raw_collected: { domain_record_at, content_at }
}
```
Certificates inside `raw.content.tls` are stored as DER bytes (`certificates_der`); the
content feature extractor reconstructs them at feature time.

### API
- **Writes (collectors):** `add_url` (URL + label + source), `store_domain_record`,
  `store_content`.
- **Reads (training):** `iter_labeled(require=...)` yields labeled docs that have the
  required raw data.

Indexes on `domain` and `label` are created on connect.
