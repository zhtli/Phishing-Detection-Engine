# `storage/` — MongoDB persistence

`mongo.py` holds `MongoStore`, the **only** component in the engine that writes to
MongoDB. Collectors use its write methods; the training pipeline uses its read helpers;
the prediction pipeline never touches it.

### Two collections

The domain record is **not** embedded in each URL doc — a domain is shared by many URLs,
so it is stored once per `(domain, collection date)` in a separate domains collection and
referenced by id. Keying by date keeps point-in-time snapshots: a domain re-collected on
a later day gets a new version, so a URL's example always pairs with the domain state seen
when that URL was collected.

**URL collection** (one per normalized URL, `_id` = normalized URL):
```js
{
  _id, url, normalized_url, domain,
  label: "phish" | "benign" | null,
  source: "phishtank" | "tranco" | "search",
  created_at, updated_at,
  raw: { domain_record_ref: "<domain>|<YYYY-MM-DD>", content: { html, tls: {...} } },
  raw_collected: { domain_record_at, content_at }
}
```

**Domains collection** (one per `(domain, date)`, `_id` = `"<domain>|<YYYY-MM-DD>"`):
```js
{ _id, domain, collected_date, collected_at, record: {...} }
```

**Collector state** (`collector_state`): per-source progress so cron runs are
incremental/resumable. The phishtank collector stores its last successful run time
(`_id` = source name) and, on the next run, filters the feed to entries verified since
then. The search collector stores the set of terms it has finished (`_id` =
`"<source>:done_terms"`) and skips them on a re-run, so a crash or rate-limit block loses
no progress.
```js
{ _id: "phishtank", last_run_at, updated_at }
{ _id: "search:done_terms", terms: [...], updated_at }
```

Certificates inside `raw.content.tls` are stored as DER bytes (`certificates_der`); the
content feature extractor reconstructs them at feature time.

### API
- **Writes (collectors):** `add_url` (URL + label + source), `store_domain_record`
  (writes the domains collection + the URL doc's `domain_record_ref`), `store_content`.
- **State (collectors):** `get_last_run(source)` / `set_last_run(source, when)` read and
  advance the per-source incremental watermark; `get_done_terms(source)` /
  `mark_term_done(source, term)` read and extend the search collector's done-terms set —
  both in `collector_state`.
- **Reads (training):** `iter_labeled(require=...)` yields labeled docs that have the
  required raw data. For `require="domain_record"` it joins the referenced domain doc and
  exposes its `record` under `raw.domain_record`, so readers are storage-agnostic.

Indexes on `domain` and `label` (URL collection) and `domain` (domains collection) are
created on connect.
