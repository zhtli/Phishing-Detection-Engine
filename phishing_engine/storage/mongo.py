"""MongoDB raw-data store.

This is the ONLY component that writes to MongoDB. Collectors use it to persist the
raw data they extract from sources (URL lists, domain records, page content). The
training pipeline uses the read helpers; the prediction pipeline never touches Mongo.

Two collections. The URL collection holds one document per normalized URL; the domain
record is **not** embedded but stored once per ``(domain, collection date)`` in a
separate domains collection and referenced by id. A domain is shared by many URLs, so
this avoids duplicating its DNS/IP/RDAP record across every URL on that host. Keying by
date (not just domain) keeps point-in-time snapshots: a domain re-collected on a later
day gets a new version, so a URL's training example always pairs with the domain state
captured when that URL was seen.

URL document (keyed by ``_id`` = normalized URL):

    {
      "_id": <normalized_url>,
      "url": <original_url>,
      "normalized_url": <normalized_url>,
      "domain": <domain>,
      "label": "phish" | "benign" | None,
      "source": <collector source>,
      "created_at", "updated_at": <datetime>,
      "raw": {
        "domain_record_ref": "<domain>|<YYYY-MM-DD>",  # -> domains collection _id
        "content": { "html": ..., "tls": { ... }, ... }
      },
      "raw_collected": { "domain_record_at": ..., "content_at": ... }
    }

Domain document (keyed by ``_id`` = ``"<domain>|<YYYY-MM-DD>"``):

    {
      "_id": "<domain>|<YYYY-MM-DD>",
      "domain": <domain>,
      "collected_date": "<YYYY-MM-DD>",
      "collected_at": <datetime>,
      "record": { ... DNS/IP/RDAP record ... }
    }
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterator, Optional

from pymongo import MongoClient

from phishing_engine.core.urls import extract_domain, normalize_url


class MongoStore:
    """Read/write handle for the single URL-documents collection.

    Writes are used by the collectors only; ``iter_*`` reads are used by training.
    """

    def __init__(self, uri: str, database: str, collection: str, domain_collection: str = "domain_records"):
        """Connect and ensure the URL and domain collection indexes exist."""
        self.client = MongoClient(uri)
        db = self.client[database]
        self.collection = db[collection]
        self.domains = db[domain_collection]
        self.state = db["collector_state"]
        self.collection.create_index("domain")
        self.collection.create_index("label")
        self.domains.create_index("domain")

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    # ------------------------------------------------------------ collector state

    def get_last_run(self, source: str) -> Optional[datetime]:
        """Return the saved last-run time (UTC) for a collector source, or None.

        Collectors use this as an incremental watermark: the next run only pulls feed
        entries newer than the previous successful run.
        """
        doc = self.state.find_one({"_id": source})
        ts = doc.get("last_run_at") if doc else None
        if isinstance(ts, datetime) and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts

    def set_last_run(self, source: str, when: datetime) -> None:
        """Persist ``when`` as the last successful run time for a collector source."""
        self.state.update_one(
            {"_id": source},
            {"$set": {"last_run_at": when, "updated_at": self._now()}},
            upsert=True,
        )

    def get_done_terms(self, source: str) -> set:
        """Return the set of search terms already completed for a source.

        Lets ``cli.collect search`` resume after a crash or rate-limit block: terms
        recorded by ``mark_term_done`` are skipped on a re-run.
        """
        doc = self.state.find_one({"_id": f"{source}:done_terms"})
        return set(doc.get("terms", [])) if doc else set()

    def mark_term_done(self, source: str, term: str) -> None:
        """Record that ``term`` has been fully searched and ingested for a source."""
        self.state.update_one(
            {"_id": f"{source}:done_terms"},
            {"$addToSet": {"terms": term}, "$set": {"updated_at": self._now()}},
            upsert=True,
        )

    # ------------------------------------------------------------------ writes

    def add_url(self, url: str, label: Optional[str] = None, source: Optional[str] = None) -> str:
        """Upsert a URL document with its label/source. Returns the normalized URL."""
        normalized = normalize_url(url)
        domain = extract_domain(normalized)
        now = self._now()

        update = {
            "$setOnInsert": {
                "_id": normalized,
                "url": url,
                "normalized_url": normalized,
                "domain": domain,
                "created_at": now,
            },
            "$set": {"updated_at": now},
        }
        if label or source:
            update["$set"].update({"label": label, "source": source})

        self.collection.update_one({"_id": normalized}, update, upsert=True)
        return normalized

    def store_domain_record(self, normalized_url: str, record: dict) -> None:
        """Store a raw domain record in the domains collection and reference it from the URL doc.

        The record is keyed by ``(domain, collection date)`` so it is written once per
        domain per day (re-collection within a day overwrites; a later day creates a new
        version). The URL document gets a ``raw.domain_record_ref`` pointing at that id.
        """
        now = self._now()
        domain = extract_domain(normalized_url)
        domain_doc_id = f"{domain}|{now.strftime('%Y-%m-%d')}"

        self.domains.update_one(
            {"_id": domain_doc_id},
            {
                "$set": {"record": record, "collected_at": now},
                "$setOnInsert": {"domain": domain, "collected_date": now.strftime("%Y-%m-%d")},
            },
            upsert=True,
        )
        self.collection.update_one(
            {"_id": normalized_url},
            {"$set": {"raw.domain_record_ref": domain_doc_id, "raw_collected.domain_record_at": now, "updated_at": now}},
            upsert=True,
        )

    def store_content(self, normalized_url: str, content: dict) -> None:
        """Attach collected raw page content to a URL document under ``raw.content``."""
        now = self._now()
        self.collection.update_one(
            {"_id": normalized_url},
            {"$set": {"raw.content": content, "raw_collected.content_at": now, "updated_at": now}},
            upsert=True,
        )

    # ------------------------------------------------------------------- reads

    def count_labeled(self, require: Optional[str] = None, limit: int = 0) -> int:
        """Count labeled documents that ``iter_labeled`` would yield (for progress totals)."""
        query: dict = {"label": {"$in": ["phish", "benign"]}}
        if require == "domain_record":
            query["raw.domain_record_ref"] = {"$exists": True}
        elif require == "content":
            query["raw.content"] = {"$exists": True}
        total = self.collection.count_documents(query)
        return min(total, limit) if limit else total

    def iter_labeled(self, require: Optional[str] = None, limit: int = 0) -> Iterator[dict]:
        """Iterate documents that carry a label.

        ``require`` may be ``"domain_record"`` or ``"content"`` to only yield documents
        that already have that raw data collected. For ``"domain_record"`` the referenced
        domain document is joined and its record placed back under ``raw.domain_record``,
        so callers (``build_train_artifacts``) read it the same way regardless of storage.
        """
        query: dict = {"label": {"$in": ["phish", "benign"]}}
        if require == "domain_record":
            query["raw.domain_record_ref"] = {"$exists": True}
            pipeline: list = [{"$match": query}]
            if limit:
                pipeline.append({"$limit": limit})
            pipeline.append(
                {
                    "$lookup": {
                        "from": self.domains.name,
                        "localField": "raw.domain_record_ref",
                        "foreignField": "_id",
                        "as": "_domain_doc",
                    }
                }
            )
            for doc in self.collection.aggregate(pipeline):
                matches = doc.pop("_domain_doc", None) or []
                if matches:
                    doc.setdefault("raw", {})["domain_record"] = matches[0].get("record")
                yield doc
            return

        if require == "content":
            query["raw.content"] = {"$exists": True}

        cursor = self.collection.find(query)
        if limit:
            cursor = cursor.limit(limit)
        for doc in cursor:
            yield doc

    def close(self) -> None:
        """Close the MongoDB client connection."""
        self.client.close()
