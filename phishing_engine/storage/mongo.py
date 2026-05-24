"""MongoDB raw-data store.

This is the ONLY component that writes to MongoDB. Collectors use it to persist the
raw data they extract from sources (URL lists, domain records, page content). The
training pipeline uses the read helpers; the prediction pipeline never touches Mongo.

Document schema (one per normalized URL, keyed by ``_id``):

    {
      "_id": <normalized_url>,
      "url": <original_url>,
      "normalized_url": <normalized_url>,
      "domain": <domain>,
      "label": "phish" | "benign" | None,
      "source": <collector source>,
      "created_at", "updated_at": <datetime>,
      "raw": {
        "domain_record": { ... DNS/IP/RDAP record ... },
        "content": { "html": ..., "tls": { ... }, ... }
      },
      "raw_collected": { "domain_record_at": ..., "content_at": ... }
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

    def __init__(self, uri: str, database: str, collection: str):
        """Connect and ensure the ``domain`` and ``label`` indexes exist."""
        self.client = MongoClient(uri)
        self.collection = self.client[database][collection]
        self.collection.create_index("domain")
        self.collection.create_index("label")

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

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
        """Attach a collected raw domain record to a URL document under ``raw.domain_record``."""
        now = self._now()
        self.collection.update_one(
            {"_id": normalized_url},
            {"$set": {"raw.domain_record": record, "raw_collected.domain_record_at": now, "updated_at": now}},
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

    def iter_labeled(self, require: Optional[str] = None, limit: int = 0) -> Iterator[dict]:
        """Iterate documents that carry a label.

        ``require`` may be ``"domain_record"`` or ``"content"`` to only yield documents
        that already have that raw data collected.
        """
        query: dict = {"label": {"$in": ["phish", "benign"]}}
        if require == "domain_record":
            query["raw.domain_record"] = {"$exists": True}
        elif require == "content":
            query["raw.content"] = {"$exists": True}

        cursor = self.collection.find(query)
        if limit:
            cursor = cursor.limit(limit)
        for doc in cursor:
            yield doc

    def close(self) -> None:
        """Close the MongoDB client connection."""
        self.client.close()
