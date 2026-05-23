from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pymongo import MongoClient

from phishing_engine.pipeline import StageResult


class MongoStore:
    def __init__(
        self,
        uri: str,
        database: str,
        collection: str,
        benign_collection: Optional[str] = None,
        phish_collection: Optional[str] = None,
    ):
        self.client = MongoClient(uri)
        self.collection = self.client[database][collection]
        self.collection.create_index("domain")
        self.collection.create_index("label")

        self.benign_collection = (
            self.client[database][benign_collection] if benign_collection else None
        )
        self.phish_collection = (
            self.client[database][phish_collection] if phish_collection else None
        )
        self._label_collections = {
            "benign": self.benign_collection,
            "phish": self.phish_collection,
        }

        for collection_obj in self._label_collections.values():
            if collection_obj is None:
                continue
            collection_obj.create_index("domain")
            collection_obj.create_index("label")

    def _now(self):
        return datetime.now(timezone.utc)

    def _label_collection(self, label: Optional[str]):
        if not label:
            return None
        return self._label_collections.get(label.lower())

    def _update_label_collection(self, label: Optional[str], normalized_url: str, update: dict) -> None:
        collection_obj = self._label_collection(label)
        if not collection_obj:
            return
        collection_obj.update_one({"_id": normalized_url}, update, upsert=True)

    def upsert_base(
        self,
        url: str,
        normalized_url: str,
        domain: str,
        label: Optional[str] = None,
        source: Optional[str] = None,
    ) -> None:
        now = self._now()
        update = {
            "$setOnInsert": {
                "_id": normalized_url,
                "url": url,
                "normalized_url": normalized_url,
                "domain": domain,
                "created_at": now,
            },
            "$set": {
                "updated_at": now,
            },
        }

        if label or source:
            update["$set"].update(
                {
                    "label": label,
                    "label_source": source,
                    "label_updated_at": now,
                }
            )
            update.setdefault("$addToSet", {}).update(
                {
                    "label_history": {
                        "label": label,
                        "source": source,
                        "added_at": now,
                    }
                }
            )

        self.collection.update_one({"_id": normalized_url}, update, upsert=True)
        self._update_label_collection(label, normalized_url, update)

    def update_stage_result(
        self,
        normalized_url: str,
        stage_id: str,
        result: StageResult,
        label: Optional[str] = None,
    ) -> None:
        now = self._now()
        payload = {
            "label": result.label,
            "probabilities": result.probabilities,
            "confidence": result.confidence,
            "decision": result.decision,
            "features": result.features,
            "artifacts": result.artifacts,
            "missing_features": result.missing_features,
            "extra_features": result.extra_features,
            "error": result.error,
            "updated_at": now,
        }
        self.collection.update_one(
            {"_id": normalized_url},
            {"$set": {f"stages.{stage_id}": payload, "updated_at": now}},
            upsert=True,
        )
        self._update_label_collection(
            label,
            normalized_url,
            {"$set": {f"stages.{stage_id}": payload, "updated_at": now}},
        )

    def update_decision(
        self,
        normalized_url: str,
        decision: str,
        stage_id: str,
        result: StageResult,
        label: Optional[str] = None,
    ) -> None:
        now = self._now()
        payload = {
            "decision": decision,
            "stage_id": stage_id,
            "label": result.label,
            "confidence": result.confidence,
            "probabilities": result.probabilities,
            "decided_at": now,
        }
        self.collection.update_one(
            {"_id": normalized_url},
            {"$set": {"last_decision": payload, "updated_at": now}},
            upsert=True,
        )
        self._update_label_collection(
            label,
            normalized_url,
            {"$set": {"last_decision": payload, "updated_at": now}},
        )

    def close(self) -> None:
        self.client.close()
