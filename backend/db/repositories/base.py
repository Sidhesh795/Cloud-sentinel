from __future__ import annotations

from typing import Any

try:
    from bson import ObjectId
except Exception:  # pragma: no cover - only used when pymongo is unavailable
    ObjectId = str

from backend.db.mongodb import get_mongo_database, stamp


class MongoRepository:
    collection_name: str

    def __init__(self) -> None:
        db = get_mongo_database()
        self.collection = None if db is None else db[self.collection_name]

    @property
    def available(self) -> bool:
        return self.collection is not None

    def insert(self, document: dict[str, Any]) -> str | None:
        if self.collection is None:
            return None
        result = self.collection.insert_one(stamp(document))
        return str(result.inserted_id)

    def find_by_id(self, document_id: str, organization_id: str | None = None) -> dict[str, Any] | None:
        if self.collection is None:
            return None
        query: dict[str, Any] = {"_id": ObjectId(document_id)}
        if organization_id is not None:
            query["organization_id"] = organization_id
        return self.collection.find_one(query)

    def list_for_org(self, organization_id: str, limit: int = 100) -> list[dict[str, Any]]:
        if self.collection is None:
            return []
        return list(self.collection.find({"organization_id": organization_id}).limit(limit))
