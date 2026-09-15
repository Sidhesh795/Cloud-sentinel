from backend.db.repositories.base import MongoRepository


class SecurityEventRepository(MongoRepository):
    collection_name = "security_events"
