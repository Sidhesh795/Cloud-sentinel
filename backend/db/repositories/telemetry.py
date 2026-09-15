from backend.db.repositories.base import MongoRepository


class TelemetryRepository(MongoRepository):
    collection_name = "telemetry"
