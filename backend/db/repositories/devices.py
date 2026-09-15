from backend.db.repositories.base import MongoRepository


class DeviceRepository(MongoRepository):
    collection_name = "devices"
