from backend.db.repositories.base import MongoRepository


class UserRepository(MongoRepository):
    collection_name = "users"
