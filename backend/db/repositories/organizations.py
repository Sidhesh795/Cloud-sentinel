from backend.db.repositories.base import MongoRepository


class OrganizationRepository(MongoRepository):
    collection_name = "organizations"
