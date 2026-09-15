from fastapi import APIRouter

from backend.config import DATA_STORE
from backend.db.mongodb import health as mongodb_health
from backend.schemas import HealthResponse, MongoHealthResponse


router = APIRouter(prefix="/health", tags=["health"])


@router.get("", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="healthy", service="cloudsentinel-backend")


@router.get("/mongodb", response_model=MongoHealthResponse)
def health_mongodb() -> MongoHealthResponse:
    payload = mongodb_health()
    if DATA_STORE != "mongodb" and payload["status"] != "healthy":
        payload["detail"] = "MongoDB is optional until DATA_STORE=mongodb is configured"
    return MongoHealthResponse(**payload)
