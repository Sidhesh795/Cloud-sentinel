from fastapi import APIRouter

from backend.schemas import HealthResponse


router = APIRouter(prefix="/health", tags=["health"])


@router.get("", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="healthy", service="cloudsentinel-backend")
