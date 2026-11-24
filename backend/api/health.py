from fastapi import APIRouter

from backend.config import DEMO_MODE
from backend.schemas import HealthResponse


router = APIRouter(prefix="/health", tags=["health"])


@router.get("", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="healthy", service="cloudsentinel-backend", demo_mode=DEMO_MODE)

