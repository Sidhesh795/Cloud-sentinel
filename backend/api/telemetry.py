from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend import models
from backend.database import get_db
from backend.schemas import TelemetryCreate, TelemetryRead


router = APIRouter(tags=["telemetry"])


@router.post("/telemetry", response_model=TelemetryRead, status_code=status.HTTP_201_CREATED)
def create_telemetry(payload: TelemetryCreate, db: Session = Depends(get_db)) -> models.Telemetry:
    user = db.query(models.User).filter(models.User.id == payload.user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    device = (
        db.query(models.Device)
        .filter(models.Device.device_id == payload.device_id, models.Device.user_id == user.id)
        .first()
    )
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    telemetry = models.Telemetry(
        user_id=user.id,
        device_id=device.id,
        requests_per_minute=payload.requests_per_minute,
        data_download_mb=payload.data_download_mb,
        failed_logins=payload.failed_logins,
        unique_applications=payload.unique_applications,
        access_frequency=payload.access_frequency,
        login_hour=payload.login_hour,
        location=payload.location,
    )
    db.add(telemetry)
    db.commit()
    db.refresh(telemetry)
    return telemetry


@router.get("/users/{user_id}/telemetry", response_model=list[TelemetryRead])
def list_user_telemetry(
    user_id: int,
    limit: int = 20,
    db: Session = Depends(get_db),
) -> list[models.Telemetry]:
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return (
        db.query(models.Telemetry)
        .filter(models.Telemetry.user_id == user_id)
        .order_by(models.Telemetry.timestamp.desc())
        .limit(min(max(limit, 1), 100))
        .all()
    )
