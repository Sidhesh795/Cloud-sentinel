from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, selectinload

from backend import models
from backend.database import get_db
from backend.schemas import UserBase, UserPostureRead
from backend.security.anomaly import assess_behavior
from backend.security.posture import evaluate_posture
from backend.security.tags import persist_active_tags


router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserBase])
def list_users(db: Session = Depends(get_db)) -> list[models.User]:
    return db.query(models.User).order_by(models.User.username).all()


@router.get("/{user_id}", response_model=UserBase)
def get_user(user_id: int, db: Session = Depends(get_db)) -> models.User:
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.get("/{user_id}/posture", response_model=UserPostureRead)
def get_user_posture(user_id: int, db: Session = Depends(get_db)) -> UserPostureRead:
    user = (
        db.query(models.User)
        .options(selectinload(models.User.devices), selectinload(models.User.security_tags))
        .filter(models.User.id == user_id)
        .first()
    )
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    device = user.devices[0] if user.devices else None
    latest_telemetry = max(user.telemetry, key=lambda item: item.timestamp) if user.telemetry else None
    anomaly = assess_behavior(latest_telemetry) if latest_telemetry else None
    posture = evaluate_posture(user, device, anomaly)
    active_tags = persist_active_tags(db, user.id, device.id if device else None, posture.tags)
    db.commit()
    return UserPostureRead(
        user=user,
        devices=user.devices,
        security_tags=active_tags,
        posture_status=posture.status,
        posture_risk=posture.posture_risk,
        last_evaluated_at=posture.evaluated_at,
        reasons=posture.reasons,
    )
