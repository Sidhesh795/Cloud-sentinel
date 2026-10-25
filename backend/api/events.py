from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend import models
from backend.auth.auth import get_current_user, get_scoped_user, is_privileged
from backend.database import get_db
from backend.schemas import SecurityEventRead


router = APIRouter(tags=["events"])


@router.get("/events", response_model=list[SecurityEventRead])
def list_events(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
) -> list[SecurityEventRead]:
    query = db.query(models.SecurityEvent)
    if is_privileged(current_user):
        query = query.filter(models.SecurityEvent.organization_id == current_user.organization_id)
    else:
        query = query.filter(models.SecurityEvent.user_id == current_user.id)
    events = (
        query
        .order_by(models.SecurityEvent.timestamp.desc())
        .limit(100)
        .all()
    )
    return [SecurityEventRead.from_model(event) for event in events]


@router.get("/users/{user_id}/events", response_model=list[SecurityEventRead])
def list_user_events(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
) -> list[SecurityEventRead]:
    get_scoped_user(db, current_user, user_id)
    events = (
        db.query(models.SecurityEvent)
        .filter(models.SecurityEvent.user_id == user_id)
        .order_by(models.SecurityEvent.timestamp.desc())
        .limit(100)
        .all()
    )
    return [SecurityEventRead.from_model(event) for event in events]
