from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend import models
from backend.database import get_db
from backend.schemas import SecurityEventRead


router = APIRouter(tags=["events"])


@router.get("/events", response_model=list[SecurityEventRead])
def list_events(db: Session = Depends(get_db)) -> list[SecurityEventRead]:
    events = (
        db.query(models.SecurityEvent)
        .order_by(models.SecurityEvent.timestamp.desc())
        .limit(100)
        .all()
    )
    return [SecurityEventRead.from_model(event) for event in events]


@router.get("/users/{user_id}/events", response_model=list[SecurityEventRead])
def list_user_events(user_id: int, db: Session = Depends(get_db)) -> list[SecurityEventRead]:
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    events = (
        db.query(models.SecurityEvent)
        .filter(models.SecurityEvent.user_id == user_id)
        .order_by(models.SecurityEvent.timestamp.desc())
        .limit(100)
        .all()
    )
    return [SecurityEventRead.from_model(event) for event in events]
