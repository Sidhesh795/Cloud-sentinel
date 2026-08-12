from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend import models
from backend.database import get_db
from backend.schemas import ApplicationRead


router = APIRouter(prefix="/applications", tags=["applications"])


@router.get("", response_model=list[ApplicationRead])
def list_applications(db: Session = Depends(get_db)) -> list[models.Application]:
    return db.query(models.Application).order_by(models.Application.cloud_provider, models.Application.name).all()


@router.get("/{application_id}", response_model=ApplicationRead)
def get_application(application_id: int, db: Session = Depends(get_db)) -> models.Application:
    application = (
        db.query(models.Application)
        .filter(models.Application.id == application_id)
        .first()
    )
    if application is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found",
        )
    return application
