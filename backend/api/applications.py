from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend import models
from sqlalchemy import or_

from backend.auth.auth import get_current_user
from backend.database import get_db
from backend.schemas import ApplicationRead


router = APIRouter(prefix="/applications", tags=["applications"])


def _scoped(db: Session, user: models.User):
    # Own-org apps plus the shared catalog (organization_id NULL).
    return db.query(models.Application).filter(
        or_(models.Application.organization_id == user.organization_id, models.Application.organization_id.is_(None))
    )


@router.get("", response_model=list[ApplicationRead])
def list_applications(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
) -> list[models.Application]:
    return _scoped(db, current_user).order_by(models.Application.cloud_provider, models.Application.name).all()


@router.get("/{application_id}", response_model=ApplicationRead)
def get_application(
    application_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
) -> models.Application:
    application = (
        _scoped(db, current_user)
        .filter(models.Application.id == application_id)
        .first()
    )
    if application is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found",
        )
    return application
