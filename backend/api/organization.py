from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend import models
from backend.auth.auth import get_current_user
from backend.database import get_db
from backend.schemas import OrganizationRead


router = APIRouter(prefix="/organization", tags=["organization"])


@router.get("", response_model=OrganizationRead)
def get_organization(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
) -> models.Organization:
    if current_user.organization_id is None:
        organization = db.query(models.Organization).order_by(models.Organization.id).first()
    else:
        organization = (
            db.query(models.Organization)
            .filter(models.Organization.id == current_user.organization_id)
            .first()
        )
    if organization is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return organization
