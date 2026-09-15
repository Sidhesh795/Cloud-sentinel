from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend import models
from backend.auth.auth import hash_password, normalize_role, require_admin_or_security
from backend.database import get_db
from backend.db.repositories.events import SecurityEventRepository
from backend.db.repositories.users import UserRepository
from backend.config import using_mongodb
from backend.schemas import AdminUserCreate, AdminUserUpdate, UserBase


router = APIRouter(prefix="/admin/users", tags=["admin"])


def _org_id(current_user: models.User) -> int | None:
    return current_user.organization_id


def _query_org_users(db: Session, current_user: models.User):
    query = db.query(models.User)
    if _org_id(current_user) is not None:
        query = query.filter(models.User.organization_id == _org_id(current_user))
    return query


def _get_org_user_or_404(db: Session, current_user: models.User, user_id: int) -> models.User:
    user = _query_org_users(db, current_user).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


def _audit_admin_action(db: Session, actor: models.User, target: models.User, action: str) -> None:
    event = models.SecurityEvent(
        organization_id=actor.organization_id,
        user_id=target.id,
        event_type=action,
        severity="INFO",
        source="CONTROL_PLANE",
        description=f"{actor.username} performed {action} for {target.username}.",
        metadata_json={"actor_user_id": actor.id, "target_user_id": target.id},
    )
    db.add(event)
    if using_mongodb():
        SecurityEventRepository().insert(
            {
                "organization_id": str(actor.organization_id),
                "user_id": str(target.id),
                "event_type": action,
                "severity": "INFO",
                "timestamp": event.timestamp,
                "source": "CONTROL_PLANE",
                "description": event.description,
                "metadata": event.metadata_json,
            }
        )


@router.post("", response_model=UserBase, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: AdminUserCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin_or_security),
) -> models.User:
    requested_role = normalize_role(payload.role)
    actor_role = normalize_role(current_user.role)
    if requested_role == "ADMIN" and actor_role != "ADMIN":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can create admins")
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    if db.query(models.User).filter(models.User.email == payload.email).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")

    now = datetime.now(timezone.utc)
    user = models.User(
        organization_id=current_user.organization_id,
        username=payload.username,
        password_hash=hash_password(payload.password),
        display_name=payload.display_name,
        role=requested_role,
        email=str(payload.email),
        status=payload.status,
        is_active=payload.status == "ACTIVE",
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    db.flush()
    _audit_admin_action(db, current_user, user, "USER_CREATED")
    db.commit()
    db.refresh(user)
    if using_mongodb():
        UserRepository().insert(
            {
                "organization_id": str(user.organization_id),
                "sqlite_id": user.id,
                "username": user.username,
                "email": user.email,
                "display_name": user.display_name,
                "role": user.role,
                "status": user.status,
                "environment": "DEMO",
                "last_login": user.last_login,
                "last_seen": user.last_seen,
            }
        )
    return user


@router.get("", response_model=list[UserBase])
def list_admin_users(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin_or_security),
) -> list[models.User]:
    return _query_org_users(db, current_user).order_by(models.User.username).all()


@router.get("/{user_id}", response_model=UserBase)
def get_admin_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin_or_security),
) -> models.User:
    return _get_org_user_or_404(db, current_user, user_id)


@router.patch("/{user_id}", response_model=UserBase)
def update_user(
    user_id: int,
    payload: AdminUserUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin_or_security),
) -> models.User:
    user = _get_org_user_or_404(db, current_user, user_id)
    requested_role = normalize_role(payload.role) if payload.role else None
    if requested_role == "ADMIN" and normalize_role(current_user.role) != "ADMIN":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can assign admins")
    if payload.email is not None:
        user.email = str(payload.email)
    if payload.display_name is not None:
        user.display_name = payload.display_name
    if requested_role is not None:
        user.role = requested_role
    if payload.status is not None:
        user.status = payload.status
        user.is_active = payload.status == "ACTIVE"
    user.updated_at = datetime.now(timezone.utc)
    _audit_admin_action(db, current_user, user, "USER_UPDATED")
    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}", response_model=UserBase)
def disable_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin_or_security),
) -> models.User:
    user = _get_org_user_or_404(db, current_user, user_id)
    if user.id == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot disable your own account")
    user.status = "DISABLED"
    user.is_active = False
    user.updated_at = datetime.now(timezone.utc)
    _audit_admin_action(db, current_user, user, "USER_DISABLED")
    db.commit()
    db.refresh(user)
    return user
