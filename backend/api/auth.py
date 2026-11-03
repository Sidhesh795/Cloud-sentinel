from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from backend.auth.auth import (
    authenticate_user,
    create_access_token,
    create_mfa_pending_token,
    get_current_user,
    username_from_pending_token,
)
from backend.database import get_db
from backend.models import User
from backend.schemas import LoginRequest, LoginResponse, MfaLoginRequest, UserBase, UserSummary


router = APIRouter(prefix="/auth", tags=["auth"])


def _finish_login(db: Session, user: User, mfa_at: int | None = None) -> LoginResponse:
    now = datetime.now(timezone.utc)
    user.last_login = now
    user.last_seen = now
    db.commit()
    return LoginResponse(
        access_token=create_access_token(user.username, mfa_at=mfa_at),
        user=UserSummary.model_validate(user),
    )


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> LoginResponse:
    from backend.security.behavior import record_login

    ip = request.client.host if request.client else None
    user = authenticate_user(db, payload.username, payload.password)
    if user is not None and user.mfa_enabled:
        return LoginResponse(mfa_required=True, mfa_token=create_mfa_pending_token(user.username))
    record_login(db, payload.username, user, ip)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _finish_login(db, user)


@router.post("/mfa/verify", response_model=LoginResponse)
def verify_mfa(payload: MfaLoginRequest, request: Request, db: Session = Depends(get_db)) -> LoginResponse:
    from backend.security import mfa
    from backend.security.behavior import record_login

    username = username_from_pending_token(payload.mfa_token)
    user = db.query(User).filter(User.username == username).first() if username else None
    if user is None or not user.is_active or not user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA session expired. Sign in again.")
    ok = mfa.check_code(db, user, payload.code)
    record_login(db, user.username, user if ok else None, request.client.host if request.client else None)
    if not ok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid code")
    return _finish_login(db, user, mfa_at=int(datetime.now(timezone.utc).timestamp()))


@router.get("/me", response_model=UserBase)
def read_current_user(current_user: User = Depends(get_current_user)) -> User:
    return current_user
