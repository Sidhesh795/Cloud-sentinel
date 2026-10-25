from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from backend.auth.auth import authenticate_user, create_access_token, get_current_user
from backend.database import get_db
from backend.models import User
from backend.schemas import LoginRequest, LoginResponse, UserBase, UserSummary


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> LoginResponse:
    from backend.security.behavior import record_login

    user = authenticate_user(db, payload.username, payload.password)
    record_login(db, payload.username, user, request.client.host if request.client else None)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    now = datetime.now(timezone.utc)
    user.last_login = now
    user.last_seen = now
    db.commit()
    return LoginResponse(
        access_token=create_access_token(user.username),
        user=UserSummary.model_validate(user),
    )


@router.get("/me", response_model=UserBase)
def read_current_user(current_user: User = Depends(get_current_user)) -> User:
    return current_user
