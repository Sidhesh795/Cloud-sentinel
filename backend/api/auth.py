from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.auth.auth import authenticate_user, create_access_token, get_current_user
from backend.database import get_db
from backend.models import User
from backend.schemas import LoginRequest, LoginResponse, UserBase, UserSummary


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    user = authenticate_user(db, payload.username, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return LoginResponse(
        access_token=create_access_token(user.username),
        user=UserSummary.model_validate(user),
    )


@router.get("/me", response_model=UserBase)
def read_current_user(current_user: User = Depends(get_current_user)) -> User:
    return current_user
