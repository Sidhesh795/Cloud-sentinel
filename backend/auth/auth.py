from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from backend import models
from backend.config import DEMO_MODE, JWT_SECRET, SESSION_MINUTES
from backend.database import get_db


SECRET_KEY = JWT_SECRET
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))


def create_access_token(subject: str, expires_delta: timedelta | None = None) -> str:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_gateway_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=SESSION_MINUTES)
    return jwt.encode({"sub": subject, "aud": "gateway", "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)


def username_from_token(token: str) -> str | None:
    """Accepts a gateway session token or a regular access token."""
    for kwargs in ({"audience": "gateway"}, {}):
        try:
            return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], **kwargs).get("sub")
        except jwt.PyJWTError:
            continue
    return None


def authenticate_user(db: Session, username: str, password: str) -> models.User | None:
    clean_username = (username or "").strip()
    user = (
        db.query(models.User)
        .filter(models.User.username.ilike(clean_username))
        .first()
    )
    if not user and DEMO_MODE:
        from backend.data.seed import (
            DEMO_PASSWORD,
            USERS,
            upsert_baseline_telemetry,
            upsert_device,
            upsert_organization,
            upsert_security_tags,
            upsert_user,
        )

        demo_match = next(
            (u for u in USERS if u["username"].lower() == clean_username.lower()),
            None,
        )
        if demo_match and password == DEMO_PASSWORD:
            org = upsert_organization(db)
            user = upsert_user(db, org, demo_match)
            device = upsert_device(db, user)
            upsert_security_tags(db, user, device)
            upsert_baseline_telemetry(db, user, device)
            db.commit()
            db.refresh(user)

    if not user:
        return None

    if not user.is_active or getattr(user, "status", "ACTIVE") != "ACTIVE":
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def normalize_role(role: str) -> str:
    return role.strip().upper()


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_roles(*allowed_roles: str):
    allowed = {normalize_role(role) for role in allowed_roles}

    def dependency(current_user: models.User = Depends(get_current_user)) -> models.User:
        if normalize_role(current_user.role) not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role for this operation",
            )
        return current_user

    return dependency


def require_admin_or_security(
    current_user: models.User = Depends(get_current_user),
) -> models.User:
    role = normalize_role(current_user.role)
    if role not in {"ADMIN", "SECURITY_ANALYST", "ANALYST"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator or security analyst role required",
        )
    return current_user
