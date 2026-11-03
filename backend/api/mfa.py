from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend import config, models
from backend.auth.auth import authenticate_user, create_access_token, get_current_user
from backend.database import get_db
from backend.security import mfa
from backend.security.ratelimit import ip_limit

router = APIRouter(prefix="/mfa", tags=["mfa"], dependencies=[Depends(ip_limit("mfa", "RL_MFA_PER_MIN"))])


class CodeBody(BaseModel):
    code: str = Field(min_length=6, max_length=32)


class DisableBody(CodeBody):
    password: str


def _log(db: Session, user: models.User, event_type: str, severity: str, description: str) -> None:
    db.add(models.SecurityEvent(
        organization_id=user.organization_id, user_id=user.id, event_type=event_type,
        severity=severity, description=description, source="IDENTITY_PROVIDER",
    ))
    db.commit()


@router.get("/status")
def mfa_status(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    return {"enabled": user.mfa_enabled, "recovery_codes_remaining": mfa.recovery_remaining(db, user) if user.mfa_enabled else 0}


@router.post("/setup")
def setup(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    if user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA is already enabled")
    secret = mfa.new_secret()
    user.mfa_secret_enc = mfa.encrypt_secret(secret)
    user.mfa_last_step = None
    db.commit()
    return {"secret": secret, "otpauth_uri": mfa.otpauth_uri(secret, user.email)}


@router.post("/enable")
def enable(body: CodeBody, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    if user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA is already enabled")
    if not user.mfa_secret_enc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Start setup first")
    if not mfa.check_code(db, user, body.code, allow_pending=True):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code")
    user.mfa_enabled = True
    codes = mfa.issue_recovery_codes(db, user)
    db.commit()
    _log(db, user, "MFA_ENABLED", "LOW", f"{user.username} enabled TOTP MFA")
    return {"recovery_codes": codes}


@router.post("/disable", status_code=status.HTTP_204_NO_CONTENT)
def disable(body: DisableBody, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)) -> None:
    if not user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA is not enabled")
    if authenticate_user(db, user.username, body.password) is None or not mfa.check_code(db, user, body.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid password or code")
    user.mfa_enabled = False
    user.mfa_secret_enc = None
    user.mfa_last_step = None
    db.query(models.MfaRecoveryCode).filter(models.MfaRecoveryCode.user_id == user.id).delete()
    db.commit()
    _log(db, user, "MFA_DISABLED", "MEDIUM", f"{user.username} disabled TOTP MFA")


@router.post("/recovery-codes")
def regenerate(body: CodeBody, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    if not user.mfa_enabled or not mfa.check_code(db, user, body.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code")
    codes = mfa.issue_recovery_codes(db, user)
    db.commit()
    return {"recovery_codes": codes}


@router.post("/stepup")
def stepup(body: CodeBody, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    """Re-prove possession of the second factor; returns a token whose MFA claim satisfies MFA_REQUIRED."""
    if not user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA is not enabled")
    if not mfa.check_code(db, user, body.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code")
    return {"access_token": create_access_token(user.username, mfa_at=int(datetime.now(timezone.utc).timestamp())), "token_type": "bearer"}
