import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from backend import models
from backend.api.devices import (
    HEARTBEAT_SECONDS,
    _audit_device_event,
    _fingerprint,
    apply_heartbeat,
    apply_posture,
)
from backend.auth.auth import bearer_scheme, require_admin_or_security
from backend.database import get_db
from backend.schemas import (
    AgentEnrollRequest,
    AgentEnrollResponse,
    DeviceHeartbeatRequest,
    DeviceHeartbeatResponse,
    DevicePostureRequest,
    DevicePostureResponse,
    EnrollmentTokenRequest,
    EnrollmentTokenResponse,
)

router = APIRouter(prefix="/agent", tags=["agent"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def get_current_device(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> models.Device:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid device credential",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None or not credentials.credentials.startswith("csd_"):
        raise unauthorized
    device = db.query(models.Device).filter(models.Device.credential_hash == _hash(credentials.credentials)).first()
    if device is None or device.status == "REVOKED":
        raise unauthorized
    return device


@router.post("/enrollment-tokens", response_model=EnrollmentTokenResponse, status_code=status.HTTP_201_CREATED)
def create_enrollment_token(
    payload: EnrollmentTokenRequest,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin_or_security),
) -> EnrollmentTokenResponse:
    target = db.query(models.User).filter(models.User.id == (payload.user_id or admin.id)).first()
    if target is None or not target.is_active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if admin.organization_id is not None and target.organization_id != admin.organization_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-organization enrollment denied")
    token = "cse_" + secrets.token_urlsafe(32)
    expires_at = _now() + timedelta(minutes=payload.ttl_minutes)
    db.add(
        models.EnrollmentToken(
            organization_id=target.organization_id,
            user_id=target.id,
            created_by_id=admin.id,
            token_hash=_hash(token),
            expires_at=expires_at,
        )
    )
    db.commit()
    return EnrollmentTokenResponse(token=token, expires_at=expires_at, user_id=target.id)


@router.post("/enroll", response_model=AgentEnrollResponse, status_code=status.HTTP_201_CREATED)
def enroll(payload: AgentEnrollRequest, db: Session = Depends(get_db)) -> AgentEnrollResponse:
    invalid = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid, expired or already used enrollment token")
    now = _now()
    token_hash = _hash(payload.token)
    record = db.query(models.EnrollmentToken).filter(models.EnrollmentToken.token_hash == token_hash).first()
    if record is None or record.used_at is not None or _aware(record.expires_at) < now:
        raise invalid
    consumed = (
        db.query(models.EnrollmentToken)
        .filter(models.EnrollmentToken.id == record.id, models.EnrollmentToken.used_at.is_(None))
        .update({"used_at": now}, synchronize_session=False)
    )
    if consumed != 1:
        db.rollback()
        raise invalid
    user = db.query(models.User).filter(models.User.id == record.user_id).first()
    if user is None or not user.is_active:
        db.commit()
        raise invalid

    secret = "csd_" + secrets.token_urlsafe(32)
    fingerprint = _fingerprint(user.organization_id, user.id, payload.hostname, payload.platform)
    device = db.query(models.Device).filter(models.Device.device_fingerprint == fingerprint).first()
    if device is None:
        device = models.Device(
            organization_id=user.organization_id,
            device_id=f"DEV-{uuid.uuid4().hex[:12].upper()}",
            user_id=user.id,
            device_name=payload.device_name,
            hostname=payload.hostname,
            platform=payload.platform,
            platform_version=payload.platform_version,
            device_fingerprint=fingerprint,
            posture_status="UNKNOWN",
            registered_at=now,
            os=payload.platform,
            os_version=payload.platform_version,
            trusted_device=True,
            os_compliant=False,
            av_active=True,
            location="Unknown",
        )
        db.add(device)
        db.flush()
        _audit_device_event(db, device, "DEVICE_REGISTERED", f"{payload.device_name} enrolled via agent.")
    else:
        _audit_device_event(db, device, "DEVICE_REENROLLED", f"{device.device_name or device.device_id} re-enrolled; credential rotated.")
    device.agent_version = payload.agent_version
    device.status = "ONLINE"
    device.last_seen = now
    device.credential_hash = _hash(secret)
    device.credential_issued_at = now
    user.device_id = device.device_id
    db.commit()
    return AgentEnrollResponse(device_id=device.device_id, device_secret=secret, heartbeat_seconds=HEARTBEAT_SECONDS)


@router.post("/heartbeat", response_model=DeviceHeartbeatResponse)
def agent_heartbeat(
    payload: DeviceHeartbeatRequest,
    db: Session = Depends(get_db),
    device: models.Device = Depends(get_current_device),
) -> DeviceHeartbeatResponse:
    return apply_heartbeat(db, device, payload)


@router.post("/posture", response_model=DevicePostureResponse)
def agent_posture(
    payload: DevicePostureRequest,
    db: Session = Depends(get_db),
    device: models.Device = Depends(get_current_device),
) -> DevicePostureResponse:
    return apply_posture(db, device, payload)


@router.post("/devices/{device_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
def revoke_device(
    device_id: str,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin_or_security),
) -> None:
    query = db.query(models.Device).filter(models.Device.device_id == device_id)
    if admin.organization_id is not None:
        query = query.filter(models.Device.organization_id == admin.organization_id)
    device = query.first()
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    device.credential_hash = None
    device.status = "REVOKED"
    _audit_device_event(db, device, "DEVICE_REVOKED", f"{device.device_name or device.device_id} revoked by {admin.username}.")
    db.commit()
