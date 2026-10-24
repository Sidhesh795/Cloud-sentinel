import hashlib
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend import models
from backend.auth.auth import create_access_token, get_current_user, normalize_role
from backend.config import using_mongodb
from backend.database import get_db
from backend.db.repositories.devices import DeviceRepository
from backend.db.repositories.events import SecurityEventRepository
from backend.db.repositories.telemetry import TelemetryRepository
from backend.schemas import (
    DeviceHeartbeatRequest,
    DeviceHeartbeatResponse,
    DeviceInventoryItem,
    DevicePostureRequest,
    DevicePostureResponse,
    DeviceRead,
    DeviceRegisterRequest,
    DeviceRegisterResponse,
)


router = APIRouter(prefix="/devices", tags=["devices"])
HEARTBEAT_SECONDS = 30


def _server_time() -> datetime:
    return datetime.now(timezone.utc)


def _can_manage_other_users(user: models.User) -> bool:
    return normalize_role(user.role) in {"ADMIN", "SECURITY_ANALYST", "ANALYST"}


def _tenant_filter(query, current_user: models.User):
    if current_user.organization_id is None:
        return query
    return query.filter(models.Device.organization_id == current_user.organization_id)


def _get_device(db: Session, current_user: models.User, device_id: str) -> models.Device:
    query = db.query(models.Device).filter(models.Device.device_id == device_id)
    query = _tenant_filter(query, current_user)
    device = query.first()
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    if device.user_id != current_user.id and not _can_manage_other_users(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device belongs to another user")
    return device


def _fingerprint(organization_id: int | None, user_id: int, hostname: str, platform: str) -> str:
    raw = f"cloudsentinel:{organization_id or 'demo'}:{user_id}:{hostname.lower()}:{platform.lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _audit_device_event(
    db: Session,
    device: models.Device,
    event_type: str,
    description: str,
    metadata: dict | None = None,
) -> None:
    event = models.SecurityEvent(
        organization_id=device.organization_id,
        user_id=device.user_id,
        device_id=device.id,
        event_type=event_type,
        severity="INFO",
        source="AGENT",
        description=description,
        metadata_json=metadata or {},
    )
    db.add(event)
    if using_mongodb():
        SecurityEventRepository().insert(
            {
                "organization_id": str(device.organization_id),
                "user_id": str(device.user_id),
                "device_id": device.device_id,
                "event_type": event_type,
                "severity": "INFO",
                "timestamp": event.timestamp,
                "source": "AGENT",
                "description": description,
                "metadata": metadata or {},
            }
        )


def _derive_posture(payload: DevicePostureRequest) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if payload.security_product_active is False:
        reasons.append("Security product is inactive")
    if payload.screen_lock_enabled is False:
        reasons.append("Screen lock is disabled")
    if payload.firewall_enabled is False:
        reasons.append("Firewall is disabled")
    if payload.encryption_enabled is False:
        reasons.append("Disk encryption is disabled")
    patch_state = (payload.patch_state or "UNKNOWN").upper()
    if patch_state in {"OUTDATED", "MISSING", "CRITICAL"}:
        reasons.append(f"Patch state is {patch_state}")

    if payload.security_product_active is False and patch_state in {"MISSING", "CRITICAL"}:
        return "COMPROMISED", reasons
    if reasons:
        return "WARNING", reasons
    if patch_state == "UNKNOWN":
        return "UNKNOWN", ["Patch state was not reported"]
    return "HEALTHY", ["Endpoint posture signals are healthy"]


@router.get("", response_model=list[DeviceInventoryItem])
def list_devices(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
) -> list[DeviceInventoryItem]:
    query = _tenant_filter(db.query(models.Device), current_user)
    if not _can_manage_other_users(current_user):
        query = query.filter(models.Device.user_id == current_user.id)
    devices = query.order_by(models.Device.last_seen.desc()).all()
    result: list[DeviceInventoryItem] = []
    for device in devices:
        latest_risk = (
            db.query(models.RiskScore)
            .filter(models.RiskScore.user_id == device.user_id)
            .order_by(models.RiskScore.timestamp.desc())
            .first()
        )
        result.append(
            DeviceInventoryItem(
                **DeviceRead.model_validate(device).model_dump(),
                username=device.user.username if device.user else None,
                user_email=device.user.email if device.user else None,
                user_display_name=device.user.display_name if device.user else None,
                risk_score=latest_risk.risk_score if latest_risk else None,
            )
        )
    return result


@router.post("/register", response_model=DeviceRegisterResponse, status_code=status.HTTP_201_CREATED)
def register_device(
    payload: DeviceRegisterRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
) -> DeviceRegisterResponse:
    target_user_id = payload.user_id or current_user.id
    if target_user_id != current_user.id and not _can_manage_other_users(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot register device for another user")
    target_user = db.query(models.User).filter(models.User.id == target_user_id).first()
    if target_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if current_user.organization_id is not None and target_user.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-organization registration denied")

    now = _server_time()
    device_public_id = f"DEV-{uuid.uuid4().hex[:12].upper()}"
    fingerprint = _fingerprint(target_user.organization_id, target_user.id, payload.hostname, payload.platform)
    existing = db.query(models.Device).filter(models.Device.device_fingerprint == fingerprint).first()
    if existing is not None:
        existing.last_seen = now
        existing.status = "ONLINE"
        existing.agent_version = payload.agent_version
        db.commit()
        return DeviceRegisterResponse(
            device_id=existing.device_id,
            agent_registration_token=create_access_token(f"device:{existing.device_id}"),
            status=existing.status,
        )

    device = models.Device(
        organization_id=target_user.organization_id,
        device_id=device_public_id,
        user_id=target_user.id,
        device_name=payload.device_name,
        hostname=payload.hostname,
        platform=payload.platform,
        platform_version=payload.platform_version,
        agent_version=payload.agent_version,
        device_fingerprint=fingerprint,
        status="ONLINE",
        posture_status="UNKNOWN",
        registered_at=now,
        os=payload.platform,
        os_version=payload.platform_version,
        trusted_device=True,
        os_compliant=True,
        av_active=True,
        location="Unknown",
        last_seen=now,
    )
    db.add(device)
    db.flush()
    target_user.device_id = device.device_id
    target_user.last_seen = now
    _audit_device_event(db, device, "DEVICE_REGISTERED", f"{payload.device_name} registered.")
    db.commit()
    db.refresh(device)

    if using_mongodb():
        DeviceRepository().insert(
            {
                "organization_id": str(device.organization_id),
                "user_id": str(device.user_id),
                "device_id": device.device_id,
                "device_name": device.device_name,
                "hostname": device.hostname,
                "platform": device.platform,
                "platform_version": device.platform_version,
                "agent_version": device.agent_version,
                "device_fingerprint": device.device_fingerprint,
                "status": device.status,
                "posture_status": device.posture_status,
                "registered_at": device.registered_at,
                "last_seen": device.last_seen,
                "environment": "DEMO",
            }
        )

    return DeviceRegisterResponse(
        device_id=device.device_id,
        agent_registration_token=create_access_token(f"device:{device.device_id}"),
        status=device.status,
    )


def apply_heartbeat(db: Session, device: models.Device, payload: DeviceHeartbeatRequest) -> DeviceHeartbeatResponse:
    now = _server_time()
    device.last_seen = now
    device.status = "ONLINE"
    if payload.agent_version:
        device.agent_version = payload.agent_version
    device.user.last_seen = now
    _audit_device_event(db, device, "DEVICE_ONLINE", f"{device.device_name or device.device_id} heartbeat received.", payload.posture_metadata)
    db.commit()
    return DeviceHeartbeatResponse(
        device_id=device.device_id,
        status=device.status,
        server_time=now,
        next_heartbeat_seconds=HEARTBEAT_SECONDS,
    )


@router.post("/{device_id}/heartbeat", response_model=DeviceHeartbeatResponse)
def heartbeat(
    device_id: str,
    payload: DeviceHeartbeatRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
) -> DeviceHeartbeatResponse:
    return apply_heartbeat(db, _get_device(db, current_user, device_id), payload)


def apply_posture(db: Session, device: models.Device, payload: DevicePostureRequest) -> DevicePostureResponse:
    posture_status, reasons = _derive_posture(payload)
    now = _server_time()
    previous = device.posture_status
    device.os = payload.os
    device.os_version = payload.os_version
    device.platform = payload.os
    device.platform_version = payload.os_version
    device.av_active = payload.security_product_active is not False
    device.os_compliant = posture_status == "HEALTHY"
    device.posture_status = posture_status
    device.last_seen = now
    telemetry = models.Telemetry(
        organization_id=device.organization_id,
        user_id=device.user_id,
        device_id=device.id,
        requests_per_minute=20,
        data_download_mb=50,
        failed_logins=0,
        unique_applications=2,
        access_frequency=5,
        login_hour=now.hour,
        location=device.location,
        event_type="DEVICE_POSTURE",
        source="AGENT",
        metadata_json={
            "posture_status": posture_status,
            "reasons": reasons,
            "signals": payload.model_dump(exclude={"metadata"}),
            "metadata": payload.metadata or {},
        },
    )
    db.add(telemetry)
    if previous != posture_status:
        _audit_device_event(
            db,
            device,
            "POSTURE_CHANGED",
            f"{device.device_name or device.device_id} posture changed from {previous} to {posture_status}.",
            {"previous": previous, "current": posture_status, "reasons": reasons},
        )
    db.commit()
    if using_mongodb():
        TelemetryRepository().insert(
            {
                "organization_id": str(device.organization_id),
                "user_id": str(device.user_id),
                "device_id": device.device_id,
                "timestamp": telemetry.timestamp,
                "event_type": "DEVICE_POSTURE",
                "source": "AGENT",
                "metadata": telemetry.metadata_json,
            }
        )
    return DevicePostureResponse(
        device_id=device.device_id,
        posture_status=posture_status,
        reasons=reasons,
        server_time=now,
    )


@router.post("/{device_id}/posture", response_model=DevicePostureResponse)
def submit_posture(
    device_id: str,
    payload: DevicePostureRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
) -> DevicePostureResponse:
    return apply_posture(db, _get_device(db, current_user, device_id), payload)
