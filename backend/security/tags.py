from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend import models


@dataclass(frozen=True)
class TagCandidate:
    tag: str
    severity: str
    source: str = "posture_engine"
    is_active: bool = True


GREEN = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"

TAG_REASON_MAP = {
    "TRUSTED_DEVICE": "Trusted device is registered for this user",
    "MFA_VERIFIED": "Recent authentication state includes MFA verification",
    "OS_COMPLIANT": "Device operating system is compliant",
    "AV_ACTIVE": "Endpoint protection is active",
    "NORMAL_BEHAVIOR": "Behavior matches normal baseline",
    "NORMAL_LOCATION": "Access location matches expected location",
    "NEW_DEVICE": "Unrecognized or untrusted device",
    "NEW_LOCATION": "Access location differs from the device baseline",
    "UNUSUAL_ACTIVITY": "Request activity is elevated above normal baseline",
    "AUTH_ANOMALY": "Multiple failed authentication attempts",
    "OUTDATED_SOFTWARE": "Device operating system is not compliant",
    "DATA_EXFILTRATION": "Data transfer volume is significantly above baseline",
    "COMPROMISED_DEVICE": "Device posture indicates possible compromise",
    "THREAT_DETECTED": "Critical telemetry threshold was exceeded",
}


def persist_active_tags(
    db: Session,
    user_id: int,
    device_pk: int | None,
    candidates: list[TagCandidate],
    source: str = "posture_engine",
) -> list[models.SecurityTag]:
    current_names = {candidate.tag for candidate in candidates}
    existing_tags = (
        db.query(models.SecurityTag)
        .filter(models.SecurityTag.user_id == user_id, models.SecurityTag.source == source)
        .all()
    )

    by_name = {tag.tag: tag for tag in existing_tags}
    now = datetime.now(timezone.utc)

    for tag in existing_tags:
        if tag.tag not in current_names:
            tag.is_active = False

    for candidate in candidates:
        tag = by_name.get(candidate.tag)
        if tag is None:
            tag = models.SecurityTag(
                user_id=user_id,
                device_id=device_pk,
                tag=candidate.tag,
                severity=candidate.severity,
                source=candidate.source,
                is_active=candidate.is_active,
                created_at=now,
            )
            db.add(tag)
        else:
            tag.device_id = device_pk
            tag.severity = candidate.severity
            tag.source = candidate.source
            tag.is_active = candidate.is_active

    db.flush()
    return (
        db.query(models.SecurityTag)
        .filter(
            models.SecurityTag.user_id == user_id,
            models.SecurityTag.source == source,
            models.SecurityTag.is_active.is_(True),
        )
        .order_by(models.SecurityTag.tag)
        .all()
    )
