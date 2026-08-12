from dataclasses import dataclass
from datetime import datetime, timezone

from backend import models
from backend.security.anomaly import AnomalyAssessment
from backend.security.tags import CRITICAL, GREEN, HIGH, MEDIUM, TagCandidate


@dataclass(frozen=True)
class PostureAssessment:
    status: str
    posture_risk: int
    tags: list[TagCandidate]
    reasons: list[str]
    evaluated_at: datetime


def _latest_telemetry(user: models.User):
    if not user.telemetry:
        return None
    return max(user.telemetry, key=lambda item: item.timestamp)


def evaluate_posture(
    user: models.User,
    device: models.Device | None,
    anomaly: AnomalyAssessment | None = None,
) -> PostureAssessment:
    telemetry = _latest_telemetry(user)
    tags: list[TagCandidate] = [TagCandidate("MFA_VERIFIED", GREEN)]
    reasons: list[str] = []
    risk = 0

    if device is None:
        tags.append(TagCandidate("NEW_DEVICE", MEDIUM))
        reasons.append("No registered device was found for the user")
        risk += 15
    else:
        if device.trusted_device:
            tags.append(TagCandidate("TRUSTED_DEVICE", GREEN))
        else:
            tags.append(TagCandidate("NEW_DEVICE", MEDIUM))
            reasons.append("Device is not marked as trusted")
            risk += 15

        if device.os_compliant:
            tags.append(TagCandidate("OS_COMPLIANT", GREEN))
        else:
            tags.append(TagCandidate("OUTDATED_SOFTWARE", MEDIUM))
            reasons.append("Device operating system is not compliant")
            risk += 12

        if device.av_active:
            tags.append(TagCandidate("AV_ACTIVE", GREEN))
        else:
            tags.append(TagCandidate("COMPROMISED_DEVICE", HIGH))
            reasons.append("Endpoint protection is inactive")
            risk += 20

        if telemetry and telemetry.location != device.location:
            tags.append(TagCandidate("NEW_LOCATION", MEDIUM))
            reasons.append("Telemetry location differs from the expected device location")
            risk += 10
        else:
            tags.append(TagCandidate("NORMAL_LOCATION", GREEN))

    if telemetry:
        if telemetry.failed_logins >= 3:
            tags.append(TagCandidate("AUTH_ANOMALY", MEDIUM))
            reasons.append("Multiple failed authentication attempts")
            risk += 10
        if telemetry.requests_per_minute >= 100 or telemetry.access_frequency >= 20:
            tags.append(TagCandidate("UNUSUAL_ACTIVITY", MEDIUM))
            reasons.append("Abnormal request frequency")
            risk += 12
        if telemetry.data_download_mb >= 500:
            tags.append(TagCandidate("DATA_EXFILTRATION", CRITICAL))
            reasons.append("Data transfer significantly above baseline")
            risk += 25
        if telemetry.requests_per_minute >= 160 and telemetry.data_download_mb >= 800:
            tags.append(TagCandidate("THREAT_DETECTED", CRITICAL))
            reasons.append("Critical telemetry thresholds exceeded")
            risk += 15

    if anomaly and anomaly.is_anomaly:
        tags.append(TagCandidate("UNUSUAL_ACTIVITY", MEDIUM))
        reasons.append(anomaly.reason)
        risk += 8
    elif telemetry:
        tags.append(TagCandidate("NORMAL_BEHAVIOR", GREEN))

    risk = max(0, min(40, risk))
    if risk >= 30:
        status = "CRITICAL"
    elif risk >= 20:
        status = "HIGH"
    elif risk >= 10:
        status = "MEDIUM"
    else:
        status = "HEALTHY"

    # Keep deterministic unique tags while preserving first-seen order.
    unique_tags = list(dict.fromkeys(tags))
    return PostureAssessment(
        status=status,
        posture_risk=risk,
        tags=unique_tags,
        reasons=reasons,
        evaluated_at=datetime.now(timezone.utc),
    )
