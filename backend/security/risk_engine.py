from dataclasses import dataclass

from backend import models
from backend.security.anomaly import AnomalyAssessment
from backend.security.posture import PostureAssessment


@dataclass(frozen=True)
class RiskAssessment:
    user_id: int
    risk_score: int
    risk_level: str
    identity_risk: int
    posture_risk: int
    behavior_risk: int
    context_risk: int
    reasons: list[str]


def risk_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def calculate_identity_risk(telemetry) -> tuple[int, list[str]]:
    if telemetry is None:
        return 5, ["No recent telemetry has been submitted"]
    risk = 2
    reasons: list[str] = []
    if telemetry.failed_logins >= 3:
        risk += 13
        reasons.append("Multiple failed authentication attempts")
    elif telemetry.failed_logins > 0:
        risk += 4
        reasons.append("Recent failed authentication attempt")
    return min(risk, 20), reasons


def calculate_context_risk(device: models.Device | None, telemetry) -> tuple[int, list[str]]:
    risk = 0
    reasons: list[str] = []
    if telemetry is None:
        return risk, reasons
    if device and telemetry.location != device.location:
        risk += 10
        reasons.append("New access location")
    if telemetry.login_hour < 6 or telemetry.login_hour > 20:
        risk += 5
        reasons.append("Login occurred outside normal business hours")
    return min(risk, 15), reasons


def calculate_risk(
    user: models.User,
    device: models.Device | None,
    telemetry,
    posture: PostureAssessment,
    anomaly: AnomalyAssessment,
) -> RiskAssessment:
    identity_risk, identity_reasons = calculate_identity_risk(telemetry)
    context_risk, context_reasons = calculate_context_risk(device, telemetry)
    behavior_risk = anomaly.behavior_risk
    posture_risk = posture.posture_risk

    score = max(
        0,
        min(100, identity_risk + posture_risk + behavior_risk + context_risk),
    )
    reasons = []
    reasons.extend(posture.reasons)
    reasons.extend(identity_reasons)
    reasons.extend(context_reasons)
    if anomaly.is_anomaly:
        reasons.append(anomaly.reason)
    elif anomaly.behavior_risk >= 30:
        reasons.append(anomaly.reason)

    return RiskAssessment(
        user_id=user.id,
        risk_score=score,
        risk_level=risk_level(score),
        identity_risk=identity_risk,
        posture_risk=posture_risk,
        behavior_risk=behavior_risk,
        context_risk=context_risk,
        reasons=list(dict.fromkeys(reasons)),
    )
