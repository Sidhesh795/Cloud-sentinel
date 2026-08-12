from dataclasses import dataclass

from fastapi import HTTPException, status
from sqlalchemy.orm import Session, selectinload

from backend import models
from backend.security.anomaly import assess_behavior
from backend.security.policy_engine import PolicyDecision, evaluate_policy
from backend.security.posture import evaluate_posture
from backend.security.risk_engine import RiskAssessment, calculate_risk
from backend.security.tags import persist_active_tags


@dataclass(frozen=True)
class GatewayDecision:
    user: models.User
    application: models.Application
    risk: RiskAssessment
    security_tags: list[models.SecurityTag]
    policy: PolicyDecision


def _load_user(db: Session, user_id: int) -> models.User:
    user = (
        db.query(models.User)
        .options(
            selectinload(models.User.devices),
            selectinload(models.User.telemetry),
            selectinload(models.User.security_tags),
        )
        .filter(models.User.id == user_id)
        .first()
    )
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


def _load_application(db: Session, application_id: int) -> models.Application:
    application = (
        db.query(models.Application)
        .filter(models.Application.id == application_id, models.Application.is_active.is_(True))
        .first()
    )
    if application is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")
    return application


def _latest_telemetry(user: models.User):
    if not user.telemetry:
        return None
    return max(user.telemetry, key=lambda item: item.timestamp)


def assess_current_context(db: Session, user_id: int) -> tuple[models.User, models.Device | None, RiskAssessment, list[models.SecurityTag]]:
    user = _load_user(db, user_id)
    device = user.devices[0] if user.devices else None
    telemetry = _latest_telemetry(user)
    if telemetry is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No telemetry available for access evaluation",
        )

    anomaly = assess_behavior(telemetry)
    posture = evaluate_posture(user, device, anomaly)
    tags = persist_active_tags(db, user.id, device.id if device else None, posture.tags)
    risk = calculate_risk(user, device, telemetry, posture, anomaly)

    db.add(
        models.RiskScore(
            user_id=user.id,
            risk_score=risk.risk_score,
            risk_level=risk.risk_level,
            identity_risk=risk.identity_risk,
            posture_risk=risk.posture_risk,
            behavior_risk=risk.behavior_risk,
            context_risk=risk.context_risk,
            resource_risk=0,
        )
    )
    db.flush()
    return user, device, risk, tags


def evaluate_access(
    db: Session,
    *,
    user_id: int,
    application_id: int,
    action: str,
    persist: bool = True,
) -> GatewayDecision:
    application = _load_application(db, application_id)
    user, device, risk, tags = assess_current_context(db, user_id)
    policy = evaluate_policy(
        user=user,
        risk=risk,
        security_tags=tags,
        device=device,
        application=application,
        action=action,
    )

    if persist:
        _record_access_decision(db, user, application, action.upper(), policy)
        db.commit()

    return GatewayDecision(
        user=user,
        application=application,
        risk=risk,
        security_tags=tags,
        policy=policy,
    )


def evaluate_access_matrix(db: Session, *, user_id: int, action: str = "READ") -> list[GatewayDecision]:
    user, device, risk, tags = assess_current_context(db, user_id)
    applications = (
        db.query(models.Application)
        .filter(models.Application.is_active.is_(True))
        .order_by(models.Application.cloud_provider, models.Application.sensitivity, models.Application.name)
        .all()
    )
    decisions: list[GatewayDecision] = []
    for application in applications:
        policy = evaluate_policy(
            user=user,
            risk=risk,
            security_tags=tags,
            device=device,
            application=application,
            action=action,
        )
        decisions.append(
            GatewayDecision(
                user=user,
                application=application,
                risk=risk,
                security_tags=tags,
                policy=policy,
            )
        )
    db.commit()
    return decisions


def _record_access_decision(
    db: Session,
    user: models.User,
    application: models.Application,
    action: str,
    policy: PolicyDecision,
) -> None:
    db.add(
        models.AccessRequest(
            user_id=user.id,
            application_id=application.id,
            action=action,
            risk_score=policy.risk_score,
            decision=policy.decision,
            reason=policy.reason,
        )
    )
    db.add(
        models.SecurityEvent(
            user_id=user.id,
            event_type=_event_type_for(policy.decision),
            severity=_severity_for(policy.decision),
            description=f"{policy.decision} for {user.username} accessing {application.name}",
            metadata_json={
                "application_id": application.id,
                "application": application.name,
                "cloud_provider": application.cloud_provider,
                "action": action,
                "decision": policy.decision,
                "risk_score": policy.risk_score,
                "risk_level": policy.risk_level,
                "policy_rule": policy.policy_rule,
            },
        )
    )


def _event_type_for(decision: str) -> str:
    return {
        "ALLOW": "ACCESS_ALLOWED",
        "MFA_REQUIRED": "MFA_REQUIRED",
        "READ_ONLY": "ACCESS_RESTRICTED",
        "DENY": "ACCESS_DENIED",
        "ISOLATE": "RESOURCE_ISOLATED",
    }.get(decision, "ACCESS_EVALUATED")


def _severity_for(decision: str) -> str:
    return {
        "ALLOW": "INFO",
        "MFA_REQUIRED": "MEDIUM",
        "READ_ONLY": "HIGH",
        "DENY": "HIGH",
        "ISOLATE": "CRITICAL",
    }.get(decision, "INFO")
