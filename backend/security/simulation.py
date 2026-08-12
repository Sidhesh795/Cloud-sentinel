from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session, selectinload

from backend import models
from backend.security.zero_trust_gateway import assess_current_context, evaluate_access


NORMAL_TELEMETRY = {
    "requests_per_minute": 20,
    "data_download_mb": 50,
    "failed_logins": 0,
    "unique_applications": 2,
    "access_frequency": 5,
    "login_hour": 10,
    "location": "Pune",
}

ATTACK_TELEMETRY = {
    "requests_per_minute": 185,
    "data_download_mb": 875,
    "failed_logins": 4,
    "unique_applications": 5,
    "access_frequency": 32,
    "login_hour": 2,
    "location": "Mumbai",
}


def _load_user(db: Session, user_id: int) -> models.User:
    user = (
        db.query(models.User)
        .options(selectinload(models.User.devices), selectinload(models.User.telemetry))
        .filter(models.User.id == user_id)
        .first()
    )
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


def _primary_device(user: models.User) -> models.Device:
    if not user.devices:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="User has no registered device")
    return user.devices[0]


def _state_for(db: Session, user_id: int) -> models.SimulationState:
    state = db.query(models.SimulationState).filter_by(user_id=user_id).first()
    if state is None:
        state = models.SimulationState(user_id=user_id, simulation_active=False, state="NORMAL")
        db.add(state)
        db.flush()
    return state


def _latest_risk(db: Session, user_id: int) -> models.RiskScore | None:
    return (
        db.query(models.RiskScore)
        .filter(models.RiskScore.user_id == user_id)
        .order_by(models.RiskScore.timestamp.desc())
        .first()
    )


def _add_telemetry(db: Session, user: models.User, device: models.Device, payload: dict) -> models.Telemetry:
    telemetry = models.Telemetry(user_id=user.id, device_id=device.id, **payload)
    db.add(telemetry)
    db.flush()
    return telemetry


def _event(db: Session, user: models.User, event_type: str, severity: str, description: str, metadata: dict | None = None) -> None:
    db.add(
        models.SecurityEvent(
            user_id=user.id,
            event_type=event_type,
            severity=severity,
            description=description,
            metadata_json=metadata or {},
        )
    )


def simulation_status(db: Session, user_id: int) -> dict:
    _load_user(db, user_id)
    state = _state_for(db, user_id)
    risk = _latest_risk(db, user_id)
    return {
        "user_id": user_id,
        "simulation_active": state.simulation_active,
        "state": state.state,
        "started_at": state.started_at,
        "risk_score": risk.risk_score if risk else None,
    }


def trigger_attack(db: Session, user_id: int) -> dict:
    user = _load_user(db, user_id)
    device = _primary_device(user)
    state = _state_for(db, user.id)

    if state.state == "COMPROMISED" and state.simulation_active:
        return _current_result(db, user.id, [])

    state.simulation_active = True
    state.state = "COMPROMISED"
    state.started_at = datetime.now(timezone.utc)
    state.updated_at = datetime.now(timezone.utc)

    device.trusted_device = False
    device.os_compliant = True
    device.av_active = True
    device.location = "Pune"
    device.last_seen = datetime.now(timezone.utc)
    _add_telemetry(db, user, device, ATTACK_TELEMETRY)

    events = [
        ("ACCOUNT_COMPROMISE_SIMULATED", "HIGH", f"Controlled account-compromise simulation started for {user.username}."),
        ("NEW_DEVICE_DETECTED", "MEDIUM", f"Unrecognized device posture detected for {user.username}."),
        ("NEW_LOCATION_DETECTED", "MEDIUM", "Location changed from Pune to Mumbai."),
        ("AUTH_ANOMALY_DETECTED", "HIGH", "Multiple failed login attempts observed."),
        ("SUSPICIOUS_BEHAVIOR_DETECTED", "HIGH", "Request frequency increased above normal baseline."),
        ("DATA_EXFILTRATION_DETECTED", "CRITICAL", "Data transfer increased from baseline 50 MB to 875 MB."),
        ("BEHAVIORAL_ANOMALY_DETECTED", "HIGH", "Behavioral activity significantly deviates from baseline."),
    ]
    for event_type, severity, description in events:
        _event(db, user, event_type, severity, description, {"simulation": True})

    return _current_result(db, user.id, [event_type for event_type, _, _ in events], reevaluate=True)


def reset_simulation(db: Session, user_id: int) -> dict:
    user = _load_user(db, user_id)
    device = _primary_device(user)
    state = _state_for(db, user.id)

    device.trusted_device = True
    device.os_compliant = True
    device.av_active = True
    device.location = "Pune"
    device.last_seen = datetime.now(timezone.utc)
    _add_telemetry(db, user, device, NORMAL_TELEMETRY)

    state.simulation_active = False
    state.state = "NORMAL"
    state.started_at = None
    state.updated_at = datetime.now(timezone.utc)

    _event(db, user, "SIMULATION_RESET", "INFO", f"Demo simulation reset for {user.username}.", {"simulation": True})
    return _current_result(db, user.id, ["SIMULATION_RESET"], reevaluate=True)


def _current_result(db: Session, user_id: int, events_created: list[str], reevaluate: bool = False) -> dict:
    db.flush()
    db.expire_all()
    user, _, risk, _ = assess_current_context(db, user_id)
    applications = (
        db.query(models.Application)
        .filter(models.Application.is_active.is_(True))
        .order_by(models.Application.cloud_provider, models.Application.sensitivity, models.Application.name)
        .all()
    )
    decisions = []
    for application in applications:
        decision = evaluate_access(db, user_id=user.id, application_id=application.id, action="READ", persist=reevaluate)
        decisions.append(decision)

    if reevaluate:
        _event(
            db,
            user,
            "RISK_ESCALATED" if risk.risk_level in {"HIGH", "CRITICAL"} else "RISK_NORMALIZED",
            "HIGH" if risk.risk_level in {"HIGH", "CRITICAL"} else "INFO",
            f"Risk recalculated to {risk.risk_level} ({risk.risk_score}/100).",
            {"risk_score": risk.risk_score, "risk_level": risk.risk_level, "simulation": True},
        )
        _event(
            db,
            user,
            "POLICY_REEVALUATED",
            "HIGH" if risk.risk_level in {"HIGH", "CRITICAL"} else "INFO",
            "Zero Trust policies re-evaluated for all active applications.",
            {"simulation": True},
        )

    state = _state_for(db, user_id)
    db.commit()
    return {
        "user_id": user_id,
        "simulation_active": state.simulation_active,
        "state": state.state,
        "started_at": state.started_at,
        "risk_score": risk.risk_score,
        "risk_level": risk.risk_level,
        "access_matrix": [
            {
                "application_id": item.application.id,
                "application": item.application.name,
                "cloud": item.application.cloud_provider,
                "sensitivity": item.application.sensitivity,
                "resource_level": item.policy.resource_level,
                "action": "READ",
                "risk_score": item.policy.risk_score,
                "risk_level": item.policy.risk_level,
                "decision": item.policy.decision,
                "reason": item.policy.reason,
                "policy_rule": item.policy.policy_rule,
                "factors": item.policy.factors,
            }
            for item in decisions
        ],
        "events_created": events_created,
    }
