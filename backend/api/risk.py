from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, selectinload

from backend import models
from backend.database import get_db
from backend.schemas import RiskAssessmentRead, RiskScoreRead, SecurityTagSummary
from backend.security.anomaly import assess_behavior
from backend.security.posture import evaluate_posture
from backend.security.risk_engine import calculate_risk
from backend.security.tags import persist_active_tags


router = APIRouter(prefix="/users", tags=["risk"])


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


def _latest_telemetry(user: models.User):
    if not user.telemetry:
        return None
    return max(user.telemetry, key=lambda item: item.timestamp)


@router.get("/{user_id}/risk", response_model=RiskAssessmentRead)
def get_user_risk(user_id: int, db: Session = Depends(get_db)) -> RiskAssessmentRead:
    user = _load_user(db, user_id)
    device = user.devices[0] if user.devices else None
    telemetry = _latest_telemetry(user)
    if telemetry is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No telemetry available for risk assessment",
        )

    anomaly = assess_behavior(telemetry)
    posture = evaluate_posture(user, device, anomaly)
    active_tags = persist_active_tags(db, user.id, device.id if device else None, posture.tags)
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
    db.commit()

    return RiskAssessmentRead(
        user_id=user.id,
        risk_score=risk.risk_score,
        risk_level=risk.risk_level,
        components={
            "identity": risk.identity_risk,
            "posture": risk.posture_risk,
            "behavior": risk.behavior_risk,
            "context": risk.context_risk,
        },
        anomaly={
            "is_anomaly": anomaly.is_anomaly,
            "anomaly_score": anomaly.anomaly_score,
            "reason": anomaly.reason,
        },
        tags=[SecurityTagSummary.model_validate(tag) for tag in active_tags],
        reasons=risk.reasons,
    )


@router.get("/{user_id}/risk-history", response_model=list[RiskScoreRead])
def get_user_risk_history(
    user_id: int,
    limit: int = 20,
    db: Session = Depends(get_db),
) -> list[models.RiskScore]:
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return (
        db.query(models.RiskScore)
        .filter(models.RiskScore.user_id == user_id)
        .order_by(models.RiskScore.timestamp.desc())
        .limit(min(max(limit, 1), 100))
        .all()
    )
